"""Test helpers for remote machines: a fake transport (no network) and a real in-process SSH server (paramiko).

FakeTransport answers the few shell commands the app sends from a small script, keeps the files it is given, and
plays back the runner's output, so the manager can be tested without any SSH at all.

LoopbackSSH is a genuine SSH server on 127.0.0.1 (paramiko's server side): host key, password and public-key login,
exec requests that really run a shell, and SFTP file writes into a temporary home folder. It lets the real transport be
tested end to end, including real host-key checking, without a network or an sshd install.
"""
from __future__ import annotations

import json
import os
import queue
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from legalprivacy.sshconn import Credentials, Stream, Transport
from legalprivacy.sshtarget import Target

# ── fake transport ──────────────────────────────────────────────────────────
LINUX_PROBE = "Linux\n/home/pat\n/usr/bin/python3\n---\n/usr/bin/chromium\n"
LINUX_NO_PYTHON = "Linux\n/home/pat\nNOPYTHON\n---\n"


class FakeStream(Stream):
    def __init__(self, script: list[str], hold: bool):
        self.q: queue.Queue = queue.Queue()
        self.written: list[str] = []
        self.closed = False
        self._status = None
        for ln in script:
            self.q.put(ln)
        if not hold:
            self.q.put(None)
        self.hold = hold

    def lines(self):
        while True:
            item = self.q.get()
            if item is None:
                self._status = 0
                return
            yield item

    def write(self, text: str) -> None:
        self.written.append(text)
        if text.strip() == "stop":
            self.q.put(json.dumps({"t": time.time(), "lvl": "info", "kind": "info", "msg": "runner stopped"}))
            self.q.put(None)

    def close(self) -> None:
        self.closed = True
        self.q.put(None)

    @property
    def exit_status(self):
        return self._status


class FakeTransport(Transport):
    """`script` maps a substring of a command to (code, stdout, stderr)."""
    instances: list[FakeTransport] = []

    def __init__(self, target: Target, creds: Credentials, store, trusted_fingerprint=None, *, probe=LINUX_PROBE,
                 key=("ssh-ed25519", "SHA256:FAKEKEY1"), stream_lines=None, hold=False, fail_auth=False):
        self.target, self.creds, self.store, self.trusted = target, creds, store, trusted_fingerprint
        self.probe, self.key, self.stream_lines, self.hold, self.fail_auth = probe, key, stream_lines or [], hold, fail_auth
        self.files: dict[str, tuple[bytes, int]] = {}
        self.commands: list[str] = []
        self.streams: list[FakeStream] = []
        self.closed = False
        self.connected = False
        FakeTransport.instances.append(self)

    def connect(self):
        ktype, fp = self.key
        stored = self.store.get(self.target)
        if stored is None and self.trusted == fp:
            self.store.trust(self.target, ktype, fp)
        else:
            self.store.check(self.target, ktype, fp)           # raises HostKeyUnknown / HostKeyChanged
        if self.fail_auth:
            from legalprivacy.sshconn import AuthFailed
            raise AuthFailed("The machine refused the login (wrong user, password or key).")
        self.connected = True

    def run(self, command, timeout=30.0):
        self.commands.append(command)
        if "uname -s" in command:
            return 0, self.probe, ""
        if "wipe" in command or "rm -rf" in command:
            return 0, "removed\n", ""
        return 0, "", ""

    def put(self, data, remote_path, mode=0o600):
        self.files[remote_path] = (data, mode)

    def open_stream(self, command):
        self.commands.append(command)
        s = FakeStream(self.stream_lines, self.hold)
        self.streams.append(s)
        return s

    def close(self):
        self.closed = True


def factory(**opts):
    """A transport factory for RemoteManager: every connection is a FakeTransport with these options."""
    def make(target, creds, store, trusted_fingerprint=None):
        # a Credentials object is shared, never copied: tests can check nothing secret ever leaves it
        return FakeTransport(target, creds, store, trusted_fingerprint, **opts)
    return make


# ── a real SSH server on 127.0.0.1 ──────────────────────────────────────────
def _server_classes():
    import paramiko

    class Server(paramiko.ServerInterface):
        def __init__(self, owner):
            self.owner = owner

        def get_allowed_auths(self, username):
            return "password,publickey"

        def check_auth_password(self, username, password):
            ok = username == self.owner.user and password == self.owner.password
            self.owner.logins += ok
            return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

        def check_auth_publickey(self, username, key):
            ok = username == self.owner.user and self.owner.client_key is not None \
                and key.asbytes() == self.owner.client_key.asbytes()
            self.owner.logins += bool(ok)
            return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_exec_request(self, channel, command):
            threading.Thread(target=self.owner.exec_command, args=(channel, command.decode()), daemon=True).start()
            return True

    class Handle(paramiko.SFTPHandle):
        def __init__(self, path, flags):
            super().__init__(flags)
            self.path = path
            self.fh = open(path, "wb" if flags & os.O_WRONLY else "rb")
            self.writefile = self.readfile = self.fh

        def stat(self):
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.fh.fileno()))

        def chattr(self, attr):
            return paramiko.SFTP_OK

    class SFTP(paramiko.SFTPServerInterface):
        def __init__(self, server, *a, **kw):
            super().__init__(server, *a, **kw)
            self.root = server.owner.home

        def _p(self, path):
            return str(Path(self.root) / str(path).lstrip("/")) if not str(path).startswith(str(self.root)) else str(path)

        def open(self, path, flags, attr):
            p = self._p(path)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            return Handle(p, flags)

        def stat(self, path):
            try:
                return paramiko.SFTPAttributes.from_stat(os.stat(self._p(path)))
            except OSError as exc:
                return paramiko.SFTPServer.convert_errno(exc.errno)

        lstat = stat

        def chattr(self, path, attr):
            if attr.st_mode is not None:
                os.chmod(self._p(path), attr.st_mode)
            return paramiko.SFTP_OK

        def mkdir(self, path, attr):
            os.makedirs(self._p(path), exist_ok=True)
            return paramiko.SFTP_OK

    return Server, SFTP


class LoopbackSSH:
    """`with LoopbackSSH() as srv:` then connect to 127.0.0.1:srv.port as srv.user with srv.password or srv.client_key."""

    def __init__(self, user="pat", password="correct horse", with_client_key=True, host_key=None):
        import paramiko
        self.user, self.password = user, password
        self.host_key = host_key or paramiko.ECDSAKey.generate()
        self.client_key = (paramiko.ECDSAKey.generate() if with_client_key else None)
        self.home = tempfile.mkdtemp(prefix="lp-ssh-home-")
        self.commands: list[str] = []
        self.logins = 0
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._transports: list = []

    def fingerprint(self) -> str:
        from legalprivacy.sshconn import fingerprint_sha256
        return fingerprint_sha256(self.host_key.asbytes())

    def write_client_key(self, passphrase: str | None = None) -> str:
        path = os.path.join(self.home, "client_key")
        self.client_key.write_private_key_file(path, password=passphrase)
        return path

    def __enter__(self):
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass
        for t in self._transports:
            try:
                t.close()
            except Exception:
                pass

    def _accept(self):
        import paramiko
        Server, SFTP = _server_classes()
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(self.host_key)
            t.set_subsystem_handler("sftp", paramiko.SFTPServer, SFTP)
            self._transports.append(t)
            try:
                t.start_server(server=Server(self))
            except Exception:
                continue

    def exec_command(self, chan, command: str):
        self.commands.append(command)
        env = dict(os.environ, HOME=self.home)
        proc = subprocess.Popen(["/bin/sh", "-c", command], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env, cwd=self.home)

        def feed():
            try:
                while True:
                    data = chan.recv(4096)
                    if not data:
                        break
                    proc.stdin.write(data)
                    proc.stdin.flush()
            except (OSError, ValueError, EOFError):
                pass
            try:
                proc.stdin.close()
            except OSError:
                pass
        threading.Thread(target=feed, daemon=True).start()
        try:
            for chunk in iter(lambda: proc.stdout.read1(4096), b""):
                chan.sendall(chunk)
        except (OSError, EOFError):
            pass
        code = proc.wait()
        try:
            chan.send_exit_status(code)
            chan.shutdown_write()
            chan.close()
        except Exception:
            pass
