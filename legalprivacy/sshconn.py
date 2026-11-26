"""SSH for remote machines: the transport, and the list of host keys you have trusted.

`paramiko` is an OPTIONAL dependency (`pip install legalprivacy[remote]`); without it everything else in the app works
and this module says so clearly. The rest of the app only talks to the small `Transport` interface below, so the tests
use a fake one and never touch a network.

Host keys are verified BEFORE any password or key is sent:
  * the first time a machine is seen, its fingerprint is shown to you and nothing is sent until you confirm it (trust
    on first use, like `ssh` does, but the app never answers the question for you);
  * a stored fingerprint that no longer matches is refused: that is either a re-installed machine or someone in the
    middle. It is never accepted silently; you must forget the old one yourself, then trust the new one deliberately.

Secrets: a password or a key passphrase lives in the `Credentials` object, in memory, for as long as the app runs.
It is never written to disk, never put in a log line, and `repr()` hides it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .paths import app_dir, write_private
from .sshtarget import Target

CONNECT_TIMEOUT = 15.0


# ── errors: every message here is written for the person at the keyboard ─────
class SSHError(RuntimeError):
    """Something went wrong talking to a remote machine. The text is safe to show (it never holds a secret)."""


class MissingParamiko(SSHError):
    def __init__(self) -> None:
        super().__init__("Remote machines need the 'paramiko' package, which is not installed. "
                         "Install it with:  pip install \"paramiko>=3.4\"  (or  pip install legalprivacy[remote]).")


class AuthFailed(SSHError):
    pass


class HostKeyUnknown(SSHError):
    def __init__(self, target: Target, key_type: str, fingerprint: str) -> None:
        self.target, self.key_type, self.fingerprint = target, key_type, fingerprint
        super().__init__(f"{target.host} has not been seen before. Check that its fingerprint is {fingerprint} "
                         f"({key_type}) before you trust it.")


class HostKeyChanged(SSHError):
    def __init__(self, target: Target, stored: str, offered: str) -> None:
        self.target, self.stored, self.offered = target, stored, offered
        super().__init__(f"The host key of {target.host} is NOT the one you trusted before (trusted {stored}, "
                         f"now offered {offered}). Nothing was sent. If the machine was re-installed, forget the old "
                         "key and trust the new one; if you did not expect this, someone may be intercepting the "
                         "connection.")


# ── secrets ─────────────────────────────────────────────────────────────────
@dataclass
class Credentials:
    password: str | None = field(default=None, repr=False)
    key_path: str | None = None
    passphrase: str | None = field(default=None, repr=False)

    def usable(self) -> bool:
        return bool(self.password or self.key_path)

    def secrets(self) -> list[str]:
        return [s for s in (self.password, self.passphrase) if s]

    def __repr__(self) -> str:
        return f"Credentials(password={'set' if self.password else None}, key_path={self.key_path!r}, " \
               f"passphrase={'set' if self.passphrase else None})"


def fingerprint_sha256(key_blob: bytes) -> str:
    """The OpenSSH style fingerprint: SHA256:base64 (no padding)."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")


# ── the host keys you have trusted ──────────────────────────────────────────
class HostKeyStore:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else app_dir() / "remote_hostkeys.json"
        self._lock = threading.Lock()

    def _read(self) -> dict:
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def get(self, target: Target) -> dict | None:
        return self._read().get(target.key)

    def trust(self, target: Target, key_type: str, fingerprint: str) -> None:
        with self._lock:
            d = self._read()
            d[target.key] = {"type": key_type, "fingerprint": fingerprint}
            write_private(self.path, json.dumps(d, indent=1))

    def forget(self, target: Target) -> bool:
        with self._lock:
            d = self._read()
            had = d.pop(target.key, None) is not None
            if had:
                write_private(self.path, json.dumps(d, indent=1))
            return had

    def check(self, target: Target, key_type: str, fingerprint: str) -> None:
        """Returns when the key is the trusted one; raises HostKeyUnknown or HostKeyChanged otherwise."""
        stored = self.get(target)
        if stored is None:
            raise HostKeyUnknown(target, key_type, fingerprint)
        if stored.get("fingerprint") != fingerprint:
            raise HostKeyChanged(target, str(stored.get("fingerprint")), fingerprint)


# ── the transport interface ─────────────────────────────────────────────────
class Stream:
    """A running remote command: read its lines, write to its input, ask it to close."""

    def lines(self) -> Iterator[str]:                       # pragma: no cover - interface
        raise NotImplementedError

    def write(self, text: str) -> None:                     # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:                                # pragma: no cover - interface
        raise NotImplementedError

    @property
    def exit_status(self) -> int | None:                    # pragma: no cover - interface
        return None


class Transport:
    """What the app needs from SSH. `connect` verifies the host key first and only then authenticates."""

    def connect(self) -> None: ...
    def run(self, command: str, timeout: float = 30.0) -> tuple[int, str, str]: ...
    def put(self, data: bytes, remote_path: str, mode: int = 0o600) -> None: ...
    def open_stream(self, command: str) -> Stream: ...
    def close(self) -> None: ...


def paramiko_available() -> bool:
    try:
        import paramiko  # noqa: F401
        return True
    except ImportError:
        return False


class _ParamikoStream(Stream):
    def __init__(self, chan, redact: list[str]):
        self._chan = chan
        self._redact = redact
        chan.set_combine_stderr(True)

    def lines(self) -> Iterator[str]:
        f = self._chan.makefile("r", encoding="utf-8", errors="replace") if _accepts_enc(self._chan) \
            else self._chan.makefile("r")
        try:
            for line in f:
                yield line.rstrip("\r\n")
        except (OSError, EOFError):
            return

    def write(self, text: str) -> None:
        try:
            self._chan.send(text.encode("utf-8"))
        except (OSError, EOFError):
            pass

    def close(self) -> None:
        try:
            self._chan.close()
        except Exception:
            pass

    @property
    def exit_status(self) -> int | None:
        try:
            return self._chan.recv_exit_status() if self._chan.exit_status_ready() else None
        except Exception:
            return None


def _accepts_enc(chan) -> bool:
    try:
        import inspect
        return "encoding" in inspect.signature(chan.makefile).parameters
    except (TypeError, ValueError):
        return False


class ParamikoTransport(Transport):
    def __init__(self, target: Target, creds: Credentials, store: HostKeyStore, trusted_fingerprint: str | None = None):
        self.target, self.creds, self.store = target, creds, store
        self.trusted_fingerprint = trusted_fingerprint     # a fingerprint the user has just confirmed in the UI
        self._t = None
        self.host_key: tuple[str, str] | None = None        # (type, fingerprint) once connected

    # -- connect
    def connect(self) -> None:
        try:
            import paramiko
        except ImportError:
            raise MissingParamiko() from None
        tg = self.target
        try:
            sock = socket.create_connection((tg.host, tg.port), timeout=CONNECT_TIMEOUT)
        except socket.gaierror:
            raise SSHError(f"Could not find {tg.host}. Check the name or address.") from None
        except TimeoutError:
            raise SSHError(f"{tg.host}:{tg.port} did not answer in {int(CONNECT_TIMEOUT)} seconds.") from None
        except OSError as exc:
            raise SSHError(f"Could not connect to {tg.host}:{tg.port} ({exc.strerror or 'network error'}).") from None
        t = paramiko.Transport(sock)
        try:
            t.banner_timeout = CONNECT_TIMEOUT
            t.start_client(timeout=CONNECT_TIMEOUT)
            key = t.get_remote_server_key()
            ktype, fp = key.get_name(), fingerprint_sha256(key.asbytes())
            self.host_key = (ktype, fp)
            self._verify(ktype, fp)                            # BEFORE anything secret is sent
            self._authenticate(paramiko, t)
            t.set_keepalive(20)
        except Exception:
            t.close()
            raise
        self._t = t

    def _verify(self, ktype: str, fp: str) -> None:
        stored = self.store.get(self.target)
        if stored is None and self.trusted_fingerprint == fp:
            self.store.trust(self.target, ktype, fp)           # the user confirmed exactly this fingerprint
            return
        self.store.check(self.target, ktype, fp)

    def _authenticate(self, paramiko, t) -> None:
        c, user = self.creds, self.target.user
        try:
            if c.key_path:
                t.auth_publickey(user, self._load_key(paramiko, c))
            elif c.password:
                t.auth_password(user, c.password)
            else:
                raise AuthFailed("No password or key was given for this machine.")
        except paramiko.AuthenticationException:
            raise AuthFailed("The machine refused the login (wrong user, password or key).") from None
        except paramiko.SSHException as exc:
            raise SSHError("The SSH login could not complete: " + _scrub(str(exc), c.secrets())) from None

    @staticmethod
    def _load_key(paramiko, c: Credentials):
        path = os.path.expanduser(c.key_path or "")
        if not os.path.isfile(path):
            raise AuthFailed("The private key file was not found. Check the path.")
        last: Exception | None = None
        for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
            try:
                return cls.from_private_key_file(path, password=c.passphrase)
            except paramiko.PasswordRequiredException:
                raise AuthFailed("That private key is protected by a passphrase; enter it.") from None
            except paramiko.SSHException as exc:
                last = exc
        if c.passphrase:
            raise AuthFailed("The key could not be read (wrong passphrase, or not an OpenSSH/PEM key).") from last
        raise AuthFailed("The key could not be read (is it an unencrypted OpenSSH/PEM private key?).") from last

    # -- use
    def _need(self):
        if self._t is None or not self._t.is_active():
            raise SSHError("The connection to the machine is closed.")
        return self._t

    def run(self, command: str, timeout: float = 30.0) -> tuple[int, str, str]:
        chan = self._need().open_session(timeout=CONNECT_TIMEOUT)
        chan.settimeout(timeout)
        try:
            chan.exec_command(command)
            out = chan.makefile("rb").read().decode("utf-8", "replace")
            err = chan.makefile_stderr("rb").read().decode("utf-8", "replace")
            return chan.recv_exit_status(), out, err
        except TimeoutError:
            raise SSHError("A command on the machine took too long.") from None
        finally:
            chan.close()

    def put(self, data: bytes, remote_path: str, mode: int = 0o600) -> None:
        import paramiko
        sftp = paramiko.SFTPClient.from_transport(self._need())
        try:
            with sftp.file(remote_path, "wb") as fh:
                fh.write(data)
            try:
                sftp.chmod(remote_path, mode)
            except OSError:
                pass                                           # Windows servers ignore modes
        except OSError as exc:
            raise SSHError(f"Could not write {remote_path} on the machine ({exc}).") from None
        finally:
            sftp.close()

    def open_stream(self, command: str) -> Stream:
        chan = self._need().open_session(timeout=CONNECT_TIMEOUT)
        chan.exec_command(command)
        return _ParamikoStream(chan, self.creds.secrets())

    def close(self) -> None:
        t, self._t = self._t, None
        if t is not None:
            try:
                t.close()
            except Exception:
                pass


def _scrub(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text


def make_transport(target: Target, creds: Credentials, store: HostKeyStore,
                   trusted_fingerprint: str | None = None) -> Transport:
    """The real transport. (Tests give the manager their own factory instead.)"""
    if not paramiko_available():
        raise MissingParamiko()
    return ParamikoTransport(target, creds, store, trusted_fingerprint)
