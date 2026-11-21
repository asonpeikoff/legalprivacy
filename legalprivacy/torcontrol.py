"""Minimal, dependency-free Tor control-port client (spec: control-spec.txt)."""
from __future__ import annotations

import binascii
import re
import socket
from .paths import getenv
from pathlib import Path

DEFAULT_COOKIE_PATHS = (
    "/var/run/tor/control.authcookie",
    "/run/tor/control.authcookie",
    "/var/lib/tor/control_auth_cookie",
    "~/.tor/control_authcookie",
)


class TorControlError(RuntimeError):
    pass


def split_hostport(spec: str, default_port: int) -> tuple[str, int]:
    host, _, port = spec.rpartition(":") if ":" in spec else (spec, "", "")
    return (host or "127.0.0.1"), (int(port) if port else default_port)


class TorControl:
    def __init__(self, host: str = "127.0.0.1", port: int = 9051,
                 password: str | None = None, cookie_path: str | None = None,
                 timeout: float = 5.0):
        self.host, self.port = host, port
        self.password = password or getenv("TOR_CONTROL_PW")
        self.cookie_path = cookie_path or getenv("TOR_CONTROL_COOKIE")
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._f = None

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> TorControl:
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        try:
            self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as exc:
            raise TorControlError(f"cannot reach control port {self.host}:{self.port}: {exc}") from exc
        self._f = self._sock.makefile("rw", newline="\r\n", encoding="utf-8")
        self._authenticate()

    def close(self) -> None:
        try:
            if self._f:
                self._f.write("QUIT\r\n")
                self._f.flush()
        except Exception:
            pass
        for obj in (self._f, self._sock):
            try:
                if obj:
                    obj.close()
            except Exception:
                pass
        self._f = self._sock = None

    # -- protocol ----------------------------------------------------------
    def _read_reply(self) -> tuple[str, list[str]]:
        lines: list[str] = []
        code = ""
        while True:
            raw = self._f.readline()
            if not raw:
                raise TorControlError("control connection closed")
            line = raw.rstrip("\r\n")
            if len(line) < 4:
                continue
            code, sep, body = line[:3], line[3], line[4:]
            if sep == "+":                      # data reply, read until "."
                lines.append(body)
                while True:
                    d = self._f.readline().rstrip("\r\n")
                    if d == ".":
                        break
                    lines.append(d[1:] if d.startswith("..") else d)
            else:
                lines.append(body)
            if sep == " ":
                return code, lines

    def cmd(self, line: str, expect_ok: bool = True) -> list[str]:
        if self._f is None:
            raise TorControlError("not connected")
        self._f.write(line + "\r\n")
        self._f.flush()
        code, lines = self._read_reply()
        if expect_ok and not code.startswith("250"):
            raise TorControlError(f"{line.split()[0]} failed: {code} {' '.join(lines)}")
        return lines

    def _authenticate(self) -> None:
        info = self.cmd("PROTOCOLINFO 1", expect_ok=False)
        methods, cookiefile = set(), None
        for ln in info:
            m = re.match(r'AUTH METHODS=([A-Z,]+)(?: COOKIEFILE="(.*)")?', ln)
            if m:
                methods = set(m.group(1).split(","))
                cookiefile = m.group(2)
        try:
            if "NULL" in methods:
                self.cmd("AUTHENTICATE")
            elif "HASHEDPASSWORD" in methods and self.password:
                if any(c in self.password for c in "\r\n\0"):
                    raise TorControlError("the control password must not contain line breaks")
                self.cmd('AUTHENTICATE "%s"' % self.password.replace("\\", "\\\\").replace('"', '\\"'))
            elif methods & {"COOKIE", "SAFECOOKIE"}:
                path = self.cookie_path or cookiefile
                if not path or not Path(path).expanduser().exists():
                    for cand in DEFAULT_COOKIE_PATHS:
                        if Path(cand).expanduser().exists():
                            path = cand
                            break
                if not path:
                    raise TorControlError("cookie auth required but no cookie file found "
                                          "(set LEGALPRIVACY_TOR_CONTROL_COOKIE)")
                data = Path(path).expanduser().read_bytes()
                if len(data) != 32:      # a real cookie is exactly 32 bytes; never send some other file's contents
                    raise TorControlError("the auth cookie file isn't a Tor control cookie (expected 32 bytes)")
                self.cmd("AUTHENTICATE " + binascii.hexlify(data).decode())
            else:
                raise TorControlError(f"no usable auth method (server offers {sorted(methods)})")
        except OSError as exc:
            raise TorControlError(f"cannot read auth cookie: {exc}") from exc

    # -- helpers -----------------------------------------------------------
    def getinfo(self, key: str) -> str:
        lines = self.cmd(f"GETINFO {key}")
        first = lines[0]
        prefix = f"{key}="
        if first.startswith(prefix):
            rest = first[len(prefix):]
            extra = [ln for ln in lines[1:] if ln != "OK"]
            return "\n".join([rest] + extra).strip()
        return first

    def newnym(self) -> None:
        self.cmd("SIGNAL NEWNYM")

    def shutdown(self) -> None:
        self.cmd("SIGNAL SHUTDOWN")

    def circuits(self) -> list[dict]:
        out = []
        for ln in self.getinfo("circuit-status").splitlines():
            parts = ln.split()
            if len(parts) < 2:
                continue
            circ = {"id": parts[0], "status": parts[1], "path": [], "purpose": "", "flags": ""}
            idx = 2
            if len(parts) > 2 and "=" not in parts[2]:
                circ["path"] = [h.split("~")[-1] if "~" in h else h.lstrip("$")[:8]
                                for h in parts[2].split(",")]
                idx = 3
            for kv in parts[idx:]:
                k, _, v = kv.partition("=")
                if k == "PURPOSE":
                    circ["purpose"] = v
                elif k == "BUILD_FLAGS":
                    circ["flags"] = v
            out.append(circ)
        return out
