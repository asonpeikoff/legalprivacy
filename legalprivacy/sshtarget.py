"""The connection string for a remote machine: `user@host[:port]` (stdlib only, no network).

Accepts a host name, an IPv4 address, or an IPv6 address in brackets (`user@[fe80::1]:2222`); the port is
optional and defaults to 22. Nothing else is needed: the password or private key is given separately.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

DEFAULT_PORT = 22
_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-\\$@]{0,63}$")          # DOMAIN\user and user@domain forms allowed
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$")
_IPV6_RE = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")


class TargetError(ValueError):
    """A connection string that cannot be used. The message is safe to show."""


@dataclass(frozen=True)
class Target:
    user: str
    host: str
    port: int = DEFAULT_PORT

    @property
    def key(self) -> str:
        """The identity of the SSH server (what a host key belongs to)."""
        return host_key_id(self.host, self.port)

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.user}@{host}" + (f":{self.port}" if self.port != DEFAULT_PORT else "")


def host_key_id(host: str, port: int) -> str:
    return f"[{host.lower()}]:{port}"


def parse_target(text: str, default_port: int = DEFAULT_PORT) -> Target:
    s = (text or "").strip()
    if not s:
        raise TargetError("Enter the connection as user@host or user@host:port.")
    if any(c.isspace() for c in s) or "://" in s:
        raise TargetError("Enter just user@host or user@host:port (no spaces, no ssh://).")
    user, sep, rest = s.rpartition("@")           # the LAST @ splits user from host (a user name may contain one)
    if not sep or not user or not rest:
        raise TargetError("The user name is missing. Use user@host or user@host:port.")
    if not _USER_RE.match(user):
        raise TargetError("That user name has characters that are not allowed.")
    port = default_port
    if rest.startswith("["):                      # [ipv6] or [ipv6]:port
        close = rest.find("]")
        if close < 0:
            raise TargetError("The IPv6 address is missing its closing ].")
        host, tail = rest[1:close], rest[close + 1:]
        if not _IPV6_RE.match(host) or ":" not in host:
            raise TargetError("That is not a valid IPv6 address.")
        if tail:
            if not tail.startswith(":"):
                raise TargetError("Put the port after the address, like [::1]:2222.")
            port = _port(tail[1:])
    else:
        host, colon, p = rest.partition(":")
        if colon:
            port = _port(p)
        if not _HOST_RE.match(host):
            raise TargetError("That host name or IP address is not valid.")
    return Target(user=user, host=host.lower(), port=port)


def _port(p: str) -> int:
    if not p.isdigit() or not (1 <= int(p) <= 65535):
        raise TargetError("The port must be a number from 1 to 65535.")
    return int(p)
