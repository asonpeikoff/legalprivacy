"""Tor DNS: an optional local DNS listener served by Tor's DNSPort.

Tor's DNSPort "opens this port to listen for UDP DNS requests, and resolves them anonymously". It only
handles A, AAAA and PTR requests. Names are resolved by Tor exit relays, so this is a deliberate, narrow
use of exits for DNS only. The Tor lane for noise stays onion-only, and a middle relay or bridge (the relay
screen) does not provide DNS: only exits resolve names, and this app never runs an exit.

Safety rules enforced here:
  * the listener is on loopback (127.0.0.1) unless the user explicitly asks for a LAN address;
  * a LAN address must be one of the machine's own private (RFC 1918 or fc00::/7) addresses, never
    0.0.0.0, never a public address.
"""
from __future__ import annotations

import ipaddress
import socket
import time

from . import dnsplan

LOOPBACK = "127.0.0.1"
TEST_NAME = "example.com"          # reserved for documentation, always resolvable, neutral
DEFAULT_PORT = 19053               # preferred port; a free one is picked when it is taken

_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_ULA = ipaddress.ip_network("fc00::/7")


class TorDnsError(ValueError):
    pass


def is_private_lan_address(addr: str) -> bool:
    """True only for an RFC 1918 IPv4 or a fc00::/7 (ULA) IPv6 address. Loopback, link-local,
    unspecified (0.0.0.0, ::), public and malformed values are all refused."""
    try:
        ip = ipaddress.ip_address((addr or "").strip())
    except ValueError:
        return False
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        return False
    if ip.version == 4:
        return any(ip in n for n in _RFC1918)
    return ip in _ULA


def validate_dns(port: int, lan: bool, lan_addr: str) -> None:
    """Raises TorDnsError for a setting that must not reach a torrc."""
    if isinstance(port, bool) or not isinstance(port, int):
        raise TorDnsError("Tor DNS port must be a whole number")
    if port != 0 and not (1024 <= port <= 65535):
        raise TorDnsError("Tor DNS port must be 0 (off) or a number from 1024 to 65535")
    if port in (9050, 9051, 9150, 9151):
        raise TorDnsError("Tor DNS port must not be one of Tor's own SOCKS/control ports")
    if lan:
        if port == 0:
            raise TorDnsError("Turn Tor DNS on before sharing it with your network")
        if not is_private_lan_address(lan_addr):
            raise TorDnsError("To share Tor DNS on your network, pick one of this computer's private "
                              "addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x or fdxx:…). "
                              "Public addresses and 0.0.0.0 are never allowed.")


def bind_address(lan: bool, lan_addr: str) -> str:
    """Where the DNSPort listens: loopback, or the one private address the user chose."""
    return lan_addr.strip() if lan and is_private_lan_address(lan_addr) else LOOPBACK


def torrc_line(port: int, lan: bool = False, lan_addr: str = "") -> str | None:
    """The `DNSPort` torrc line, or None when Tor DNS is off. Never a wildcard address."""
    validate_dns(port, lan, lan_addr)
    if port == 0:
        return None
    host = bind_address(lan, lan_addr)
    if ":" in host:
        host = f"[{host}]"
    return f"DNSPort {host}:{port}"


def local_private_addresses() -> list[str]:
    """This machine's private (RFC 1918 / ULA) addresses, for the 'share on my network' picker."""
    found: list[str] = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.append(info[4][0])
    except OSError:
        pass
    try:                        # the address the OS would use for the local network (no packet is sent)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 9))
            found.append(s.getsockname()[0])
    except OSError:
        pass
    try:
        import psutil           # optional; used only when it happens to be installed
        for addrs in psutil.net_if_addrs().values():
            found += [a.address for a in addrs if a.family in (socket.AF_INET, socket.AF_INET6)]
    except Exception:
        pass
    out: list[str] = []
    for a in found:
        a = a.split("%")[0]
        if is_private_lan_address(a) and a not in out:
            out.append(a)
    return out


def probe(host: str, port: int, name: str = TEST_NAME, timeout: float = 15.0) -> dict:
    """Send one real A query to the DNSPort and report the answer and how long it took.
    Tor needs a few seconds to build a circuit for the first lookup, so the timeout is generous."""
    t0 = time.time()
    data = dnsplan._ask(host, name, timeout=timeout, port=port)
    ms = round((time.time() - t0) * 1000)
    if data is None:
        return {"ok": False, "name": name, "ms": ms,
                "error": "No answer from the Tor DNS port. Tor may still be connecting, or Tor DNS is off."}
    rcode = data[3] & 0x0F
    answers = dnsplan.answers_a(data)
    if rcode == 0 and answers:
        return {"ok": True, "name": name, "answers": answers, "ms": ms}
    if rcode == 0:
        return {"ok": False, "name": name, "ms": ms, "error": "Tor answered, but with no address for that name."}
    return {"ok": False, "name": name, "ms": ms,
            "error": f"Tor could not resolve the test name (DNS code {rcode}). Try again in a moment."}
