"""Maximum DNS security: encrypted lookups to the secure resolvers, and Tor does the name lookups for onion visits."""
import random
import socket

from legalprivacy import engines
from legalprivacy.config import Profile, apply_overrides
from legalprivacy.dnsplan import _query
from legalprivacy.engines import DOT_HOSTS, DnsNoise, configure_dns, dot_query
from legalprivacy.transports import TorTransport


def test_mixed_dns_with_encryption_for_the_secure_part_is_the_default():
    p = Profile(name="d")
    assert p.dns.mode == "mix" and p.dns.system_share == 0.85 and p.dns.encrypted is True
    apply_overrides(p, {"dns": {"encrypted": False}})
    assert p.dns.encrypted is False


class _FakeTLS:
    def __init__(self, reply):
        self.sent, self._buf = b"", reply
    def settimeout(self, _t): pass
    def sendall(self, b): self.sent += b
    def recv(self, n):
        out, self._buf = self._buf[:n], self._buf[n:]
        return out
    def __enter__(self): return self
    def __exit__(self, *a): return False


class _Ctx:
    def __init__(self, tls): self.tls, self.host = tls, None
    def wrap_socket(self, raw, server_hostname=None):
        self.host = server_hostname
        return self.tls


def test_dns_over_tls_is_length_prefixed_and_checked_against_the_resolver_name(monkeypatch):
    packet = _query("example.com", 7)
    answer = b"\x00\x07" + b"\x81\x80" + b"\x00" * 8 + b"abcd"
    tls = _FakeTLS(len(answer).to_bytes(2, "big") + answer)
    ctx = _Ctx(tls)
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: _FakeTLS(b""))
    got = dot_query("9.9.9.9", packet, 1.0, context=ctx)
    assert got == answer and ctx.host == "dns.quad9.net"
    assert tls.sent == len(packet).to_bytes(2, "big") + packet
    assert dot_query("203.0.113.9", packet, 1.0, context=ctx) is None           # not a known TLS resolver: no plain fallback here


def test_a_failed_tls_handshake_is_a_failure_never_a_plain_text_retry(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: _FakeTLS(b""))
    sent = []
    monkeypatch.setattr(socket.socket, "sendto", lambda *a, **k: sent.append(a) or 0, raising=False)
    configure_dns(True)
    monkeypatch.setattr(engines, "dot_query", lambda ip, pkt, t=3.0, context=None: None)
    noise = DnsNoise(random.Random(1), plan=None)
    assert noise.fire(_query("example.com", 1), "9.9.9.9") is False and not sent


def test_an_unencrypted_resolver_is_swapped_for_one_that_can_do_tls():
    configure_dns(True)
    class Plan:
        def pick(self): return ("80.152.203.134", "OpenNIC")
    class Pool:
        def hostname(self): return "example.org"
    noise = DnsNoise(random.Random(3), domains=Pool(), plan=Plan())
    assert noise.make_query()[2] in DOT_HOSTS
    configure_dns(False)
    try:
        assert noise.make_query()[2] == "80.152.203.134"                         # switched off: your list is used as is
    finally:
        configure_dns(True)


def test_onion_and_tor_lookups_are_done_by_tor_not_your_dns():
    from legalprivacy.identity import make_identity
    tor = TorTransport.__new__(TorTransport)
    tor.socks_host, tor.socks_port, tor.circuit_seed = "127.0.0.1", 9050, "s"
    ident = make_identity(random.Random(1), 1, ["w"])
    assert tor._socks_proxies(ident)["https"].startswith("socks5h://")           # the "h": Tor resolves the name


def test_the_tor_client_config_refuses_leaky_and_internal_answers():
    import inspect

    from legalprivacy import tormanager
    src = inspect.getsource(tormanager.TorManager._write_torrc)
    for opt in ("SafeSocks 1", "ClientDNSRejectInternalAddresses 1", "ClientRejectInternalAddresses 1"):
        assert opt in src
