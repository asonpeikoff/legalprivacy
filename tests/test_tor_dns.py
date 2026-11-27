"""Tor DNS (optional DNSPort): validation, torrc lines, the test helper, controller state. Offline."""
import socket
import struct
import threading

import pytest

from legalprivacy import tordns
from legalprivacy.config import ConfigError, Profile, apply_overrides
from legalprivacy.events import EventLog
from legalprivacy.tormanager import TorManager


# ── validation ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("addr", ["192.168.1.20", "10.0.0.5", "172.16.4.4", "172.31.255.1", "fd12:3456::1"])
def test_private_addresses_accepted(addr):
    assert tordns.is_private_lan_address(addr)


@pytest.mark.parametrize("addr", ["0.0.0.0", "::", "127.0.0.1", "::1", "8.8.8.8", "172.32.0.1", "169.254.1.1",
                                  "fe80::1", "224.0.0.1", "", "example.com", "192.168.1.1\nDNSPort 0.0.0.0:53"])
def test_non_private_addresses_refused(addr):
    assert not tordns.is_private_lan_address(addr)


def test_default_is_off_and_loopback():
    cfg = Profile(name="x").transports["tor"]
    assert cfg.dns_port == 0 and cfg.dns_lan is False
    assert tordns.torrc_line(0) is None
    assert tordns.torrc_line(19053) == "DNSPort 127.0.0.1:19053"


def test_lan_line_only_with_private_address():
    assert tordns.torrc_line(19053, True, "192.168.1.20") == "DNSPort 192.168.1.20:19053"
    assert tordns.torrc_line(19053, True, "fd00::5") == "DNSPort [fd00::5]:19053"
    for bad in ("0.0.0.0", "8.8.8.8", "", "::"):
        with pytest.raises(tordns.TorDnsError):
            tordns.torrc_line(19053, True, bad)
    with pytest.raises(tordns.TorDnsError):
        tordns.torrc_line(0, True, "192.168.1.20")        # LAN sharing needs Tor DNS on


def test_lan_address_ignored_unless_lan_enabled():
    assert tordns.torrc_line(19053, False, "192.168.1.20") == "DNSPort 127.0.0.1:19053"


@pytest.mark.parametrize("port", [-1, 53, 1023, 65536, 9050, 9051])
def test_bad_ports_refused(port):
    with pytest.raises(tordns.TorDnsError):
        tordns.validate_dns(port, False, "")


def test_config_validation_and_coercion():
    p = Profile(name="x")
    apply_overrides(p, {"transports": {"tor": {"dns_port": "19053"}}})
    assert p.transports["tor"].dns_port == 19053
    with pytest.raises(ConfigError):
        apply_overrides(Profile(name="x"), {"transports": {"tor": {"dns_port": 80}}})
    with pytest.raises(ConfigError):
        apply_overrides(Profile(name="x"), {"transports": {"tor": {"dns_port": "abc"}}})
    with pytest.raises(ConfigError):
        apply_overrides(Profile(name="x"), {"transports": {"tor": {"dns_port": 19053, "dns_lan": True,
                                                                    "dns_lan_addr": "1.2.3.4"}}})
    with pytest.raises(ConfigError):
        apply_overrides(Profile(name="x"), {"transports": {"tor": {"dns_port": 19053, "dns_lan": True}}})
    ok = apply_overrides(Profile(name="x"), {"transports": {"tor": {"dns_port": 19053, "dns_lan": True,
                                                                     "dns_lan_addr": "10.1.2.3"}}})
    assert ok.transports["tor"].dns_lan_addr == "10.1.2.3"


def test_lan_requires_literal_true():
    p = apply_overrides(Profile(name="x"), {"transports": {"tor": {"dns_port": 19053, "dns_lan": "yes",
                                                                    "dns_lan_addr": "10.1.2.3"}}})
    assert p.transports["tor"].dns_lan is False


# ── the torrc the manager writes ────────────────────────────────────────────
def _torrc(tmp_path, monkeypatch, **kw):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    tm = TorManager(EventLog(), **kw)
    tm.binary = str(tmp_path / "tor")
    tm.dns_port = kw.get("dns_port", 0)
    data = tmp_path / "data"
    data.mkdir()
    tm.cookie_path = str(tmp_path / "cookie")
    tm.socks_host, tm.socks_port, tm.control_host, tm.control_port = "127.0.0.1", 19050, "127.0.0.1", 19051
    return tm._write_torrc(data).read_text()


def test_torrc_has_no_dnsport_by_default(tmp_path, monkeypatch):
    assert "DNSPort" not in _torrc(tmp_path, monkeypatch)


def test_torrc_dnsport_loopback(tmp_path, monkeypatch):
    t = _torrc(tmp_path, monkeypatch, dns_port=19053)
    assert "DNSPort 127.0.0.1:19053" in t
    assert "DNSPort 0.0.0.0" not in t
    assert "ExitPolicy" not in t and "ExitNodes" not in t       # the noise lane stays as it was


def test_torrc_dnsport_lan(tmp_path, monkeypatch):
    t = _torrc(tmp_path, monkeypatch, dns_port=19053, dns_lan=True, dns_lan_addr="192.168.1.9")
    assert "DNSPort 192.168.1.9:19053" in t and "DNSPort 0.0.0.0" not in t


def test_dns_info_states():
    tm = TorManager(EventLog(), dns_port=19053)
    assert tm.dns_info()["on"] and not tm.dns_info()["ready"]
    assert TorManager(EventLog()).dns_info()["on"] is False
    assert TorManager(EventLog(), mode="external", dns_port=19053).dns_info()["managed"] is False


# ── the test helper against a local fake DNS server ─────────────────────────
class FakeDns:
    """Answers every A query with 93.184.216.34 (or NXDOMAIN / nothing), over UDP on loopback."""
    def __init__(self, behaviour="answer"):
        self.behaviour = behaviour
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self._stop = threading.Event()
        self.seen: list[bytes] = []
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                continue
            self.seen.append(data)
            if self.behaviour == "silent":
                continue
            qid = data[:2]
            question = data[12:]
            if self.behaviour == "nxdomain":
                self.sock.sendto(qid + b"\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + question, addr)
                continue
            rr = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
            self.sock.sendto(qid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question + rr, addr)

    def close(self):
        self._stop.set()
        self.t.join(1)
        self.sock.close()


def test_probe_gets_answer_and_latency():
    srv = FakeDns()
    try:
        r = tordns.probe("127.0.0.1", srv.port, timeout=3)
    finally:
        srv.close()
    assert r["ok"] and r["answers"] == ["93.184.216.34"] and r["ms"] >= 0
    assert b"\x07example\x03com\x00" in srv.seen[0]           # a real A query for the neutral name
    assert srv.seen[0][-4:] == b"\x00\x01\x00\x01"


def test_probe_nxdomain_is_a_plain_error():
    srv = FakeDns("nxdomain")
    try:
        r = tordns.probe("127.0.0.1", srv.port, timeout=3)
    finally:
        srv.close()
    assert not r["ok"] and "code 3" in r["error"]


def test_probe_timeout_is_a_plain_error():
    srv = FakeDns("silent")
    try:
        r = tordns.probe("127.0.0.1", srv.port, timeout=0.5)
    finally:
        srv.close()
    assert not r["ok"] and "No answer" in r["error"]


# ── controller ──────────────────────────────────────────────────────────────
@pytest.fixture()
def ctl(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    from legalprivacy.controller import Controller
    return Controller(str(tmp_path / "config.yaml"))


def test_tor_state_reports_dns_off_by_default(ctl):
    d = ctl.tor_state()["dns"]
    assert d["on"] is False and d["address"] is None and d["port"] is None and d["lan"] is False


def test_tor_state_reports_dns_on(ctl):
    ctl.apply_config({"transports": {"tor": {"dns_port": 19053}}})
    d = ctl.tor_state()["dns"]
    assert d["on"] and d["address"] == "127.0.0.1" and not d["ready"]


def test_dns_test_when_off_or_not_ready(ctl):
    assert "off" in ctl.tor_dns_test()["error"]
    ctl.apply_config({"transports": {"tor": {"dns_port": 19053}}})
    r = ctl.tor_dns_test()
    assert not r["ok"] and "isn't ready" in r["error"]


def test_dns_test_uses_the_dnsport(ctl):
    srv = FakeDns()
    try:
        ctl.apply_config({"transports": {"tor": {"dns_port": 19053}}})
        tm = ctl.tor_manager()
        tm.state, tm.dns_port, tm.dns_host = "ready", srv.port, "127.0.0.1"
        r = ctl.tor_dns_test()
    finally:
        srv.close()
    assert r["ok"] and r["answers"] == ["93.184.216.34"]
    assert ctl.tor_state()["dns_test"]["ok"]


def test_changing_dns_settings_rebuilds_the_manager(ctl):
    first = ctl.tor_manager()
    ctl.apply_config({"transports": {"tor": {"dns_port": 19053}}})
    assert ctl.tor_manager() is not first
