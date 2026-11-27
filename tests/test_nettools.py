"""Tools tab: speed test wiring, DNS check (Qubes-aware, egress resolver), privacy-check rows."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

from legalprivacy import nettools  # noqa: E402
from legalprivacy.controller import Controller  # noqa: E402


def _ctl():
    return Controller(os.path.join(tempfile.mkdtemp(), "config.yaml"))


def test_speed_start_reads_the_clearnet_proxy_from_the_transports_dict(monkeypatch=None):
    """Regression: `profile.transports.clearnet` raised "'dict' object has no attribute 'clearnet'"."""
    c = _ctl()
    seen = {}
    real = nettools.speed_test
    nettools.speed_test = lambda proxy, progress=None, **k: seen.update(proxy=proxy) or {
        "down_mbps": 1.0, "up_mbps": 2.0, "errors": [], "via": "direct"}
    try:
        c.speed_start()
        for _ in range(100):
            if c.speed_status()["state"] == "done":
                break
            time.sleep(0.02)
    finally:
        nettools.speed_test = real
    assert c.speed_status()["state"] == "done" and c.speed_status()["result"]["up_mbps"] == 2.0
    assert "proxy" in seen


def test_speed_endpoints_can_be_overridden_from_the_environment():
    import importlib
    os.environ["LEGALPRIVACY_SPEED_DOWN_URL"] = "https://example.test/down?n={n}"
    try:
        importlib.reload(nettools)
        assert nettools.DOWN_URL.format(n=5) == "https://example.test/down?n=5"
    finally:
        del os.environ["LEGALPRIVACY_SPEED_DOWN_URL"]
        importlib.reload(nettools)
    assert "cloudflare" in nettools.DOWN_URL


def test_speed_test_sends_a_browser_user_agent_so_endpoints_do_not_403(monkeypatch):
    # Regression: speed.cloudflare.com answers 403 to a request with no User-Agent (the default urllib one).
    seen = []
    import urllib.request

    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=-1): return b"" if seen and seen[-1].get("read") else (seen[-1].__setitem__("read", True) or b"x" * 1000)

    def fake_open(self, req, timeout=0):
        ua = req.get_header("User-agent") if hasattr(req, "get_header") else None
        seen.append({"url": req.full_url, "ua": ua})
        return FakeResp()
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", fake_open)
    nettools.speed_test(down_bytes=1000, up_bytes=1000, timeout=5)
    assert len(seen) == 2 and all(h["ua"] and "Mozilla" in h["ua"] for h in seen)


def _stub(monkey_resolvers, egress, qubes=None):
    nettools.system_resolvers = lambda: {"system": "Linux", "resolvers": monkey_resolvers, "note": ""}
    nettools.egress_resolver = lambda: egress
    nettools.qubes_vm_type = lambda: qubes


def test_dns_check_explains_private_and_qubes_resolvers_and_reports_the_real_one():
    saved = (nettools.system_resolvers, nettools.egress_resolver, nettools.qubes_vm_type)
    try:
        _stub(["10.139.1.1", "192.168.1.1", "9.9.9.9"], {"ip": "9.9.9.9", "name": "dns9.quad9.net"}, "AppVM")
        d = nettools.dns_leak_check(["9.9.9.9"])
    finally:
        nettools.system_resolvers, nettools.egress_resolver, nettools.qubes_vm_type = saved
    v = {r["ip"]: r["verdict"] for r in d["resolvers"]}
    assert "Qubes virtual DNS" in v["10.139.1.1"]
    assert "private address" in v["192.168.1.1"]
    assert "chosen secure" in v["9.9.9.9"]
    assert d["egress_resolver"]["is_chosen"] is True and d["qubes"] == "AppVM"
    assert "Qubes OS (AppVM)" in d["note"]


def test_dns_check_without_qubes_has_no_qubes_note():
    saved = (nettools.system_resolvers, nettools.egress_resolver, nettools.qubes_vm_type)
    try:
        _stub(["8.8.8.8"], {"error": "lookup failed: offline"})
        d = nettools.dns_leak_check([])
    finally:
        nettools.system_resolvers, nettools.egress_resolver, nettools.qubes_vm_type = saved
    assert d["qubes"] is None and "Qubes" not in d["note"] and "error" in d["egress_resolver"]


def test_privacy_check_on_qubes_does_not_claim_the_vpn_is_missing():
    saved = nettools.qubes_vm_type
    nettools.qubes_vm_type = lambda: "AppVM"
    try:
        rows = {r["name"]: r for r in nettools.privacy_check(_ctl())}
    finally:
        nettools.qubes_vm_type = saved
    assert "Qubes OS" in rows["VPN"]["detail"] and "No VPN interface seen" not in rows["VPN"]["detail"]
    assert "network qubes" in rows["Encrypted DNS"]["detail"]


def test_privacy_check_has_a_mac_row():
    import legalprivacy.macspoof as m
    saved = m.MacSpoofer.status, m.MacSpoofer.environment
    m.MacSpoofer.status = lambda self: [{"iface": "wlan0", "eligible": True, "spoofed": False}]
    m.MacSpoofer.environment = lambda self: {"qubes_vm_type": None, "xen_virtual_interfaces": []}
    try:
        rows = {r["name"]: r for r in nettools.privacy_check(_ctl())}
    finally:
        m.MacSpoofer.status, m.MacSpoofer.environment = saved
    assert "wlan0" in rows["MAC address"]["detail"] and "mac randomize" in rows["MAC address"]["advice"]


def test_a_vpn_providers_address_is_recognised_and_counts_for_encrypted_dns(monkeypatch):
    monkeypatch.setattr(nettools, "qubes_vm_type", lambda: None)
    monkeypatch.setattr(nettools, "_vpn_interfaces", lambda: [])
    monkeypatch.setattr(nettools, "external_ip_owner",
                        lambda timeout=6.0: {"ip": "203.0.113.5", "org": "AS62371 Proton AG", "hostname": "", "error": None})
    rows = {r["name"]: r for r in nettools.privacy_check(_ctl())}
    assert rows["VPN"]["status"] == "ok" and "Proton AG" in rows["VPN"]["detail"]
    assert rows["Encrypted DNS"]["status"] == "ok" and "VPN" in rows["Encrypted DNS"]["detail"]
    monkeypatch.setattr(nettools, "external_ip_owner",
                        lambda timeout=6.0: {"ip": "203.0.113.5", "org": "AS7922 Comcast Cable", "hostname": "", "error": None})
    rows = {r["name"]: r for r in nettools.privacy_check(_ctl())}
    assert rows["VPN"]["status"] == "info" and "not a known VPN" in rows["VPN"]["detail"]
    assert nettools.vpn_provider({"org": "AS9009 M247 Europe SRL"})[0] == "host"
    assert nettools.vpn_provider({"org": "AS39351 31173 Services AB"})[0] == "vpn"


def test_ublock_origin_is_found_however_it_was_installed(tmp_path, monkeypatch):
    import json
    import legalprivacy.history as h
    ff = tmp_path / "ff"
    (ff / "abc.default-release").mkdir(parents=True)
    (ff / "abc.default-release" / "extensions.json").write_text(json.dumps(
        {"addons": [{"id": "uBlock0@raymondhill.net", "active": True, "location": "app-system-share"}]}))
    ch = tmp_path / "chrome"
    (ch / "Profile 1").mkdir(parents=True)
    (ch / "Profile 1" / "Secure Preferences").write_text('{"extensions":{"settings":{"cjpalhdlnbpafiamejdnhcphjbkeiagm":{}}}}')
    monkeypatch.setattr(h, "_firefox_bases", lambda: [str(ff)])
    monkeypatch.setattr(h, "_chromium_bases", lambda: [("Chrome", str(ch))])
    monkeypatch.setattr(nettools, "_FIREFOX_SYSTEM_EXT", ())
    monkeypatch.setattr(nettools, "_MORE_FIREFOX_BASES", ())
    monkeypatch.setattr(nettools, "_MORE_CHROMIUM_BASES", ())
    assert nettools._content_blocker() == ["Chrome", "Firefox"]
    sysext = tmp_path / "share" / "{ec8030f7-c20a-464f-9b0e-13a3a9e97384}"
    (sysext / "uBlock0@raymondhill.net").mkdir(parents=True)
    (ff / "abc.default-release" / "extensions.json").unlink()
    monkeypatch.setattr(nettools, "_FIREFOX_SYSTEM_EXT", (str(tmp_path / "share"),))
    assert "Firefox (system add-on)" in nettools._content_blocker()
