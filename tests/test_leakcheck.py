import os
import tempfile
from legalprivacy import leakcheck as L
from legalprivacy.config import ConfigError
from legalprivacy.controller import Controller


def by_id(checks):
    return {c["id"]: c for c in checks}


def test_every_check_has_want_saw_status_and_plain_words():
    facts = {"running": True, "paused": False, "dns": {"mode": "mix", "resolvers": [
        {"ip": "1.1.1.1", "enabled": True, "verdict": "ok"}, {"ip": "9.9.9.9", "enabled": True, "verdict": "down"}]},
        "system_resolvers": [{"ip": "10.0.0.1", "what": "your router"}],
        "tor": {"ready": True, "state": "ready", "pct": 100},
        "exit": {"direct_ip": "1.2.3.4", "tor_ip": "5.6.7.8", "is_tor": True},
        "real_browser": True, "own_ua": True}
    cs = by_id(L.build_checks(facts))
    for c in cs.values():
        assert c["want"] and c["saw"] and c["status"] in ("ok", "bad", "info", "unknown")
    assert cs["noise"]["status"] == "ok" and cs["dns"]["status"] == "ok" and cs["exit"]["status"] == "ok"
    s = L.summarize(list(cs.values()))
    assert s["all_good"] and s["bad"] == 0


def test_problems_are_named_not_working_with_advice():
    facts = {"running": False, "dns": {"mode": "mix", "intercepted": True, "system_egress": "9.9.9.9", "resolvers": [
        {"ip": "1.1.1.1", "enabled": True, "verdict": "intercepted"}]},
        "tor": {"ready": True, "state": "ready", "pct": 100},
        "exit": {"direct_ip": "1.2.3.4", "tor_ip": "1.2.3.4", "is_tor": False}, "real_browser": False}
    cs = by_id(L.build_checks(facts))
    assert cs["noise"]["status"] == "bad" and cs["dns"]["status"] == "bad"
    assert cs["exit"]["status"] == "bad" and cs["browser"]["status"] == "bad"
    assert all(cs[k]["hint"] for k in ("noise", "dns", "exit", "browser"))
    assert L.summarize(list(cs.values()))["bad"] == 4


def test_untested_is_unknown_not_working():
    facts = {"running": True, "dns": {"mode": "mix", "resolvers": [{"ip": "1.1.1.1", "enabled": True}]},
             "tor": {"ready": True, "state": "ready", "pct": 100}}
    cs = by_id(L.build_checks(facts))
    assert cs["dns"]["status"] == "unknown" and cs["exit"]["status"] == "unknown"
    assert not L.summarize(list(cs.values()))["all_good"]


def test_panic_levels_keep_settings():
    d = tempfile.mkdtemp()
    c = Controller(profile_path=os.path.join(d, "p.json"))
    c.apply_config({"transports": {"clearnet": {"enabled": True, "browser": "off"}}})
    r = c.panic("soft")
    assert "noise was already stopped" in r["done"] and os.path.exists(c.profile_path)
    assert "Proof data and log files deleted" in c.panic("hard")["done"]
    assert os.path.exists(c.profile_path)
    try:
        c.panic("nuclear")
        raise AssertionError
    except ConfigError:
        pass
