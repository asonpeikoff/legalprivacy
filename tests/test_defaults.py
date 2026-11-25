import pytest

from legalprivacy.config import ConfigError
from legalprivacy.controller import Controller


@pytest.fixture
def ctl(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    return Controller(str(tmp_path / "config.yaml"))


def test_reset_to_recommended_keeps_personal_data(ctl):
    ctl.apply_config({"rate": {"level": 9}, "extras": {"typos": True}, "identity": {"own_ua": "MyBrowser/1"},
                      "mylist": {"enabled": True, "sites": ["example.org"]}})
    ctl.reset_to_recommended()
    assert ctl.profile.rate.level == 5.0 and ctl.profile.extras.typos is False
    assert ctl.profile.identity.own_ua == "MyBrowser/1"
    assert ctl.profile.mylist.sites == ["example.org"]


def test_my_defaults_round_trip(ctl):
    with pytest.raises(ConfigError):
        ctl.apply_my_defaults()
    ctl.apply_config({"rate": {"level": 8}})
    assert ctl.save_my_defaults() == {"has_mine": True}
    ctl.reset_to_recommended()
    assert ctl.profile.rate.level == 5.0
    ctl.apply_my_defaults()
    assert ctl.profile.rate.level == 8.0


def test_private_bridge_is_not_published_and_gives_a_pasteable_line(tmp_path):
    from legalprivacy.relay import RelaySpec, generate_torrc
    pub = generate_torrc(RelaySpec(mode="bridge", nickname="b", practice=False))
    priv = generate_torrc(RelaySpec(mode="bridge", nickname="b", practice=False, private=True))
    assert "PublishServerDescriptor bridge" in pub and "PublishServerDescriptor 0" in priv
    assert "ExitRelay 0" in priv and "reject *:*" in priv
    from legalprivacy.config import valid_bridge_line
    assert valid_bridge_line("203.0.113.5:9001 " + "A" * 40)


def test_exclude_nodes_accepts_only_fingerprints_and_countries(ctl):
    from legalprivacy.config import valid_exclude_entry
    assert valid_exclude_entry("A" * 40) and valid_exclude_entry("$" + "b" * 40) and valid_exclude_entry("{ru}")
    for bad in ("A" * 39, "{russia}", "1.2.3.4", "x\nSocksPort 1", ""):
        assert not valid_exclude_entry(bad)
    ctl.apply_config({"transports": {"tor": {"exclude_nodes": "{ru}\n" + "A" * 40 + ", {cn}"}}})
    assert ctl.profile.transports["tor"].exclude_nodes == ["{ru}", "A" * 40, "{cn}"]
    with pytest.raises(ConfigError):
        ctl.apply_config({"transports": {"tor": {"exclude_nodes": "evil\nSocksPort 1"}}})


def test_torrc_avoids_listed_relays(tmp_path, monkeypatch):
    from legalprivacy.events import EventLog
    from legalprivacy.tormanager import TorManager
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    tm = TorManager(EventLog(), exclude_nodes=["a" * 40, "{ru}"], exclude_strict=True)
    tm.binary = str(tmp_path / "bundle" / "tor" / "tor")
    tm.socks_host, tm.socks_port, tm.control_host, tm.control_port = "127.0.0.1", 19050, "127.0.0.1", 19051
    tm.cookie_path = str(tmp_path / "cookie")
    text = tm._write_torrc(tmp_path / "data").read_text()
    assert "ExcludeNodes $" + "a" * 40 + ",{ru}" in text and "StrictNodes 1" in text


def test_default_avoid_list_is_the_us_plus_governmental_names():
    from legalprivacy.config import Profile
    tor = Profile(name="d").transports["tor"]
    assert tor.exclude_nodes == ["{us}"] and tor.exclude_gov_names is True and tor.exclude_strict is True


def test_governmental_names_are_found_without_catching_ordinary_words(tmp_path):
    from legalprivacy import relayfilter as F
    for name in ("FBIvan", "NSAhoneypot", "PoliceNode", "TotallyNotTheCIA", "government1", "pentagonexit"):
        assert F.looks_governmental(name), name
    for name in ("transaction", "special", "financial", "amsterdam", "ABC", "Federation"):
        assert F.looks_governmental(name) is None, name
    assert F.looks_governmental("x", "ops@agency.gov") and F.looks_governmental("x", "a@b.mil")
    relays = [{"fingerprint": "A" * 40, "nickname": "FBIvan", "contact": ""},
              {"fingerprint": "B" * 40, "nickname": "nicenode", "contact": ""},
              {"fingerprint": "bad", "nickname": "NSA", "contact": ""}]
    assert [r["fingerprint"] for r in F.scan(relays)] == ["A" * 40]
    import json
    cache = tmp_path / "avoid.json"
    calls = []

    def http(url):
        calls.append(url)
        return json.dumps({"relays": relays}).encode()
    assert len(F.refresh(cache, http)) == 1 and len(F.refresh(cache, http)) == 1
    assert len(calls) == 1                                        # fetched once, then kept for a day
    def offline(url):
        raise OSError("no network")
    assert len(F.refresh(cache, offline, max_age=0)) == 1          # offline: keeps the last list


def test_dns_defaults_lean_on_normal_dns_and_do_more_lookups():
    from legalprivacy.config import Profile
    p = Profile(name="d")
    assert p.dns.mode == "mix" and p.dns.system_share == 0.85
    assert p.engines["dns"].budget_per_day > p.engines["search"].budget_per_day


def test_firefox_leads_when_the_engine_is_there_and_nobody_claims_it_when_it_is_not():
    from legalprivacy import useragents as U
    try:
        U.set_firefox_engine(True)
        w = U.persona_weights(0.0)
        assert w["desktop-firefox"] > w["desktop-chrome"] > w["desktop-chromium"]
        U.set_firefox_engine(False)
        assert U.persona_weights(0.0)["desktop-firefox"] == 0
    finally:
        U.set_firefox_engine(None)


def test_ason_persona_is_the_default_and_spreads_over_many_sites():
    import random as _r
    from collections import Counter
    from legalprivacy.config import Profile
    from legalprivacy.interests import CATEGORIES, PERSONAS, Persona
    assert Profile(name="d").extras.persona == "Ason" and abs(sum(PERSONAS["Ason"].values()) - 1) < 1e-9
    assert set(PERSONAS["Ason"]) <= set(CATEGORIES)
    p = Persona(_r.Random(3), "Ason")
    c = Counter(p.site() for _ in range(4000))
    assert len(c) > 300                                           # many different sites ...
    assert c.most_common(1)[0][1] < 0.03 * 4000                   # ... and no single one dominates
    objectivist = set(CATEGORIES["Objectivism"]["sites"])
    share = sum(n for s, n in c.items() if s in objectivist) / 4000
    assert 0.08 < share < 0.22                                    # present, but not oversampled
    assert "legalizingprivacy.substack.com" in objectivist
    assert not any("prometheusfdn" in s or "meetup" in s for s in objectivist)


def test_old_default_persona_is_switched_to_ason_once(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    cfg = tmp_path / "config.yaml"
    c = Controller(str(cfg))
    c.apply_config({"extras": {"persona": "Data scientist"}})
    c.app["migrated_ason"] = False
    c._save()
    c2 = Controller(str(cfg))
    assert c2.profile.extras.persona == "Ason"
    c2.apply_config({"extras": {"persona": "Data scientist"}})          # a later, deliberate choice is kept
    assert Controller(str(cfg)).profile.extras.persona == "Data scientist"


def test_launcher_prints_the_dashboard_link_and_the_start_script_can_install_a_service(tmp_path, monkeypatch, capsys):
    from legalprivacy import launcher
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    assert launcher.main(["--url"]) == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("http://127.0.0.1:8765/?t=") and len(out.split("t=")[1]) >= 16
    assert launcher.main(["--url", "--port", "9000"]) == 0
    assert capsys.readouterr().out.startswith("http://127.0.0.1:9000/?t=")
    import pathlib
    sh = (pathlib.Path(__file__).resolve().parent.parent / "start-legalprivacy.sh").read_text()
    assert "--service" in sh and "--uninstall-service" in sh and "systemctl --user" in sh
    assert "ExecStart=$DIR/.venv/bin/python -m legalprivacy --no-browser" in sh and "NoNewPrivileges=true" in sh


def test_health_strongly_recommends_bridges_and_tor_dns_with_one_click_fixes(tmp_path, monkeypatch):
    from legalprivacy.controller import Controller
    monkeypatch.setenv("HOME", str(tmp_path))
    c = Controller(str(tmp_path / "p.yaml"))
    c.apply_config({"transports": {"tor": {"enabled": True}}})
    by = {x["name"]: x for x in c.doctor()}
    br, dn = by["Tor bridges"], by["Tor DNS (ordinary sites)"]
    assert br["status"] == "warn" and "Strongly recommended" in br["detail"] and br["fix"]["config"]["transports"]["tor"]["bridge_mode"] == "obfs4"
    assert dn["status"] == "warn" and dn["fix"]["config"]["transports"]["tor"]["dns_port"] > 0
    assert by["Your own DNS"]["status"] == "info"
    c.apply_config(br["fix"]["config"])
    c.apply_config(dn["fix"]["config"])
    by = {x["name"]: x for x in c.doctor()}
    assert by["Tor bridges"]["status"] == "ok" and by["Tor DNS (ordinary sites)"]["status"] == "ok"
    c.apply_config({"transports": {"tor": {"enabled": False}}})
    off = {x["name"]: x for x in c.doctor()}["Tor"]
    assert off["fix"]["config"]["transports"]["tor"]["enabled"] is True              # without Tor, the fix is to switch it on


def test_health_offers_to_restore_the_recommended_behaviour_switches_and_nothing_else():
    from legalprivacy.controller import Controller
    c = Controller()
    row = next(r for r in c.doctor() if r["name"] == "Recommended settings")
    assert row["status"] == "ok" and "fix" not in row
    c.profile.extras.multi_tab = False
    c.profile.extras.persona = "Ason"
    row = next(r for r in c.doctor() if r["name"] == "Recommended settings")
    assert row["status"] == "warn" and row["fix"]["config"] == {"extras": {"multi_tab": True}}
