from pathlib import Path
import pytest

from legalprivacy.config import ConfigError, Profile
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
    pub = generate_torrc(RelaySpec(mode="bridge", nickname="b"))
    priv = generate_torrc(RelaySpec(mode="bridge", nickname="b", private=True))
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
    tm = TorManager(EventLog(), exclude_nodes=["a" * 40, "{ru}"])
    tm.binary = str(tmp_path / "bundle" / "tor" / "tor")
    tm.socks_host, tm.socks_port, tm.control_host, tm.control_port = "127.0.0.1", 19050, "127.0.0.1", 19051
    tm.cookie_path = str(tmp_path / "cookie")
    text = tm._write_torrc(tmp_path / "data").read_text()
    assert "ExcludeNodes $" + "a" * 40 + ",{ru}" in text and "StrictNodes 1" in text


def test_default_avoid_list_is_the_us_and_there_is_no_governmental_name_filter():
    import legalprivacy
    from legalprivacy.config import BANNED_RELAYS, Profile
    tor = Profile(name="d").transports["tor"]
    assert tor.exclude_nodes == ["{us}"]
    assert not hasattr(tor, "exclude_gov_names")                    # guessing from names was removed
    assert "5C62A7A4BFD24D61034499857C4B5E437CD2361F" in BANNED_RELAYS
    assert not (Path(legalprivacy.__file__).parent / "relayfilter.py").exists()


def test_dns_defaults_lean_on_normal_dns_and_do_more_lookups():
    from legalprivacy.config import Profile
    p = Profile(name="d")
    assert p.dns.mode == "mix" and p.dns.encrypted and p.dns.system_share == 0.85
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
    assert Profile(name="d").extras.persona == "Default mix" and abs(sum(PERSONAS["Default mix"].values()) - 1) < 1e-9
    assert set(PERSONAS["Default mix"]) <= set(CATEGORIES)
    p = Persona(_r.Random(3), "Default mix")
    c = Counter(p.site() for _ in range(4000))
    assert len(c) > 300                                           # many different sites ...
    assert c.most_common(1)[0][1] < 0.03 * 4000                   # ... and no single one dominates
    objectivist = set(CATEGORIES["Objectivism"]["sites"])
    share = sum(n for s, n in c.items() if s in objectivist) / 4000
    assert 0.12 < share < 0.32                                    # a main part (about a fifth), not all of it
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
    assert c2.profile.extras.persona == "Default mix"
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
    c.apply_config({"transports": {"tor": {"enabled": True, "bridge_mode": "off"}}})      # the old defaults
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


def test_old_defaults_move_to_the_new_ones_once():
    from legalprivacy.config import apply_overrides, Profile
    from legalprivacy.controller import move_old_defaults
    p = apply_overrides(Profile(name="old"), {
        "extras": {"persona": "", "persona_share": 0.9, "interest_list": ["Data science", "News"]},
        "transports": {"clearnet": {"browser_engine": "auto"}},
        "identity": {"ua_mode": "pin", "ua_pin": "own"}, "traffic": {"mobile_share": 0.55},
        "engines": {"search": {"budget_per_day": 120}, "crawl": {"budget_per_day": 40}, "dns": {"budget_per_day": 200}}})
    moved = move_old_defaults(p)
    assert p.extras.persona == "Default mix" and p.extras.persona_share == 0.8
    assert {"Objectivism", "Authors and readers", "Web 2.0"} <= set(p.extras.interest_list)
    assert p.transports["clearnet"].browser_engine == "mine"
    assert p.identity.ua_mode == "mix" and p.identity.ua_own_share == 0.85
    assert p.engines["dns"].budget_per_day == 480 and p.traffic.mobile_share == 0.10 and len(moved) == 7
    assert apply_overrides(Profile(name="x"), {"extras": {"persona": "Ason"}}).extras.persona == "Default mix"


def test_background_amounts_sit_outside_the_activity_mix():
    from legalprivacy import gui_fields as F
    from legalprivacy.config import Profile
    v = F.profile_values(Profile(name="d"), {})
    assert "dns" not in v["engines_mix"] and v["dns_amount"] == "3"
    out = F.build_config_payload({"engines_mix": {"search": 75, "crawl": 25}, "dns_amount": "5", "pkg_amount": "0"})
    assert out["engines"]["dns"] == {"enabled": True, "budget_per_day": 5000}
    assert out["engines"]["packages"]["enabled"] is False


def test_health_offers_to_restore_the_recommended_behaviour_switches_and_nothing_else():
    from legalprivacy.controller import Controller
    c = Controller()
    row = next(r for r in c.doctor() if r["name"] == "Recommended settings")
    assert row["status"] == "ok" and "fix" not in row
    c.profile.extras.multi_tab = False
    c.profile.extras.persona = "Data scientist"           # a persona choice is not a behaviour switch
    row = next(r for r in c.doctor() if r["name"] == "Recommended settings")
    assert row["status"] == "warn" and row["fix"]["config"] == {"extras": {"multi_tab": True}}


def test_old_defaults_move_to_tor_on_with_obfs4_once():
    from legalprivacy.controller import move_old_defaults_v5
    p = Profile(name="old")
    tor = p.transports["tor"]
    tor.enabled, tor.bridge_mode = False, "off"
    assert move_old_defaults_v5(p) == ["Tor: on", "Tor bridges: built-in obfs4"]
    assert tor.enabled is True and tor.bridge_mode == "obfs4"
    tor.bridge_mode = "snowflake"                       # a bridge you chose is left alone
    assert move_old_defaults_v5(p) == [] and tor.bridge_mode == "snowflake"


def test_dns_on_the_old_secure_only_default_moves_to_mix_once():
    from legalprivacy.config import Profile
    from legalprivacy.controller import move_old_defaults_v6
    p = Profile(name="d")
    p.dns.mode = "secure"
    assert move_old_defaults_v6(p) == ["DNS: mix, 85% on your normal DNS"] and p.dns.mode == "mix"
    p.dns.mode = "system"                                        # a choice someone made stays
    assert move_old_defaults_v6(p) == [] and p.dns.mode == "system"
