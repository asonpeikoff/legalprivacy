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
