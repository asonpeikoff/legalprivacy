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
