"""After an update the app asks once: keep the settings, or start from the new defaults. History and own data stay."""
import threading
from pathlib import Path

import yaml

from legalprivacy import __version__, controller as controller_mod, webui
from legalprivacy.controller import Controller


def _old_install(tmp_path, monkeypatch, version="2.0.0"):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    c = Controller(str(path))
    c.apply_config({"extras": {"duck_chat": False, "typos": True},
                    "mylist": {"sites": ["example.org"], "weights": {"example.org": 7}},
                    "transports": {"tor": {"bridges": ["obfs4 198.51.100.7:443 " + "A" * 40 + " cert=x iat-mode=0"]}}})
    c.app["ml_history"] = [{"at": 1, "score": 0.5}]
    c.app["autostart"] = False
    c._save()
    d = yaml.safe_load(path.read_text())
    d["app"]["settings_version"] = version
    path.write_text(yaml.safe_dump(d))
    return path


def test_a_fresh_install_asks_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    c = Controller(str(tmp_path / "config.yaml"))
    assert c.upgrade_pending is None and c.state()["upgrade"] is None
    c._save()
    assert Controller(str(tmp_path / "config.yaml")).upgrade_pending is None


def test_an_update_asks_and_keeping_changes_nothing(tmp_path, monkeypatch):
    path = _old_install(tmp_path, monkeypatch)
    c = Controller(str(path))
    assert c.upgrade_pending == {"from": "2.0.0", "to": __version__} and c.state()["upgrade"]["from"] == "2.0.0"
    c._save()                                                         # an autosave meanwhile does not answer it
    assert Controller(str(path)).upgrade_pending is not None
    r = c.resolve_upgrade(True)
    assert r["kept"] and c.profile.extras.typos is True and c.profile.extras.duck_chat is False
    assert Controller(str(path)).upgrade_pending is None              # asked once


def test_starting_from_the_defaults_keeps_history_and_your_own_data_and_backs_up_the_rest(tmp_path, monkeypatch):
    path = _old_install(tmp_path, monkeypatch)
    c = Controller(str(path))
    nick = c.profile.relay.nickname
    r = c.resolve_upgrade(False)
    p = c.profile
    assert p.extras.typos is False and p.extras.duck_chat is True                   # options: defaults again
    assert p.mylist.sites == ["example.org"] and p.mylist.weights == {"example.org": 7}
    assert p.transports["tor"].bridges and p.relay.nickname == nick
    assert c.app["ml_history"] == [{"at": 1, "score": 0.5}]                         # history stays
    backup = Path(r["backup"])
    assert backup.exists() and yaml.safe_load(backup.read_text())["profile"]["extras"]["typos"] is True
    again = Controller(str(path))
    assert again.upgrade_pending is None and again.profile.extras.typos is False


def test_with_no_answer_the_settings_are_kept_and_everything_starts(tmp_path, monkeypatch):
    path = _old_install(tmp_path, monkeypatch)
    c = Controller(str(path))
    started = threading.Event()
    monkeypatch.setattr(webui, "UPGRADE_ANSWER_WAIT", 0.05)
    monkeypatch.setattr(webui, "_start_rest", lambda ctl: started.set())
    monkeypatch.setattr(c, "_start_feed_timer", lambda: None)
    c.app["observe"] = False
    webui.start_services(c)
    assert started.wait(5) and c.upgrade_pending is None and c.profile.extras.typos is True


def test_an_answer_releases_what_was_held_back(tmp_path, monkeypatch):
    path = _old_install(tmp_path, monkeypatch)
    c = Controller(str(path))
    calls = []
    c._deferred_start = lambda: calls.append(1)
    c.resolve_upgrade(False)
    c.resolve_upgrade(True)                                  # a late second answer (the timer) does nothing
    assert calls == [1]


def test_switching_duck_chat_off_now_sticks_across_restarts(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    c = Controller(str(path))
    c.apply_config({"extras": {"duck_chat": False}})
    assert "migrated_defaults_v4" in controller_mod.APP_DEFAULTS
    assert Controller(str(path)).profile.extras.duck_chat is False
