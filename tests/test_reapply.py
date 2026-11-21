import tempfile
import os
from legalprivacy.controller import Controller


def test_reapply_keeps_log_and_running_state():
    d = tempfile.mkdtemp()
    c = Controller(profile_path=os.path.join(d, "p.json"))
    c.apply_config({"transports": {"clearnet": {"enabled": True, "browser": "off"}}})
    c.start()
    try:
        c.log.info("t", "marker")
        c.apply_config({"traffic": {"mobile_share": 0.3}})
        c.reapply()
        assert c.running
        assert any(e["message"] == "marker" for e in c.log.since(0))     # the log survives an apply
        assert c.app.get("clear_logs_on_restart", True) is True       # setting restored
    finally:
        c.stop()


def test_reapply_when_stopped_is_a_noop():
    c = Controller(profile_path=os.path.join(tempfile.mkdtemp(), "p.json"))
    c.reapply()
    assert not c.running


def test_start_reason_is_logged_and_repeated_starts_are_called_out():
    d = tempfile.mkdtemp()
    c = Controller(profile_path=os.path.join(d, "p.json"))
    c.apply_config({"transports": {"clearnet": {"enabled": True, "browser": "off"}}})
    c.start(reason="autostart on launch")
    try:
        assert any("autostart on launch" in e["message"] for e in c.log.since(0))
        for _ in range(5):
            c.reapply()
        assert any("started" in e["message"] and "times in the last minute" in e["message"] for e in c.log.since(0))
    finally:
        c.stop()


def test_apply_is_verified_and_logged_with_what_changed():
    d = tempfile.mkdtemp()
    c = Controller(profile_path=os.path.join(d, "p.json"))
    c.apply_config({"transports": {"clearnet": {"enabled": True, "browser": "off"}}})
    c.start()
    try:
        assert c.settings_status()["in_effect"] is True
        c.apply_config({"rate": {"level": 7}})
        assert c.settings_status()["in_effect"] is False          # saved but not yet running
        c.reapply()
        st = c.settings_status()
        assert st["in_effect"] is True and st["applied_at"]
        msgs = [e["message"] for e in c.log.since(0)]
        assert any("Applied live and verified" in m and "level" in m and "→ 7" in m for m in msgs)
    finally:
        c.stop()


def test_private_settings_are_not_printed_in_the_log():
    c = Controller(profile_path=os.path.join(tempfile.mkdtemp(), "p.json"))
    diff = c._settings_diff({"a": {"bridges": ["x"], "level": 1}}, {"a": {"bridges": ["secret-bridge"], "level": 2}})
    assert "a.bridges changed" in diff and not any("secret-bridge" in x for x in diff) and "a.level: 1 → 2" in diff
