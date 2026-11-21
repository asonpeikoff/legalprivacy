"""Turbo mode: a second, separate real-browser lane layered on top of the normal noise."""
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

from legalprivacy.config import ConfigError, ExtrasConfig  # noqa: E402
from legalprivacy.controller import Controller  # noqa: E402
from legalprivacy.transports import HitResult  # noqa: E402


class FakeBrowser:
    is_browser = True
    scale = None

    def __init__(self):
        self.calls, self.thread_ids = 0, set()

    def hit(self, identity, target):
        self.calls += 1
        self.thread_ids.add(threading.get_ident())
        return HitResult(200, "<html></html>")

    def close(self):
        pass


def _ctl():
    c = Controller(os.path.join(tempfile.mkdtemp(), "config.yaml"))
    c.apply_config({"transports": {"clearnet": {"enabled": True, "browser": "off"}, "tor": {"enabled": False}},
                    "extras": {"turbo_per_min": 20}})
    return c


def test_turbo_is_off_by_default_and_validated():
    assert ExtrasConfig().turbo is False and ExtrasConfig().turbo_per_min == 6
    for bad in (0, 21):
        try:
            ExtrasConfig(turbo_per_min=bad).validate()
        except ConfigError:
            continue
        raise AssertionError(bad)


def test_turbo_needs_the_real_browser_and_says_so():
    c = _ctl()
    c.start()
    try:
        st = c.set_turbo(True)
        assert st["on"] is True and st["running"] is False and st["needs_browser"] is True
        assert any("needs the real browser" in e["message"] for e in c.log.since(0))
    finally:
        c.stop()


def test_turbo_runs_separately_shares_one_activity_list_and_stops_with_the_noise():
    c = _ctl()
    fake = FakeBrowser()
    c.browser_info = lambda: {"active": True, "available": True, "detail": "x", "setting": "on", "visible": False}
    c._clearnet_transport = lambda stop: _Wrap(fake)
    c.start()
    try:
        c.set_turbo(True, 20)
        for _ in range(100):
            if c.turbo_state()["pages"] >= 1:
                break
            time.sleep(0.05)
        t = c.turbo_state()
        assert t["running"] and t["pages"] >= 1 and t["per_min"] == 20
        hits = c.hits(0)
        assert any(h["lane"] == "turbo" for h in hits)
        seqs = [h["seq"] for h in hits]
        assert len(seqs) == len(set(seqs))                          # one numbering across both runners
        c.set_turbo(False)
        assert c.turbo_state()["running"] is False
    finally:
        c.stop()
    assert c.turbo_state()["running"] is False


def test_turbo_starts_with_the_noise_when_it_is_on_in_settings():
    c = _ctl()
    c.browser_info = lambda: {"active": True, "available": True, "detail": "x", "setting": "on", "visible": False}
    c._clearnet_transport = lambda stop: _Wrap(FakeBrowser())
    c.apply_config({"extras": {"turbo": True}})
    c.start()
    try:
        assert c.turbo_state()["running"] is True
    finally:
        c.stop()
    assert c.turbo_state()["running"] is False


class _Wrap:
    """A minimal transport around FakeBrowser for the Lane."""
    is_browser = True
    name = "clearnet"
    dimmed = False

    def __init__(self, fake):
        self.fake, self.scale = fake, None

    def hit(self, identity, target):
        return self.fake.hit(identity, target)

    def close(self):
        pass
