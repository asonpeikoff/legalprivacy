"""The Tor lane's real browser: Tor Browser driven like a person, with the plain lane as the fallback."""
import random

from legalprivacy import torlane
from legalprivacy.scheduler import _onion_offline
from legalprivacy.transports import HitResult, Target

URL = "http://" + "a" * 56 + ".onion/"


class FakeDriver:
    """Enough of a Selenium driver for the human behaviour to run against."""

    def __init__(self, fail=None):
        self.fail, self.visited, self.quit_called, self.current_url = fail, [], False, ""
        self.page_source = "<html><title>Hello</title><a href='/x'>x</a></html>"

    def set_page_load_timeout(self, t):
        self.timeout = t

    def get(self, url):
        if self.fail:
            raise Exception(self.fail)
        self.visited.append(url)
        self.current_url = url

    def execute_script(self, script, *a):
        if "innerWidth" in script:
            return [1000, 700]
        if "scrollHeight" in script:
            return 3000
        if "scrollY" in script:
            return 0
        if "responseStatus" in script:
            return 200
        return None

    def quit(self):
        self.quit_called = True


def lane(driver=None, **kw):
    seen = {}

    def factory(env):
        seen["env"] = env
        if isinstance(driver, Exception):
            raise driver
        return driver or FakeDriver()
    t = torlane.TorBrowserTransport(socks="127.0.0.1:19050", control="127.0.0.1:19051", cookie_path="/tmp/c",
                                    scale=lambda: 0.001, rng=random.Random(1), driver_factory=factory, **kw)
    return t, seen


def test_an_onion_visit_goes_through_the_real_browser_with_the_apps_tor_and_reads_like_a_person():
    t, seen = lane()
    res = t.hit(None, Target(url=URL, dwell=0.05, timeout=5.0))
    assert res.status == 200 and "Hello" in res.html and res.detail == "Tor Browser" and res.on_page_s >= 0
    assert t._driver.visited == [URL]
    env = seen["env"]
    assert env["TOR_SOCKS_PORT"] == "19050" and env["TOR_CONTROL_PORT"] == "19051" and env["TOR_SKIP_LAUNCH"] == "1"
    assert "TOR_TRANSPROXY" not in env                                    # it would switch Tor Browser's proxy off
    assert t.is_browser is True and t.nav_log[-1]["url"] == URL


def test_an_offline_onion_site_is_reported_the_way_the_scheduler_already_understands():
    t, _ = lane(FakeDriver(fail="Reached error page: about:neterror?e=onionServices.descMissing&u=http://x.onion/"))
    res = t.hit(None, Target(url=URL, dwell=0.01, timeout=5.0))
    assert res.status is None and "host unreachable" in res.error and _onion_offline(res)
    t, _ = lane(FakeDriver(fail="Timeout loading page after 60000ms"))
    res = t.hit(None, Target(url=URL, dwell=0.01, timeout=5.0))
    assert "timed out" in res.error and _onion_offline(res)


def test_when_the_browser_cannot_start_the_plain_lane_carries_on_and_the_reason_is_logged():
    msgs = []
    t, _ = lane(RuntimeError("geckodriver not found\nmore"), on_event=lambda lvl, m: msgs.append((lvl, m)))
    calls = []
    t.fallback.hit = lambda identity, target: calls.append(target.url) or HitResult(200, "<html>plain</html>")
    assert t.hit(None, Target(url=URL)).html == "<html>plain</html>"
    assert t.hit(None, Target(url=URL)).html == "<html>plain</html>"
    assert calls == [URL, URL] and t._failed == "geckodriver not found"
    assert msgs and msgs[0][0] == "warn" and "geckodriver not found" in msgs[0][1]      # said once, not on every visit
    assert len(msgs) == 1


def test_a_new_identity_closes_the_browser_and_a_moved_tor_restarts_it():
    t, _ = lane()
    t.hit(None, Target(url=URL, dwell=0.01, timeout=5.0))
    first = t._driver
    t.renew_circuits()
    assert first.quit_called and t._driver is None                          # the next visit starts fresh: no cookies or history
    t.hit(None, Target(url=URL, dwell=0.01, timeout=5.0))
    second = t._driver
    t.set_endpoint("127.0.0.1:19050", "127.0.0.1:19051", "/tmp/c")
    assert t._driver is second                                              # same endpoint: left alone
    t.set_endpoint("127.0.0.1:20050", "127.0.0.1:20051", "/tmp/c2")
    assert second.quit_called and t.socks_port == 20050 and t.fallback.socks_port == 20050


def test_a_closed_browser_window_is_replaced_on_the_next_visit():
    t, _ = lane()
    t.hit(None, Target(url=URL, dwell=0.01, timeout=5.0))
    t._driver.fail = "invalid session id"
    res = t.hit(None, Target(url=URL, dwell=0.01, timeout=5.0))
    assert res.status is None and t._driver is None


def test_the_lane_is_only_used_when_everything_it_needs_is_there(tmp_path, monkeypatch):
    from legalprivacy.controller import Controller
    monkeypatch.setenv("HOME", str(tmp_path))
    c = Controller(str(tmp_path / "p.yaml"))
    c.apply_config({"transports": {"tor": {"enabled": True}}})
    monkeypatch.setattr(torlane, "support", lambda: (False, "Tor Browser isn't installed yet"))
    assert c._tor_lane_transport(__import__("threading").Event()) is None   # plain lane, with the reason in the log
    monkeypatch.setattr(torlane, "support", lambda: (True, "/x/firefox"))
    assert isinstance(c._tor_lane_transport(__import__("threading").Event()), torlane.TorBrowserTransport)
    c.apply_config({"transports": {"tor": {"onion_browser": False}}})
    assert c._tor_lane_transport(__import__("threading").Event()) is None   # switched off
