"""Traffic mix patterns, phone emulation defaults, bookmarks import, My List weights."""
import json
import os
import random
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from legalprivacy.browser import BrowserTransport  # noqa: E402
from legalprivacy.config import ConfigError, Profile, apply_overrides  # noqa: E402
from legalprivacy.domains import DomainPool  # noqa: E402
from legalprivacy.history import _chromium_bookmark_urls, sites_from_bookmarks_file  # noqa: E402
from legalprivacy.identity import make_identity  # noqa: E402
from legalprivacy.rate import RatePlanner  # noqa: E402
from legalprivacy.scheduler import Runner, build_lanes  # noqa: E402
from legalprivacy.transports import ClearnetTransport, HitResult  # noqa: E402
from legalprivacy.useragents import sample_entry  # noqa: E402


# ── phones ──────────────────────────────────────────────────────────────────
def test_default_phone_is_iphone_13_with_safari_and_about_a_tenth_of_identities():
    rng = random.Random(4)
    es = [sample_entry(rng) for _ in range(3000)]
    phones = [e for e in es if e["mobile"]]
    assert 0.07 < len(phones) / len(es) < 0.13
    assert all(e["device"] == "iPhone 13" and "iPhone" in e["ua"] and not e["chromium"] for e in phones)
    android = [sample_entry(rng, 1.0, "Pixel 7") for _ in range(50)]
    assert all(e["device"] == "Pixel 7" and "Android" in e["ua"] for e in android)
    mixed = {sample_entry(rng, 1.0, "mix")["device"] for _ in range(400)}
    assert "iPhone 13" in mixed and len(mixed) >= 3


class _CDP:
    def __init__(self, log): self.log = log
    def send(self, method, params): self.log.append((method, params))


class _Page:
    def __init__(self): self.closed, self.handlers, self.viewport = False, {}, None
    def on(self, ev, fn): self.handlers.setdefault(ev, []).append(fn)
    def close(self):
        self.closed = True
        for fn in self.handlers.get("close", []):
            fn(self)
    def set_viewport_size(self, vp): self.viewport = vp


class _Ctx:
    def __init__(self, kw, log): self.kw, self.log, self.pages, self.handlers, self.scripts = kw, log, [], {}, []
    def add_init_script(self, js): self.scripts.append(js)
    def on(self, ev, fn): self.handlers.setdefault(ev, []).append(fn)
    def route(self, *a): pass
    def new_page(self):
        pg = _Page()
        self.pages.append(pg)
        for fn in self.handlers.get("page", []):       # Playwright fires "page" before new_page returns
            fn(pg)
        return pg
    def site_opens_popup(self):
        pg = _Page()
        for fn in self.handlers.get("page", []):
            fn(pg)
        return pg
    def new_cdp_session(self, page): return _CDP(self.log)
    def close(self): pass


class _Browser:
    def __init__(self): self.contexts, self.cdp, self.ctxs = [], [], []
    def new_context(self, **kw):
        self.contexts.append(kw)
        self.ctxs.append(_Ctx(kw, self.cdp))
        return self.ctxs[-1]


def _transport(headless=True, exe="/usr/bin/google-chrome"):
    t = BrowserTransport(headless=headless, executable=exe)
    t._browser, t._major = _Browser(), "158"
    return t


def test_iphone_identity_gets_iphone_screen_touch_and_a_clean_safari_override():
    ident = make_identity(random.Random(1), 7, ["w"], entry=sample_entry(random.Random(9), 1.0, "iPhone 13"))
    t = _transport()
    t._session(ident)
    ctx = t._browser.contexts[0]
    assert ctx["viewport"] == {"width": 390, "height": 664} and ctx["device_scale_factor"] == 3.0
    assert ctx["is_mobile"] and ctx["has_touch"] and "user_agent" not in ctx    # no leaky Playwright override
    method, params = t._browser.cdp[0]
    assert params["platform"] == "iPhone" and "userAgentMetadata" not in params   # Safari: no client hints
    assert params["userAgent"] == ident.user_agent


def _desktop_identity(seed=2, n=3):
    for i in range(200):
        e = sample_entry(random.Random(seed + i), 0.0)
        if e["chromium"] and "Chrome/" in e["ua"]:
            return make_identity(random.Random(1), n, ["w"], entry=e)
    raise AssertionError("no chromium desktop entry")


def test_every_tab_uses_the_identitys_own_user_agent_hidden_or_visible():
    ident = _desktop_identity()
    for headless in (True, False):
        t = _transport(headless=headless)
        t._session(ident)
        _, params = t._browser.cdp[0]
        assert params["userAgent"] == ident.user_agent and "Headless" not in params["userAgent"]
        major = ident.user_agent.split("Chrome/")[1].split(".")[0]
        assert {"brand": "Chromium", "version": major} in params["userAgentMetadata"]["brands"]


def test_firefox_or_safari_user_agents_send_no_client_hints():
    e = dict(sample_entry(random.Random(2), 0.0), ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) "
             "Gecko/20100101 Firefox/133.0", chromium=False, platform="Windows")
    t = _transport()
    t._session(make_identity(random.Random(1), 4, ["w"], entry=e))
    _, params = t._browser.cdp[0]
    assert "Firefox/133.0" in params["userAgent"] and "userAgentMetadata" not in params


def test_identities_are_tabs_in_one_window_and_popups_are_closed():
    t = _transport(headless=False)
    a, b = _desktop_identity(2, 3), _desktop_identity(40, 5)
    t._session(a)
    t._session(b)
    assert len(t._browser.ctxs) == 1 and len(t._browser.ctxs[0].pages) == 2     # two tabs, one window
    assert not any(pg.closed for pg in t._browser.ctxs[0].pages)
    assert "window.open" in t._browser.ctxs[0].scripts[0]
    popup = t._browser.ctxs[0].site_opens_popup()
    assert popup.closed                                                          # never runs with another UA
    t._session(_desktop_identity(80, 9))                                         # a third: oldest tab closes
    assert len(t._browser.ctxs) == 1 and t._browser.ctxs[0].pages[0].closed


# ── traffic mix ─────────────────────────────────────────────────────────────
def _runner(pattern, plain=0.0):
    p = Profile(name="t")
    apply_overrides(p, {"traffic": {"pattern": pattern, "browser": 70, "plain": plain, "onion": 0},
                        "rate": {"mode": "steady", "level": 5}})
    lanes = build_lanes(p, ["w"], clearnet_transport=ClearnetTransport(), plain_transport=ClearnetTransport() if plain else None)
    return Runner(profile=p, lanes=lanes, wordlist=["w"], sleep_fn=lambda s: None,
                  probe_fn=lambda *a: HitResult(200, ""), rate=RatePlanner(random.Random(2), p.rate), mix=True)


def _lane_share(r, lane):
    return sum(v for (ln, _), v in r.engine_shares().items() if ln == lane)


def test_blend_keeps_the_lane_shares_and_plain_lane_has_no_dns():
    r = _runner("blend", plain=30)
    r.plan_hour(12)
    assert abs(_lane_share(r, "clearnet-plain") - 0.30) < 0.01
    assert "dns" not in next(l for l in r.lanes if l.name == "clearnet-plain").engines


def test_drift_moves_shares_and_alternate_runs_one_kind_at_a_time():
    r = _runner("drift", plain=30)
    seen = []
    for h in range(24):
        r.plan_hour(h)
        seen.append(_lane_share(r, "clearnet-plain"))
    assert max(seen) - min(seen) > 0.1                     # it wanders
    a = _runner("alternate", plain=30)
    dominant = []
    for h in range(24):
        a.plan_hour(h)
        dominant.append(max(_lane_share(a, "clearnet"), _lane_share(a, "clearnet-plain")))
    assert min(dominant) > 0.85                            # one lane at a time


def test_bad_traffic_settings_are_rejected():
    for bad in ({"pattern": "zigzag"}, {"device": "Nokia 3310"}, {"mobile_share": 2}):
        try:
            apply_overrides(Profile(name="t"), {"traffic": bad})
            raise AssertionError(f"accepted {bad}")
        except ConfigError:
            pass


# ── bookmarks & weights ─────────────────────────────────────────────────────
def test_bookmarks_from_chrome_json_and_an_export_file():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "Bookmarks")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"roots": {"bookmark_bar": {"children": [
            {"type": "url", "url": "https://www.example.com/a"},
            {"type": "folder", "children": [{"type": "url", "url": "https://news.example.org/"}]}]}}}, fh)
    assert sorted(_chromium_bookmark_urls(path)) == ["https://news.example.org/", "https://www.example.com/a"]
    html = '<DL><DT><A HREF="https://www.example.com/x">Ex</A><DT><A HREF="https://pornhub.com/">no</A></DL>'
    res = sites_from_bookmarks_file(html)
    assert res["sites"] == [["example.com", 1]] and res["filtered"] == 1


def test_firefox_bookmarks_query_matches_schema():
    d = tempfile.mkdtemp()
    path = os.path.join(d, "places.sqlite")
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT)")
    con.execute("CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER)")
    con.execute("INSERT INTO moz_places VALUES (1, 'https://example.net/')")
    con.execute("INSERT INTO moz_bookmarks (type, fk) VALUES (1, 1)")
    con.commit()
    con.close()
    from legalprivacy.history import _read_copy
    rows = _read_copy(path, "SELECT p.url FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk WHERE b.type = 1", ())
    assert rows == [("https://example.net/",)]


def test_how_often_weights_steer_my_list():
    mine = ["often-example.com", "rare-example.org"]
    pool = DomainPool(random.Random(3), None, my_sites=mine, random_share=0.0,
                      my_weights={"often-example.com": 10, "rare-example.org": 1})
    picks = [pool._mine() for _ in range(2000)]
    assert picks.count("often-example.com") > 7 * picks.count("rare-example.org")


def test_engine_matches_your_browser_and_falls_back_to_chromium():
    import tempfile
    from unittest import mock
    os.environ["LEGALPRIVACY_HOME"] = tempfile.mkdtemp()
    from legalprivacy.controller import Controller
    c = Controller()
    c.apply_config({"identity": {"own_ua": "Mozilla/5.0 (X11; Linux x86_64; rv:160.0) Gecko/20100101 Firefox/160.0"},
                    "transports": {"clearnet": {"browser_engine": "auto"}}})
    with mock.patch("legalprivacy.browser.find_playwright_firefox", return_value="/x/firefox"):
        assert c._browser_engine() == "firefox"
    with mock.patch("legalprivacy.browser.find_playwright_firefox", return_value=None):
        assert c._browser_engine() == "chromium"                 # not installed: fall back
    c.apply_config({"transports": {"clearnet": {"browser_engine": "chromium"}}})
    with mock.patch("legalprivacy.browser.find_playwright_firefox", return_value="/x/firefox"):
        assert c._browser_engine() == "chromium"


def test_firefox_engine_runs_phone_identities_as_desktop_without_devtools():
    ident = make_identity(random.Random(1), 7, ["w"], entry=sample_entry(random.Random(9), 1.0, "iPhone 13"))
    t = _transport()
    t.engine = "firefox"
    t._session(ident)
    ctx = t._browser.contexts[0]
    assert "is_mobile" not in ctx and t._browser.cdp == [] and ctx["user_agent"] == ident.user_agent


def test_a_page_cannot_send_the_tab_to_another_site_on_its_own():
    from legalprivacy.browser import _site
    assert _site("news.example.co.uk") == "example.co.uk" and _site("www.google.com") == "google.com"

    class CDP:
        def __init__(self): self.sent, self.handlers = [], {}
        def on(self, ev, fn): self.handlers[ev] = fn
        def send(self, method, params=None):
            self.sent.append((method, params))
            return {"frameTree": {"frame": {"id": "MAIN"}}} if method == "Page.getFrameTree" else {}

    class Pg:
        url = "https://www.example.com/article"

    t = _transport()
    page, cdp = Pg(), CDP()
    t._tabs[1] = page
    t._guard_tab(page, cdp)
    paused = cdp.handlers["Fetch.requestPaused"]

    def nav(url, frame="MAIN"):
        cdp.sent.clear()
        paused({"requestId": "r", "frameId": frame, "request": {"url": url}})
        return cdp.sent[0][0]
    assert nav("https://blog.example.com/next") == "Fetch.continueRequest"          # same site: fine
    assert nav("https://ads.tracker.net/click") == "Fetch.fulfillRequest"           # another site: blocked
    assert nav("https://ads.tracker.net/frame", frame="AD") == "Fetch.continueRequest"   # an ad's own frame
    t._doing(page, "noise: open (page)", "https://other.org/")
    assert nav("https://cdn.redirect.io/x") == "Fetch.continueRequest"              # while the noise is opening
    t._doing(page, None)
    assert nav("https://other.org/landing") == "Fetch.continueRequest"              # where it was sent
    assert t.blocked_navs == 1 and t.nav_log[-1]["why"].startswith("blocked")


def test_browser_mix_is_the_default_and_routes_by_identity():
    from types import SimpleNamespace as NS
    from legalprivacy.browser import MixedBrowserTransport
    from legalprivacy.config import Profile
    p = Profile(name="d")
    assert p.transports["clearnet"].browser_engine == "mine" and p.identity.ua_mode == "mix"
    chrome, ff = NS(dimmed=False, closed=False, name="c"), NS(dimmed=False, closed=False, name="f")
    chrome.hit = lambda i, t: "chromium"
    ff.hit = lambda i, t: "firefox"
    chrome.close = ff.close = lambda: None
    m = MixedBrowserTransport(chrome, ff)
    firefox_id = NS(chromium=False, user_agent="Mozilla/5.0 (X11; rv:140.0) Gecko/20100101 Firefox/140.0")
    chrome_id = NS(chromium=True, user_agent="Mozilla/5.0 Chrome/140")
    safari_id = NS(chromium=False, user_agent="Mozilla/5.0 (iPhone) Safari/604.1")
    assert (m.hit(firefox_id, None), m.hit(chrome_id, None), m.hit(safari_id, None)) == ("firefox", "chromium", "chromium")
    assert MixedBrowserTransport(chrome, None).hit(firefox_id, None) == "chromium"      # no Firefox installed
    m.dimmed = True
    assert chrome.dimmed and ff.dimmed
