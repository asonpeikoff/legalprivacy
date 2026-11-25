"""Optional signed-in accounts: everything except a real sign-in/visit (browser launches are stubbed)."""
import json
import math
import os
import random
import stat
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

from legalprivacy import accounts as A  # noqa: E402
from legalprivacy.config import ConfigError, Profile, apply_overrides, profile_to_dict  # noqa: E402
from legalprivacy.controller import Controller  # noqa: E402
from legalprivacy.events import EventLog  # noqa: E402
from legalprivacy.webui import UIServer  # noqa: E402


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    return tmp_path


def good_state(provider="google", expires=None):
    name = A.PROVIDERS[provider]["auth_cookies"][0]
    dom = ".google.com" if provider == "google" else ".login.live.com"
    return {"cookies": [{"name": name, "value": "x", "domain": dom, "path": "/",
                         "expires": expires if expires is not None else time.time() + 86400}], "origins": []}


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def make(cfg=None, running=True, visit=None, proxy=None, tor=(), clock=None, seed=1):
    cfg = cfg if cfg is not None else {"google": {"enabled": True, "per_hour": 3, "per_day": 5, "on_challenge": "pause"},
                                       "microsoft": {"enabled": True, "per_hour": 3, "per_day": 5}}
    return A.AccountsManager(EventLog(), config=lambda: cfg, running=lambda: running, proxy=lambda: proxy,
                             tor_addrs=lambda: tor, visit_impl=visit, has_display_fn=lambda: True,
                             browser_ok=lambda: (True, "x"), firefox_import=lambda p: None,
                             rng=random.Random(seed), now=clock or time.time)


def sign_in(m, provider="google", state=None):
    m._signin_impl = lambda p, cancel, progress: state if state is not None else good_state(p)
    m.begin_signin(provider)
    m.wait_signin(provider)
    assert m._signin[provider]["state"] == "done", m._signin[provider]


OK_PAGE = A.VisitResult(status=200, url="https://mail.google.com/mail/u/0/#inbox", title="Inbox", text="Compose")


# ── config ─────────────────────────────────────────────────────────────────────────────────
def test_config_defaults_off_and_validation():
    p = Profile(name="t")
    assert all(not a.enabled and a.per_hour == 3 and a.on_challenge == "pause" for a in p.accounts.values())
    apply_overrides(p, {"accounts": {"google": {"enabled": True, "per_hour": 10, "per_day": 50}}})
    assert p.accounts["google"].enabled and p.accounts["google"].per_hour == 10
    assert not p.accounts["microsoft"].enabled
    for bad in ({"google": {"per_hour": 0}}, {"google": {"per_hour": 11}}, {"google": {"per_hour": 2.5}},
                {"google": {"per_hour": True}}, {"google": {"per_day": 0}}, {"google": {"enabled": "yes"}},
                {"google": {"on_challenge": "ignore"}}, {"yahoo": {"enabled": True}}, "nope"):
        with pytest.raises(ConfigError):
            apply_overrides(Profile(name="t"), {"accounts": bad})
    assert profile_to_dict(p)["profile"]["accounts"]["google"]["per_hour"] == 10


def test_old_profiles_without_accounts_still_load():
    p = apply_overrides(Profile(name="t"), {"profile": {"name": "old", "engines": {}}})
    assert set(p.accounts) == {"google", "microsoft"} and not p.accounts["google"].enabled


# ── allowlist / blocklist ───────────────────────────────────────────────────────────────────
def test_url_allowlist():
    ok = [("google", "https://www.google.com/search?q=cats"), ("google", "https://mail.google.com/mail/u/0/#inbox"),
          ("google", "https://www.youtube.com/"), ("microsoft", "https://outlook.live.com/mail/0/inbox"),
          ("microsoft", "https://outlook.office.com/calendar/view/week"), ("microsoft", "https://www.bing.com/search?q=a"),
          ("microsoft", "https://www.microsoft.com/en-us/")]
    bad = [("google", "http://www.google.com/search?q=a"), ("google", "https://mail.google.com/"),
           ("google", "https://myaccount.google.com/"), ("google", "https://accounts.google.com/signout"),
           ("google", "https://evil.example/mail/"), ("google", "https://mail.google.com.evil.example/mail/"),
           ("microsoft", "https://outlook.live.com/owa/"), ("microsoft", "https://account.microsoft.com/"),
           ("microsoft", "https://www.google.com/search?q=a"), ("nobody", "https://www.google.com/search")]
    assert all(A.url_allowed(p, u) for p, u in ok)
    assert not any(A.url_allowed(p, u) for p, u in bad)
    assert A.nav_allowed("google", "https://accounts.google.com/v3/signin/identifier")
    assert not A.nav_allowed("google", "https://example.com/")


def test_every_planned_visit_is_allowed():
    rng = random.Random(3)
    for prov in A.PROVIDER_IDS:
        for host in (None, "outlook.office.com", "outlook.live.com"):
            for _ in range(300):
                assert A.url_allowed(prov, A.plan_visit(prov, rng, mail_host=host))
    # work accounts use the office.com mailbox, personal ones live.com
    urls = {A.plan_visit("microsoft", rng, mail_host="outlook.office.com") for _ in range(300)}
    assert not any("outlook.live.com" in u for u in urls) and any("outlook.office.com" in u for u in urls)


def test_click_blocklist():
    for t in ("Send", "Delete", "Archive", "Mark as read", "Reply all", "Forward", "Compose", "New message", "Accept",
              "Decline", "Sign out", "Settings", "Move to Inbox", "Label as", "Report spam"):
        assert not A.click_allowed(text=t), t
    assert not A.click_allowed(text="Home", href="https://mail.google.com/mail/?logout")
    assert not A.click_allowed(label="Delete conversation")
    assert A.click_allowed(text="Inbox", href="https://mail.google.com/mail/u/0/#inbox")
    assert "stopImmediatePropagation" in A.READONLY_JS and "'click'" in A.READONLY_JS


def test_classify_page():
    c = A.classify_page
    assert c("google", "https://mail.google.com/mail/u/0/#inbox", "Inbox", "Compose", 200) == "ok"
    assert c("google", "https://www.google.com/search?q=a", "a", "", 429) == "rate_limited"
    assert c("google", "https://www.google.com/sorry/index", "", "", 200) == "challenge"
    assert c("google", "https://www.google.com/search?q=a", "", "Our systems have detected unusual traffic", 200) == "challenge"
    assert c("microsoft", "https://outlook.live.com/mail/", "Outlook", "Verify it’s you", 200) == "challenge"
    assert c("google", "https://accounts.google.com/v3/signin", "Sign in", "", 200) == "signin"
    assert c("microsoft", "https://login.live.com/login.srf", "Sign in", "", 200) == "signin"
    assert c("google", "https://workspace.google.com/products/gmail/", "Gmail", "", 200) == "signed_out"
    assert c("google", "https://mail.google.com/mail/", "", "", 500) == "blocked"


# ── saved sessions ──────────────────────────────────────────────────────────────────────────
def test_signin_saves_private_file_and_forget_deletes_it():
    m = make()
    assert m.status()["accounts"]["google"]["state"] == "signed_out"
    sign_in(m)
    f = A._state_file("google")
    assert f.exists() and stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(A._meta_file("google").stat().st_mode) == 0o600
    assert stat.S_IMODE(f.parent.stat().st_mode) == 0o700
    st = m.status()["accounts"]["google"]
    assert st["state"] == "signed_in" and st["saved_at"] and st["signin"]["state"] == "done"
    assert "password" not in f.read_text().lower()
    m.forget("google")
    assert not f.exists() and not A._meta_file("google").exists()
    assert m.status()["accounts"]["google"]["state"] == "signed_out"


def test_window_closed_before_signing_in_saves_nothing():
    m = make()
    m._signin_impl = lambda p, cancel, progress: {"cookies": [], "origins": []}
    m.begin_signin("google")
    m.wait_signin("google")
    assert m._signin["google"]["state"] == "failed" and "nothing was saved" in m._signin["google"]["message"]
    assert not A._state_file("google").exists()
    m._signin_impl = lambda p, cancel, progress: None
    m.begin_signin("google")
    m.wait_signin("google")
    assert not A._state_file("google").exists()


def test_signin_refuses_without_a_display_or_browser_and_unknown_provider():
    m = make()
    m._has_display = lambda: False
    with pytest.raises(A.AccountError, match="no display"):
        m.begin_signin("google")
    m._has_display = lambda: True
    m._browser_ok = lambda: (False, "No Chrome found")
    with pytest.raises(A.AccountError, match="browser"):
        m.begin_signin("google")
    with pytest.raises(A.AccountError):
        m.begin_signin("yahoo")


def test_signin_runs_in_background_and_reports_progress():
    m = make()
    gate = threading.Event()

    def slow(provider, cancel, progress):
        progress("waiting", "window open")
        gate.wait(3)
        return good_state(provider)
    m._signin_impl = slow
    t0 = time.time()
    m.begin_signin("google")
    assert time.time() - t0 < 1                              # did not block
    time.sleep(0.1)
    assert m.status()["accounts"]["google"]["signin"] == {"state": "waiting", "message": "window open"}
    with pytest.raises(A.AccountError, match="already open"):
        m.begin_signin("google")
    gate.set()
    m.wait_signin("google")
    assert m.status()["accounts"]["google"]["state"] == "signed_in"


def test_expired_cookies_mean_needs_signin_again():
    m = make()
    sign_in(m, state=good_state("google", expires=time.time() + 5))
    clock = Clock(time.time() + 100)
    m.now = clock
    assert m.status()["accounts"]["google"]["state"] == "needs_signin"
    assert m.eligible("google", clock())[1] == "saved session expired"


# ── eligibility, caps ───────────────────────────────────────────────────────────────────────
def test_nothing_runs_unless_signed_in_switch_on_and_noise_running():
    seen = []
    visit = lambda *a: seen.append(a) or OK_PAGE   # noqa: E731
    cfg = {"google": {"enabled": False, "per_hour": 3, "per_day": 5}, "microsoft": {"enabled": False}}
    m = make(cfg, visit=visit)
    assert m.visit_once("google") is None                      # signed out
    sign_in(m)
    assert m.visit_once("google") is None and not seen         # signed in but switch off
    cfg["google"]["enabled"] = True
    m._running = lambda: False
    assert m.visit_once("google") is None and not seen         # noise not running
    m._running = lambda: True
    assert m.visit_once("google") is OK_PAGE and len(seen) == 1
    assert A.url_allowed("google", seen[0][1])


def test_hourly_and_daily_caps():
    clock = Clock()
    seen = []
    m = make(visit=lambda *a: seen.append(1) or OK_PAGE, clock=clock)
    sign_in(m)
    for _ in range(3):
        assert m.visit_once("google") is OK_PAGE
        clock.t += 60
    assert m.visit_once("google") is None and len(seen) == 3           # 3 per hour
    assert m.eligible("google")[1] == "hourly cap reached"
    clock.t += 3600
    assert m.visit_once("google") is OK_PAGE and m.visit_once("google") is OK_PAGE
    assert m.eligible("google")[1] == "daily cap reached"               # per_day = 5
    clock.t += 86400
    assert m.eligible("google")[0]


def test_visit_timing_is_jittered():
    clock = Clock()
    m = make(visit=lambda *a: OK_PAGE, clock=clock)
    sign_in(m)
    gaps = []
    for i in range(40):
        m._next_at.clear()
        m._next_at["google"] = 0
        clock.t = 1_000_000.0 + i * 100000
        m.tick("google", clock.t)
        gaps.append(m._next_at["google"] - clock.t)
    assert len(set(round(g) for g in gaps)) > 30 and max(gaps) - min(gaps) > 1500


def test_good_visit_refreshes_the_saved_session_privately():
    fresh = good_state()
    fresh["cookies"][0]["value"] = "rotated"
    m = make(visit=lambda *a: A.VisitResult(200, OK_PAGE.url, "Inbox", "x", state=fresh))
    sign_in(m)
    assert m.visit_once("google")
    f = A._state_file("google")
    assert "rotated" in f.read_text() and stat.S_IMODE(f.stat().st_mode) == 0o600


# ── randomized, escalating pause ────────────────────────────────────────────────────────────
def test_pause_ranges_and_escalation():
    rng = random.Random(42)
    now = 10_000_000.0
    first = [A.pause_seconds(rng, [], now) for _ in range(2000)]
    assert all(3 * 3600 <= x <= 12 * 3600 for x in first)
    assert min(first) < 4 * 3600 and max(first) > 11 * 3600 and len({round(x) for x in first}) > 1900
    mid = math.sqrt(3 * 12) * 3600                                         # log-uniform: median near the geometric mean
    assert abs(sorted(first)[1000] - mid) < 0.15 * mid
    second = [A.pause_seconds(rng, [now - 86400], now) for _ in range(2000)]          # one stop, 1 day ago
    assert all(12 * 3600 <= x <= 36 * 3600 for x in second)
    third = [A.pause_seconds(rng, [now - 5 * 86400, now - 86400], now) for _ in range(2000)]   # two within a week
    assert all(24 * 3600 <= x <= 96 * 3600 for x in third)
    # outside the windows it starts over
    assert all(3 * 3600 <= A.pause_seconds(rng, [now - 4 * 86400], now) <= 12 * 3600 for _ in range(200))
    assert all(24 * 3600 <= A.pause_seconds(rng, [now - 6 * 86400, now - 5 * 86400], now) <= 96 * 3600 for _ in range(200))


def test_seeded_pause_is_reproducible_but_not_fixed():
    a = [A.pause_seconds(random.Random(7), [], 0) for _ in range(2)]
    assert a[0] == a[1]
    r = random.Random(7)
    assert A.pause_seconds(r, [], 0) != A.pause_seconds(r, [], 0)


@pytest.mark.parametrize("page,cause", [
    (A.VisitResult(429, "https://www.google.com/search?q=a", "", ""), "rate_limited"),
    (A.VisitResult(200, "https://www.google.com/sorry/index", "", "unusual traffic"), "challenge"),
    (A.VisitResult(200, "https://accounts.google.com/v3/signin", "Sign in", ""), "signin"),
])
def test_stop_pauses_only_that_account_and_escalates(page, cause):
    clock = Clock()
    m = make(visit=lambda *a: page, clock=clock)
    sign_in(m)
    sign_in(m, "microsoft")
    assert m.visit_once("google") is page
    st = m.status()["accounts"]["google"]
    assert st["state"] == "needs_attention" and 3 * 3600 <= st["attention_until"] - clock() <= 12 * 3600
    assert st["attention_reason"] and m.eligible("google")[1] == "needs attention"
    assert m.eligible("microsoft")[0]                                   # the other account is untouched
    assert any("paused signed-in visits until about" in e["message"] for e in m.log.since(0, "warn"))
    clock.t += 13 * 3600                                                # pause over: a second stop within 3 days is longer
    assert m.eligible("google")[0]
    m.visit_once("google")
    st = m.status()["accounts"]["google"]
    assert 12 * 3600 <= st["attention_until"] - clock() <= 36 * 3600


def test_third_stop_within_a_week_is_one_to_four_days():
    clock = Clock()
    m = make(visit=lambda *a: A.VisitResult(429, "https://www.google.com/search?q=a"), clock=clock)
    sign_in(m)
    for _ in range(2):
        clock.t += 2 * 86400
        m.stop_for_attention("google", "rate_limited", clock())
    clock.t += 2 * 86400
    secs = m.stop_for_attention("google", "challenge", clock())
    assert 24 * 3600 <= secs <= 96 * 3600


def test_resume_now_ends_the_pause_but_escalation_is_remembered():
    clock = Clock()
    m = make(clock=clock)
    sign_in(m)
    m.stop_for_attention("google", "challenge", clock())
    assert m.status()["accounts"]["google"]["state"] == "needs_attention"
    m.resume("google")
    assert m.status()["accounts"]["google"]["state"] == "signed_in" and m.eligible("google")[0]
    clock.t += 3600
    assert 12 * 3600 <= m.stop_for_attention("google", "challenge", clock()) <= 36 * 3600


def test_keep_going_mode_ignores_robot_checks_and_429_but_not_a_dead_session():
    clock = Clock()
    cfg = {"google": {"enabled": True, "per_hour": 3, "per_day": 5, "on_challenge": "continue"}, "microsoft": {}}
    m = make(cfg, visit=lambda *a: A.VisitResult(429, "https://www.google.com/search?q=a"), clock=clock)
    sign_in(m)
    assert m.stop_for_attention("google", "challenge", clock()) is None
    assert m.visit_once("google")
    assert m.status()["accounts"]["google"]["state"] == "signed_in"
    assert any("not recommended" in e["message"] for e in m.log.since(0, "warn"))
    assert m.stop_for_attention("google", "signin", clock()) is not None   # a signed-out session still pauses
    assert m.status()["accounts"]["google"]["state"] == "needs_attention"


def test_ordinary_noise_carries_on_while_an_account_is_paused():
    from legalprivacy.scheduler import Runner, build_lanes
    from legalprivacy.transports import HitResult
    prof = Profile(name="t")
    prof.engines["search"].budget_per_day = 10
    hits = []
    r = Runner(profile=prof, lanes=build_lanes(prof, ["a", "b"]), wordlist=["a", "b"], clock=lambda: 0.0,
               local_hour_fn=lambda: 12.0, sleep_fn=lambda s: None, max_iterations=50,
               probe_fn=lambda l, i, t: hits.append(t.url) or HitResult(200, ""))
    m = make()
    sign_in(m)
    m.stop_for_attention("google", "challenge")
    assert m.status()["accounts"]["google"]["state"] == "needs_attention"
    for _ in range(5):
        r.run_once(wait=False)
    assert len(hits) == 5                                  # signed-out noise unaffected
    assert not hasattr(m, "runner") and not any("mail.google" in h for h in hits)


# ── never over Tor ──────────────────────────────────────────────────────────────────────────
def test_never_over_tor():
    for bad in ("socks5://127.0.0.1:9050", "socks5h://localhost:9150", "socks5://abc.onion:1080",
                "http://xyz.onion:8080"):
        with pytest.raises(A.AccountError, match="Tor"):
            A.check_clearnet_proxy(bad)
    with pytest.raises(A.AccountError):
        A.check_clearnet_proxy("socks5://127.0.0.1:9333", ("127.0.0.1:9333",))
    A.check_clearnet_proxy(None)
    A.check_clearnet_proxy("http://proxy.example:3128", ("127.0.0.1:9050",))
    seen = []
    m = make(visit=lambda *a: seen.append(a) or OK_PAGE, proxy="socks5://127.0.0.1:9050")
    sign_in(m)
    with pytest.raises(A.AccountError, match="Tor"):
        m.visit_once("google")
    assert not seen
    m._proxy = lambda: "http://proxy.example:3128"
    assert m.visit_once("google") and seen[0][3] == "http://proxy.example:3128"   # the clearnet lane's own proxy
    # the manager takes no transport/lane: it cannot reach the Tor lane
    import inspect
    assert not any("lane" in n or "transport" in n for n in inspect.signature(A.AccountsManager.__init__).parameters)


# ── cookies are separate; wipe and panic ─────────────────────────────────────────────────────
def test_cookie_wipe_leaves_account_files_and_noise_jar_is_elsewhere():
    from legalprivacy import browser as B
    m = make()
    sign_in(m)
    t = B.BrowserTransport.__new__(B.BrowserTransport)
    t.cookie_hours, t.cookie_vary, t.engine, t.on_event = 1.0, True, "chromium", lambda *a: None
    jar = t._jar(False)
    jar.parent.mkdir(parents=True, exist_ok=True)
    jar.write_text("{}")
    B._born_file(jar).write_text(f"{int(time.time()) - 99999} 3600")
    assert t._load_jar(False) is None and not jar.exists()                # the weekly/hourly wipe ran
    assert A._state_file("google").exists() and A._meta_file("google").exists()
    assert A.accounts_dir() not in jar.parents and jar.parent != A.accounts_dir()
    assert not str(jar).startswith(str(A.accounts_dir()))


def test_panic_levels_and_text(home):
    c = Controller(str(home / "config.yaml"))
    c.accounts._signin_impl = lambda p, cancel, progress: good_state(p)
    c.accounts._has_display = lambda: True
    c.accounts._browser_ok = lambda: (True, "x")
    for level, gone in (("soft", False), ("medium", True), ("hard", True)):
        c.accounts.begin_signin("google")
        c.accounts.wait_signin("google")
        assert A._state_file("google").exists()
        out = c.panic(level)
        assert A._state_file("google").exists() != gone
        assert any("signed-in account sessions deleted" in d for d in out["done"]) == gone
    html = open(os.path.join(os.path.dirname(__file__), "..", "legalprivacy", "web", "index.html"), encoding="utf-8").read()
    assert "delete any signed-in account sessions" in html and "signed-in account sessions and connection records" in html


# ── endpoints (browser launch stubbed) ───────────────────────────────────────────────────────
def _call(base, token, path, body=None):
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"X-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_endpoints(home):
    c = Controller(str(home / "config.yaml"))
    srv = UIServer(c, port=0)
    threading.Thread(target=srv.httpd.serve_forever, daemon=True).start()
    base, tok = f"http://127.0.0.1:{srv.port}", srv.token
    try:
        code, st = _call(base, tok, "/api/state")
        assert code == 200 and st["accounts"]["accounts"]["google"]["state"] == "signed_out"
        assert st["profile"]["accounts"]["google"]["enabled"] is False
        assert _call(base, "bad", "/api/accounts")[0] == 401
        c.accounts._has_display = lambda: False                       # no display: plain refusal
        code, err = _call(base, tok, "/api/accounts/signin", {"provider": "google"})
        assert code == 400 and "no display" in err["error"]
        c.accounts._has_display = lambda: True
        c.accounts._browser_ok = lambda: (True, "x")
        c.accounts._signin_impl = lambda p, cancel, progress: good_state(p)
        assert _call(base, tok, "/api/accounts/signin", {"provider": "google"})[0] == 200
        c.accounts.wait_signin("google")
        assert _call(base, tok, "/api/accounts")[1]["accounts"]["google"]["state"] == "signed_in"
        assert _call(base, tok, "/api/config", {"accounts": {"google": {"enabled": True, "per_hour": 5}}})[0] == 200
        assert c.profile.accounts["google"].per_hour == 5 and c.accounts._cfg("google")["enabled"]
        assert _call(base, tok, "/api/config", {"accounts": {"google": {"per_hour": 99}}})[0] == 400
        assert _call(base, tok, "/api/accounts/signin", {"provider": "yahoo"})[0] == 400
        c.accounts.stop_for_attention("google", "challenge")
        assert _call(base, tok, "/api/accounts/resume", {"provider": "google"})[0] == 200
        assert _call(base, tok, "/api/accounts")[1]["accounts"]["google"]["state"] == "signed_in"
        assert _call(base, tok, "/api/accounts/forget", {"provider": "google"})[0] == 200
        assert _call(base, tok, "/api/accounts")[1]["accounts"]["google"]["state"] == "signed_out"
    finally:
        srv.httpd.shutdown()


def test_firefox_sign_in_is_reused_without_a_window(tmp_path, monkeypatch):
    import sqlite3
    monkeypatch.setattr(A, "accounts_dir", lambda: tmp_path)
    prof = tmp_path / "ff"
    prof.mkdir()
    con = sqlite3.connect(prof / "cookies.sqlite")
    con.execute("CREATE TABLE moz_cookies (name, value, host, path, expiry, isSecure, isHttpOnly, sameSite)")
    far = (time.time() + 86400 * 30) * 1000                       # milliseconds, as newer Firefox stores them
    con.executemany("INSERT INTO moz_cookies VALUES (?,?,?,?,?,?,?,?)",
                    [("SID", "x", ".google.com", "/", far, 1, 1, 0), ("other", "y", ".example.com", "/", far, 0, 0, 1)])
    con.commit(); con.close()
    st = A.firefox_session("google", prof)
    assert st and [c["name"] for c in st["cookies"]] == ["SID"] and st["cookies"][0]["expires"] < 1e11
    assert A.firefox_session("microsoft", prof) is None
    m = make()
    m._firefox_import = lambda p: A.firefox_session(p, prof)
    m._signin_impl = lambda *a: (_ for _ in ()).throw(AssertionError("no window should open"))
    assert m.begin_signin("google").get("from_firefox") and m.has_session("google")
