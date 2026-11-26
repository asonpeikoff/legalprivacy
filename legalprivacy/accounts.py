"""Optional signed-in accounts (Google, Microsoft): the noise browser can browse while signed in.

The owner signs in BY HAND in a visible browser window; noisyCricket never sees, stores or types a
password or a code. Only the browser's own session (cookies) is kept, in app_dir()/accounts/, apart from
the ordinary noise browser's cookies. Signed-in visits are read-only: they LOAD and scroll a short list of
allowed pages and never click, so nothing is ever sent, deleted, archived, labelled or changed.

Rules enforced here (and tested):
  * nothing runs unless the account is signed in AND its switch is on AND noise is running;
  * hourly and daily caps; a random, escalating pause when a sign-in page, a robot check or a 429 shows up;
  * only the clearnet browser, never Tor (a Tor-looking proxy is refused);
  * an explicit allowlist of pages and a blocklist of click targets; all clicks are cancelled in the page.
"""
from __future__ import annotations

import json
import os
import random
import shutil
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable

# After a sign-in page, robot check or 429 the account's signed-in visits pause for a RANDOM, escalating
# while (log-uniform, so there is no fixed length to spot): 3-12 h the first time, 12-36 h if it happens again
# within 3 days, 1-4 days if it keeps happening within a week.
PAUSE_RANGES = ((3 * 3600, 12 * 3600), (12 * 3600, 36 * 3600), (24 * 3600, 96 * 3600))
ESCALATE_WINDOWS = (3 * 86400, 7 * 86400)
SOFT_CAUSES = ("challenge", "rate_limited")     # the ones the "keep going" setting may ignore
SIGNIN_TIMEOUT = 15 * 60              # how long the sign-in window may stay open

TOR_SOCKS_PORTS = (9050, 9150)


class AccountError(RuntimeError):
    pass


# ── what each provider may visit (the allowlist) ───────────────────────────────────────────
# Each entry: (host, path prefix). A visit is only ever started at one of PLAN's addresses, and the
# browser may only navigate to addresses matching ALLOWED (or to a sign-in page, which is then
# recognised and ends the visit).
PROVIDERS: dict[str, dict] = {
    "google": {
        "label": "Google",
        "signin_url": "https://accounts.google.com/ServiceLogin?service=mail"
                      "&continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F",
        "allowed": [("www.google.com", "/search"), ("mail.google.com", "/mail/"), ("www.youtube.com", "/")],
        "signin_hosts": ("accounts.google.com", "consent.google.com"),
        "home": [("mail.google.com", "/mail/"), ("myaccount.google.com", "/")],
        "auth_cookies": ("SID", "SAPISID", "__Secure-1PSID", "__Secure-3PSID", "__Secure-1PAPISID"),
        "cookie_domain": "google.com",
    },
    "microsoft": {
        "label": "Microsoft (Outlook)",
        "signin_url": "https://outlook.live.com/mail/0/",
        "allowed": [("outlook.live.com", "/mail/"), ("outlook.live.com", "/calendar/"),
                    ("outlook.office.com", "/mail/"), ("outlook.office.com", "/calendar/"),
                    ("www.bing.com", "/search"), ("www.microsoft.com", "/")],
        "signin_hosts": ("login.live.com", "login.microsoftonline.com"),
        "home": [("outlook.live.com", "/mail/"), ("outlook.office.com", "/mail/")],
        "auth_cookies": ("ESTSAUTHPERSISTENT", "ESTSAUTH", "ESTSAUTHLIGHT", "MSPAuth", "RPSSecAuth", "WLSSC"),
        "cookie_domain": "",           # any of live.com / microsoftonline.com / microsoft.com / office.com
    },
}
PROVIDER_IDS = tuple(PROVIDERS)

# (url or template, weight). {q} is replaced by an ordinary search topic.
PLAN: dict[str, list[tuple[str, float]]] = {
    "google": [("https://www.google.com/search?q={q}", 5), ("https://mail.google.com/mail/u/0/#inbox", 3),
               ("https://www.youtube.com/", 3)],
    "microsoft": [("https://outlook.live.com/mail/0/inbox", 3), ("https://outlook.office.com/mail/inbox", 0),
                  ("https://outlook.live.com/calendar/", 2), ("https://www.bing.com/search?q={q}", 4),
                  ("https://www.microsoft.com/", 2)],
}

# Anything that could send, delete, archive, label, mark, reply, forward, compose, accept/decline,
# sign out or change a setting. Matched against a click target's text, aria-label, title and link.
BLOCKED_CLICK_WORDS = (
    "send", "delete", "discard", "trash", "remove", "archive", "label", "move to", "mark as", "mark read",
    "mark unread", "read", "unread", "spam", "junk", "report", "block", "unsubscribe", "reply", "forward",
    "compose", "new message", "new mail", "write", "draft", "accept", "decline", "tentative", "rsvp",
    "sign out", "log out", "logout", "signout", "switch account", "add account", "settings", "setting",
    "preferences", "options", "manage", "security", "password", "save", "submit", "confirm", "pin",
    "flag", "snooze", "star", "undo", "empty", "create", "edit", "upload", "share", "invite", "subscribe",
    "like", "comment", "post", "buy", "purchase", "order", "pay", "checkout")
BLOCKED_HREF_PARTS = ("logout", "signout", "sign-out", "/delete", "/send", "compose", "/settings",
                      "action=", "accounts.google.com/signout", "login.srf?wa=wsignout")


def click_allowed(text: str = "", href: str = "", label: str = "") -> bool:
    """The gate any click would have to pass. Today the visits never click at all (every click is
    cancelled in the page itself), so this only ever protects future code."""
    blob = " ".join((text or "", label or "")).lower()
    for w in BLOCKED_CLICK_WORDS:
        if w in blob:
            return False
    h = (href or "").lower()
    return not any(p in h for p in BLOCKED_HREF_PARTS)


def url_allowed(provider: str, url: str) -> bool:
    """True if this address is one signed-in visits may load for this provider (https only)."""
    try:
        u = urllib.parse.urlparse(url)
    except ValueError:
        return False
    if u.scheme != "https" or not u.hostname:
        return False
    host = u.hostname.lower()
    path = u.path or "/"
    for h, prefix in PROVIDERS.get(provider, {}).get("allowed", []):
        if host == h and path.startswith(prefix):
            return True
    return False


def is_signin_url(provider: str, url: str) -> bool:
    try:
        u = urllib.parse.urlparse(url)
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    if host in PROVIDERS.get(provider, {}).get("signin_hosts", ()):
        return True
    return "/servicelogin" in (u.path or "").lower() or "/signin" in (u.path or "").lower()


def nav_allowed(provider: str, url: str) -> bool:
    """Navigations the page may make: the allowlist, plus a sign-in page (which ends the visit)."""
    return url_allowed(provider, url) or is_signin_url(provider, url)


def plan_visit(provider: str, rng: random.Random, topics: list[str] | None = None,
               mail_host: str | None = None) -> str:
    """Pick the next address to visit: always built from PLAN, and always passes url_allowed()."""
    if provider not in PLAN:
        raise AccountError(f"unknown provider {provider!r}")
    topics = topics or ["weather this week", "python tutorial", "easy dinner recipe", "local news",
                        "how to fix a bike chain", "movie showtimes"]
    items = list(PLAN[provider])
    if provider == "microsoft":                       # the mailbox host this account actually uses
        work = mail_host == "outlook.office.com"
        items = [(u, w) for u, w in items if ("outlook." not in u or ("office.com" in u) == work)]
        items = [(u, (w or 3) if "outlook." in u else w) for u, w in items]
    url, _ = rng.choices(items, weights=[w or 0.0001 for _, w in items])[0]
    if "{q}" in url:
        url = url.replace("{q}", urllib.parse.quote_plus(rng.choice(topics)))
    if not url_allowed(provider, url):                # cannot happen; belt and braces
        raise AccountError(f"refusing to visit {url}")
    return url


# ── reading a page: is this still a normal signed-in page? ───────────────────────────────────
CHALLENGE_MARKERS = ("unusual traffic", "unusual activity", "verify it's you", "verify it’s you",
                     "verify your identity", "confirm it's you", "confirm it’s you", "captcha",
                     "not a robot", "are you a robot", "suspicious activity", "suspicious sign-in",
                     "your account has been locked", "account has been temporarily", "help us protect your account",
                     "we need to verify", "security check", "prove you're not", "prove you’re not")


def classify_page(provider: str, url: str, title: str = "", text: str = "", status: int | None = 200) -> str:
    """'ok' | 'rate_limited' | 'challenge' | 'signin' | 'signed_out' | 'blocked'."""
    if status == 429:
        return "rate_limited"
    low = (url or "").lower()
    if "/sorry/" in low or "captcha" in low:
        return "challenge"
    blob = f"{title} {text}".lower()
    if any(m in blob for m in CHALLENGE_MARKERS):
        return "challenge"
    if is_signin_url(provider, url):
        return "signin"
    if not url_allowed(provider, url):
        return "signed_out"            # e.g. Gmail sends a signed-out visitor to its marketing page
    if status is not None and status >= 400:
        return "blocked"
    return "ok"


def pause_seconds(rng: random.Random, earlier_stops: list[float], now: float) -> float:
    """How long to pause now, given when this account stopped before (unix times, any age)."""
    import math
    in3 = sum(1 for t in earlier_stops if now - t < ESCALATE_WINDOWS[0])
    in7 = sum(1 for t in earlier_stops if now - t < ESCALATE_WINDOWS[1])
    tier = 2 if in7 >= 2 else 1 if in3 >= 1 else 0
    lo, hi = PAUSE_RANGES[tier]
    return math.exp(rng.uniform(math.log(lo), math.log(hi)))


REASONS = {
    "rate_limited": "it answered “too many requests” (HTTP 429)",
    "challenge": "it asked to verify it's you, or showed a robot check / unusual-activity page",
    "signin": "it showed a sign-in page (the saved session no longer works)",
    "signed_out": "it no longer looks signed in (the saved session expired)",
    "expired": "the saved cookies have expired",
    "blocked": "it returned an error page",
}


# ── saved browser sessions ───────────────────────────────────────────────────────────────────
def accounts_dir() -> Path:
    from .paths import app_dir
    return app_dir() / "accounts"


def _state_file(provider: str) -> Path:
    return accounts_dir() / f"{provider}.json"


def _meta_file(provider: str) -> Path:
    return accounts_dir() / f"{provider}.meta.json"


def _write_private(path: Path, text: str) -> None:
    """Write a file only its owner can read (0600 where the OS supports it)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    from .paths import write_private
    write_private(path, text)


def looks_signed_in(provider: str, state: dict | None, now: float | None = None) -> bool:
    """Does this saved browser state hold the provider's sign-in cookies, still unexpired?"""
    return _auth_cookies(provider, state, now) > 0


def _auth_cookies(provider: str, state: dict | None, now: float | None) -> int:
    now = time.time() if now is None else now
    spec = PROVIDERS.get(provider)
    if not spec or not isinstance(state, dict):
        return 0
    n = 0
    for c in state.get("cookies") or []:
        if not isinstance(c, dict) or c.get("name") not in spec["auth_cookies"]:
            continue
        dom = str(c.get("domain", "")).lstrip(".").lower()
        want = spec["cookie_domain"]
        if want and not (dom == want or dom.endswith("." + want)):
            continue
        if provider == "microsoft" and not any(dom.endswith(x) for x in
                                               ("live.com", "microsoftonline.com", "microsoft.com", "office.com")):
            continue
        exp = c.get("expires", -1)
        if isinstance(exp, (int, float)) and exp > 0 and exp < now:
            continue                       # expired
        n += 1
    return n


def has_display() -> bool:
    if sys.platform in ("win32", "darwin"):
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def check_clearnet_proxy(proxy: str | None, tor_addrs: tuple[str, ...] = ()) -> None:
    """Signed-in visits are never allowed over Tor: refuse a proxy that is (or looks like) Tor."""
    if not proxy:
        return
    p = proxy.strip().lower()
    if p in {a.lower() for a in tor_addrs if a}:
        raise AccountError("signed-in visits never go over Tor")
    u = urllib.parse.urlparse(p if "://" in p else "//" + p)
    host = (u.hostname or "").lower()
    if host.endswith(".onion"):
        raise AccountError("signed-in visits never go over Tor")
    try:
        port = u.port
    except ValueError:
        port = None
    if (u.scheme or "").startswith("socks") and host in ("127.0.0.1", "localhost", "::1") and port in TOR_SOCKS_PORTS:
        raise AccountError("signed-in visits never go over Tor")
    for a in tor_addrs:
        if a and host and f"{host}:{port}" == a.lower().split("://")[-1]:
            raise AccountError("signed-in visits never go over Tor")


# Defence in depth: the page cannot click, submit or press a key that acts on a mailbox. We never click
# anyway; this makes sure a page script or a stray event can't either.
READONLY_JS = """(() => {
  const stop = e => { e.preventDefault(); e.stopImmediatePropagation(); };
  for (const t of ['click', 'dblclick', 'auxclick', 'submit', 'contextmenu', 'dragstart', 'drop'])
    window.addEventListener(t, stop, true);
  window.addEventListener('keydown', e => {
    if (!['ArrowDown', 'ArrowUp', 'PageDown', 'PageUp', 'Home', 'End', ' ', 'Tab'].includes(e.key)) stop(e);
  }, true);
  window.open = function () { return null; };
})();"""


@dataclass
class VisitResult:
    status: int | None = 200
    url: str = ""
    title: str = ""
    text: str = ""
    error: str | None = None
    state: dict | None = None          # refreshed browser state, saved only after a normal visit
    seconds: float = 0.0


def _real_visit(provider: str, url: str, state_path: str, proxy: str | None, stop: threading.Event,
                rng: random.Random, executable: str | None = None) -> VisitResult:
    """Load one allowed page in a throwaway clearnet browser using the account's saved session, scroll a
    little, read nothing but the address, title and the start of the text. Needs a real browser; not
    exercised by the unit tests."""
    from playwright.sync_api import sync_playwright
    from .browser import find_browser
    from .humanize import HumanDriver
    exe = executable or find_browser()
    if not exe:
        return VisitResult(error="no Chromium-family browser found")
    pw = sync_playwright().start()
    browser = None
    try:
        args = ["--disable-blink-features=AutomationControlled", "--no-default-browser-check",
                "--no-first-run", "--disable-background-networking"]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            args.append("--no-sandbox")
        browser = pw.chromium.launch(executable_path=exe, headless=True, args=args,
                                     proxy={"server": proxy} if proxy else None)
        ctx = browser.new_context(storage_state=state_path, locale="en-US", viewport={"width": 1366, "height": 768})
        page = ctx.new_page()
        ua = page.evaluate("() => navigator.userAgent")
        if "Headless" in ua:                          # a signed-in Google/Microsoft page dislikes this
            ctx.close()
            ctx = browser.new_context(storage_state=state_path, locale="en-US", viewport={"width": 1366, "height": 768},
                                      user_agent=ua.replace("HeadlessChrome", "Chrome"))
            page = ctx.new_page()
        ctx.add_init_script(READONLY_JS)

        def guard(route):
            req = route.request
            try:
                if req.is_navigation_request() and req.frame == page.main_frame and not nav_allowed(provider, req.url):
                    return route.abort()
            except Exception:
                pass
            return route.continue_()
        ctx.route("**/*", guard)
        resp = page.goto(url, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(3000)                   # mail apps draw themselves after the page loads
        title = (page.title() or "")
        try:
            text = page.evaluate("() => (document.body ? document.body.innerText : '').slice(0, 3000)") or ""
        except Exception:
            text = ""
        res = VisitResult(status=resp.status if resp is not None else 200, url=page.url, title=title, text=text)
        if classify_page(provider, res.url, title, text, res.status) == "ok":
            act = _ReadOnlyActuator(page, False, stop)
            stats = HumanDriver(rng, act).browse(dwell=rng.uniform(8, 35))
            res.seconds = stats.get("seconds", 0.0)
            try:
                res.state = ctx.storage_state()
            except Exception:
                pass
        return res
    except Exception as exc:
        return VisitResult(error=str(exc).splitlines()[0][:200] if str(exc) else repr(exc))
    finally:
        try:
            if browser:
                browser.close()
        finally:
            pw.stop()


def _make_readonly_actuator():
    from .browser import PlaywrightActuator

    class ReadOnlyActuator(PlaywrightActuator):
        def select_text(self, x, y, dx):             # no press-drag-release on a mailbox page
            return False
    return ReadOnlyActuator


class _ReadOnlyActuator:
    def __new__(cls, page, mobile, stop):
        return _make_readonly_actuator()(page, mobile, stop, None)


FIREFOX_COOKIE_HOSTS = {"google": ("google.com", "youtube.com"),
                        "microsoft": ("live.com", "microsoftonline.com", "microsoft.com", "office.com")}


def firefox_session(provider: str, profile: Path | None = None) -> dict | None:
    """The sign-in you already have in your own Firefox: its cookies for this provider, read from a COPY of the
    cookie file of the profile Firefox opens by default (Firefox itself is never touched or changed). Returns a
    browser state like the sign-in window's, or None when Firefox isn't signed in there."""
    import sqlite3
    import tempfile
    if profile is None:
        try:
            from .realfirefox import default_profile
            profile = default_profile()
        except Exception:
            profile = None
    src = Path(profile) / "cookies.sqlite" if profile else None
    if src is None or not src.exists():
        return None
    hosts = FIREFOX_COOKIE_HOSTS.get(provider, ())
    tmp = Path(tempfile.mkdtemp(prefix="lp-ffcookies-"))
    try:
        for name in ("cookies.sqlite", "cookies.sqlite-wal"):          # the -wal file holds the newest cookies
            if (src.parent / name).exists():
                shutil.copy2(src.parent / name, tmp / name)
        con = sqlite3.connect(f"file:{tmp / 'cookies.sqlite'}?mode=ro", uri=True)
        try:
            rows = con.execute("SELECT name, value, host, path, expiry, isSecure, isHttpOnly, sameSite "
                               "FROM moz_cookies").fetchall()
        finally:
            con.close()
    except Exception:
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    cookies = []
    for name, value, host, path, expiry, secure, http_only, same in rows:
        dom = str(host or "").lstrip(".").lower()
        if not any(dom == h or dom.endswith("." + h) for h in hosts):
            continue
        exp = float(expiry or -1)
        if exp > 1e11:                                   # newer Firefox stores milliseconds
            exp /= 1000.0
        cookies.append({"name": name, "value": value, "domain": host, "path": path or "/", "expires": exp,
                        "httpOnly": bool(http_only), "secure": bool(secure),
                        "sameSite": {1: "Lax", 2: "Strict"}.get(int(same or 0), "None")})
    state = {"cookies": cookies, "origins": []}
    return state if looks_signed_in(provider, state) else None


def _real_signin(provider: str, cancel: threading.Event, progress: Callable[[str, str], None],
                 executable: str | None = None) -> dict | None:
    """Open a VISIBLE browser at the provider's sign-in page and wait while the person signs in by hand.
    Returns the browser's storage_state when they are done (window closed, or the signed-in home reached).
    This code never reads or types anything in the page. Not exercised by the unit tests."""
    from playwright.sync_api import sync_playwright
    from .browser import find_browser
    spec = PROVIDERS[provider]
    exe = executable or find_browser()
    if not exe:
        raise AccountError("No Chrome, Edge, Brave or Chromium found on this computer")
    pw = sync_playwright().start()
    browser = None
    last: dict | None = None
    try:
        args = ["--no-default-browser-check", "--no-first-run"]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            args.append("--no-sandbox")
        browser = pw.chromium.launch(executable_path=exe, headless=False, args=args,
                                     ignore_default_args=["--enable-automation"])
        ctx = browser.new_context(viewport=None)
        page = ctx.new_page()
        page.goto(spec["signin_url"], wait_until="domcontentloaded", timeout=60000)
        progress("waiting", "A browser window is open. Sign in there (password and any code are typed "
                            "by you, in that window). It closes by itself once your inbox shows, or close it when done.")
        t0 = time.time()
        home_since = None
        while not cancel.is_set() and time.time() - t0 < SIGNIN_TIMEOUT:
            try:
                if not browser.is_connected() or page.is_closed() and not ctx.pages:
                    break
                open_pages = [p for p in ctx.pages if not p.is_closed()]
                if not open_pages:
                    break
                url = open_pages[-1].url
                # Only the cookies are read while the person signs in: reading the full storage state every second
                # (it visits every origin's local storage) made Google's sign-in page reload over and over.
                try:
                    last = {"cookies": ctx.cookies(), "origins": []}
                except Exception:
                    pass
                at_home = any(url.startswith(f"https://{h}{p}") for h, p in spec["home"])
                if at_home and looks_signed_in(provider, last):
                    home_since = home_since or time.time()
                    if time.time() - home_since > 4:      # give it a moment to settle, then finish
                        try:
                            last = ctx.storage_state() or last
                        except Exception:
                            pass
                        break
                else:
                    home_since = None
                time.sleep(1.0)
            except Exception:
                break                                        # window closed under us
        return last
    finally:
        try:
            if browser:
                browser.close()
        except Exception:
            pass
        try:
            pw.stop()
        except Exception:
            pass


# ── the manager ───────────────────────────────────────────────────────────────────────────────
class AccountsManager:
    """Owns the saved sessions, the sign-in threads and the (single) signed-in visit loop.

    config():  the profile's accounts section {provider: AccountConfig-like with enabled/per_hour/per_day}
    running(): True while noise is running and not paused
    proxy():   the clearnet lane's proxy (never Tor's)
    """

    def __init__(self, log, config: Callable[[], dict], running: Callable[[], bool],
                 proxy: Callable[[], str | None] = lambda: None,
                 tor_addrs: Callable[[], tuple[str, ...]] = lambda: (),
                 signin_impl=None, visit_impl=None, has_display_fn=None, browser_ok=None, firefox_import=None,
                 rng: random.Random | None = None, now: Callable[[], float] = time.time):
        self.log, self._config, self._running = log, config, running
        self._proxy, self._tor_addrs = proxy, tor_addrs
        self._signin_impl = signin_impl or _real_signin
        self._firefox_import = firefox_import or firefox_session
        self._visit_impl = visit_impl or _real_visit
        self._has_display = has_display_fn or has_display
        self._browser_ok = browser_ok or self._default_browser_ok
        self.rng = rng or random.Random()
        self.now = now
        self._lock = threading.RLock()
        self._signin: dict[str, dict] = {}            # provider -> {state, message, cancel}
        self._next_at: dict[str, float] = {}
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @staticmethod
    def _default_browser_ok() -> tuple[bool, str]:
        from .browser import browser_support
        return browser_support()

    # ── files ──
    def _meta(self, provider: str) -> dict:
        try:
            m = json.loads(_meta_file(provider).read_text(encoding="utf-8"))
            return m if isinstance(m, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_meta(self, provider: str, meta: dict) -> None:
        _write_private(_meta_file(provider), json.dumps(meta))

    def _load_state(self, provider: str) -> dict | None:
        try:
            s = json.loads(_state_file(provider).read_text(encoding="utf-8"))
            return s if isinstance(s, dict) else None
        except (OSError, ValueError):
            return None

    def has_session(self, provider: str) -> bool:
        return _state_file(provider).exists()

    def forget(self, provider: str) -> None:
        self._check(provider)
        with self._lock:
            for f in (_state_file(provider), _meta_file(provider)):
                try:
                    f.unlink()
                except OSError:
                    pass
            self._next_at.pop(provider, None)
        self.log.info("accounts", f"{PROVIDERS[provider]['label']}: signed out and the saved session deleted.")

    def forget_all(self) -> None:
        """Panic (medium/hard): delete the whole accounts folder and cancel any sign-in in progress."""
        with self._lock:
            for s in self._signin.values():
                s["cancel"].set()
            self._signin.clear()
            self._next_at.clear()
        shutil.rmtree(accounts_dir(), ignore_errors=True)

    @staticmethod
    def _check(provider: str) -> None:
        if provider not in PROVIDERS:
            raise AccountError(f"unknown account type {provider!r}")

    # ── status ──
    def _cfg(self, provider: str) -> dict:
        c = self._config().get(provider)
        if c is None:
            return {"enabled": False, "per_hour": 3, "per_day": 12, "on_challenge": "pause"}
        return c if isinstance(c, dict) else {"enabled": c.enabled, "per_hour": c.per_hour, "per_day": c.per_day,
                                              "on_challenge": c.on_challenge}

    def _counts(self, meta: dict, now: float) -> tuple[int, int]:
        v = [t for t in meta.get("visits", []) if isinstance(t, (int, float)) and now - t < 86400]
        return sum(1 for t in v if now - t < 3600), len(v)

    def status(self) -> dict:
        now = self.now()
        out = {}
        for p, spec in PROVIDERS.items():
            meta = self._meta(p)
            cfg = self._cfg(p)
            state = self._load_state(p) if self.has_session(p) else None
            attn = float(meta.get("attention_until", 0) or 0)
            if state is None:
                st = "signed_out"
            elif not looks_signed_in(p, state, now):
                st = "needs_signin"
            elif attn > now:
                st = "needs_attention"
            else:
                st = "signed_in"
            h, d = self._counts(meta, now)
            si = self._signin.get(p) or {}
            out[p] = {"id": p, "label": spec["label"], "state": st, "saved_at": meta.get("saved_at"),
                      "enabled": bool(cfg.get("enabled")), "per_hour": cfg.get("per_hour"),
                      "per_day": cfg.get("per_day"), "visits_hour": h, "visits_day": d,
                      "attention_reason": meta.get("reason") if st == "needs_attention" else None,
                      "attention_until": attn if st == "needs_attention" else None,
                      "on_challenge": cfg.get("on_challenge", "pause"),
                      "last_visit": meta.get("last_visit"),
                      "signin": {"state": si.get("state", "idle"), "message": si.get("message", "")}}
        return {"accounts": out, "display": self._has_display()}

    # ── eligibility: signed in AND switch on AND noise running AND under the caps ──
    def eligible(self, provider: str, now: float | None = None) -> tuple[bool, str]:
        now = self.now() if now is None else now
        cfg = self._cfg(provider)
        if not cfg.get("enabled"):
            return False, "switch is off"
        if not self._running():
            return False, "noise is not running"
        state = self._load_state(provider) if self.has_session(provider) else None
        if state is None:
            return False, "not signed in"
        if not looks_signed_in(provider, state, now):
            return False, "saved session expired"
        meta = self._meta(provider)
        if float(meta.get("attention_until", 0) or 0) > now:
            return False, "needs attention"
        h, d = self._counts(meta, now)
        if h >= int(cfg.get("per_hour", 3)):
            return False, "hourly cap reached"
        if d >= int(cfg.get("per_day", 12)):
            return False, "daily cap reached"
        return True, "ok"

    def stop_for_attention(self, provider: str, why: str, now: float | None = None) -> float | None:
        """A sign-in page, robot check or 429 showed up. Pause this account's signed-in visits for a random,
        escalating while (unless the account is set to keep going after a robot check / 429).
        Returns the pause length in seconds, or None if it kept going. Never affects the ordinary noise."""
        now = self.now() if now is None else now
        label, reason = PROVIDERS[provider]["label"], REASONS.get(why, why)
        meta = self._meta(provider)
        if why in SOFT_CAUSES and self._cfg(provider).get("on_challenge") == "continue":
            self.log.warn("accounts", f"{label}: {reason}. Carrying on, as you chose (not recommended: "
                                      "the site may restrict the account).")
            return None
        stops = [t for t in meta.get("stops", []) if isinstance(t, (int, float)) and now - t < 30 * 86400]
        secs = pause_seconds(self.rng, stops, now)
        meta["stops"] = stops + [now]
        meta["attention_until"] = now + secs
        meta["reason"] = reason
        self._save_meta(provider, meta)
        until = time.strftime("%H:%M on %d %b", time.localtime(now + secs))
        self.log.warn("accounts", f"{label}: paused signed-in visits until about {until} because {reason}. "
                                  "The ordinary noise carries on. Open the site yourself to check the account is "
                                  "fine; Resume now (Settings, Accounts) restarts it sooner.")
        return secs

    def resume(self, provider: str) -> None:
        """Resume now: end the pause (earlier pauses are remembered, so the next one still escalates)."""
        self._check(provider)
        meta = self._meta(provider)
        meta["attention_until"] = 0
        meta["reason"] = None
        self._save_meta(provider, meta)
        self._next_at.pop(provider, None)
        self.log.info("accounts", f"{PROVIDERS[provider]['label']}: signed-in visits resumed.")

    # ── one visit ──
    def visit_once(self, provider: str) -> VisitResult | None:
        """Run one signed-in visit if (and only if) the account is eligible. Returns the result, or None."""
        self._check(provider)
        now = self.now()
        ok, _ = self.eligible(provider, now)
        if not ok:
            return None
        proxy = self._proxy()
        check_clearnet_proxy(proxy, tuple(self._tor_addrs()))      # raises: never over Tor
        meta = self._meta(provider)
        url = plan_visit(provider, self.rng, mail_host=meta.get("mail_host"))
        if not url_allowed(provider, url):
            raise AccountError(f"refusing to visit {url}")
        label = PROVIDERS[provider]["label"]
        meta["visits"] = [t for t in meta.get("visits", []) if now - t < 86400] + [now]    # counts even if it fails
        meta["last_visit"] = now
        self._save_meta(provider, meta)
        try:
            res = self._visit_impl(provider, url, str(_state_file(provider)), proxy, self._stop, self.rng)
        except Exception as exc:
            self.log.warn("accounts", f"{label}: signed-in visit failed ({str(exc)[:120]}).")
            return VisitResult(error=str(exc))
        if res.error:
            self.log.warn("accounts", f"{label}: signed-in visit failed ({res.error[:120]}).")
            return res
        verdict = classify_page(provider, res.url, res.title, res.text, res.status)
        if verdict != "ok":
            self.stop_for_attention(provider, verdict)
            return res
        self.log.info("accounts", f"{label}: signed-in visit to {urllib.parse.urlparse(res.url).hostname}"
                                  f"{urllib.parse.urlparse(res.url).path[:30]} (read-only).")
        if res.state and looks_signed_in(provider, res.state):        # keep the session fresh
            try:
                _write_private(_state_file(provider), json.dumps(res.state))
            except OSError:
                pass
        return res

    # ── the loop ──
    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop = threading.Event()
            self._next_at = {}
            self._thread = threading.Thread(target=self._loop, daemon=True, name="legalprivacy-accounts")
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t and t is not threading.current_thread():
            t.join(timeout=5)

    def _loop(self) -> None:
        stop = self._stop
        while not stop.wait(15):
            for p in PROVIDER_IDS:
                if stop.is_set():
                    return
                try:
                    self.tick(p)
                except Exception as exc:
                    self.log.warn("accounts", f"{PROVIDERS[p]['label']}: {str(exc)[:120]}")

    def tick(self, provider: str, now: float | None = None) -> bool:
        """Called every few seconds: visit if it is time and the account is eligible."""
        now = self.now() if now is None else now
        if not self._running() or not self.eligible(provider, now)[0]:
            self._next_at.pop(provider, None)              # idle: schedule afresh when it becomes eligible
            return False
        if provider not in self._next_at:
            self._next_at[provider] = now + self.rng.uniform(60, 900)
        if now < self._next_at[provider]:
            return False
        per_hour = max(1, int(self._cfg(provider).get("per_hour", 3)))
        self._next_at[provider] = now + (3600.0 / per_hour) * self.rng.uniform(0.6, 2.2)
        return self.visit_once(provider) is not None

    # ── sign in (background thread; progress is polled through status()) ──
    def begin_signin(self, provider: str) -> dict:
        self._check(provider)
        label = PROVIDERS[provider]["label"]
        try:                                     # already signed in in your own Firefox: use that, no window
            ff = self._firefox_import(provider)
        except Exception:
            ff = None
        if ff and looks_signed_in(provider, ff, self.now()):
            self._save_session(provider, ff)
            with self._lock:
                self._signin[provider] = {"state": "done", "cancel": threading.Event(),
                                          "message": "Used the sign-in you already have in your own Firefox "
                                                     "(Firefox itself is unchanged). Turn the switch on to let the noise use it."}
            self.log.info("accounts", f"{label}: using the sign-in from your own Firefox (session saved on this computer).")
            return {"ok": True, "from_firefox": True}
        if not self._has_display():
            raise AccountError("This computer has no display, so a sign-in window can't open here. "
                               "Sign in from a computer with a screen (desktop session), not a headless server.")
        ok, detail = self._browser_ok()
        if not ok:
            raise AccountError(f"A real browser is needed to sign in: {detail}")
        with self._lock:
            cur = self._signin.get(provider)
            if cur and cur["state"] in ("starting", "waiting", "saving"):
                raise AccountError("A sign-in window for this account is already open.")
            entry = {"state": "starting", "message": "Opening the browser window…", "cancel": threading.Event()}
            self._signin[provider] = entry

        def progress(state: str, message: str) -> None:
            entry["state"], entry["message"] = state, message

        def work():
            try:
                state = self._signin_impl(provider, entry["cancel"], progress)
                if entry["cancel"].is_set():
                    entry["state"], entry["message"] = "failed", "Cancelled."
                    return
                progress("saving", "Saving the session…")
                if not looks_signed_in(provider, state, self.now()):
                    entry["state"], entry["message"] = "failed", (
                        "The window closed before sign-in finished, so nothing was saved. Try again.")
                    return
                self._save_session(provider, state)
                entry["state"], entry["message"] = "done", "Signed in. Turn the switch on to let the noise use it."
                self.log.info("accounts", f"{label}: signed in (session saved on this computer).")
            except Exception as exc:
                entry["state"], entry["message"] = "failed", f"Sign-in didn't finish: {str(exc)[:160]}"
                self.log.warn("accounts", f"{label}: sign-in didn't finish ({str(exc)[:120]}).")

        threading.Thread(target=work, daemon=True, name=f"signin-{provider}").start()
        return {"ok": True}

    def _save_session(self, provider: str, state: dict) -> None:
        _write_private(_state_file(provider), json.dumps(state))
        meta = self._meta(provider)
        meta.update({"saved_at": self.now(), "attention_until": 0, "reason": None})
        host = self._mail_host(state)
        if host:
            meta["mail_host"] = host
        self._save_meta(provider, meta)

    @staticmethod
    def _mail_host(state: dict) -> str | None:
        """Work/school accounts use outlook.office.com; personal ones outlook.live.com."""
        for o in state.get("origins") or []:
            h = urllib.parse.urlparse(str(o.get("origin", ""))).hostname
            if h in ("outlook.office.com", "outlook.live.com"):
                return h
        return None

    def wait_signin(self, provider: str, timeout: float = 5.0) -> None:   # for tests
        end = time.time() + timeout
        while time.time() < end and (self._signin.get(provider) or {}).get("state") in ("starting", "waiting", "saving"):
            time.sleep(0.01)
