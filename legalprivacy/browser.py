"""Real-browser transport: a genuine Chrome/Edge/Chromium driven like a person.

Why: a plain HTTP client fetches HTML only — no JavaScript, images or CSS, no
scrolling, and a TLS/HTTP2 fingerprint that is not a browser's no matter what
User-Agent it claims. Sites (and anyone watching traffic) can tell. Driving a
real browser gives the real network fingerprint plus everything HumanDriver does:
scrolling, reading pauses, mouse movement, clicking/tapping results, the
occasional file download (fetched and discarded, never written to disk).

Desktop personas use the browser's own, honest User-Agent (no spoofing, so the
header, JS navigator and TLS all agree). Mobile personas (~25%) get touch
emulation, a phone viewport and an Android UA built from the browser's real
major version, with matching client-hint metadata.

Optional: needs the `playwright` Python package and a Chromium-family browser.
If either is missing, legalPrivacy falls back to the plain HTTP transport.
"""
from __future__ import annotations

import glob
import os
import random
import re
import shutil
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from collections.abc import Callable

from .useragents import DEFAULT_DEVICE, MOBILE_DEVICES
from .humanize import HumanDriver, lognormal_clipped
from .transports import ClearnetTransport, HitResult, Target, Transport
from .paths import getenv

MULTI_TAB = True        # set from Settings (extras.multi_tab)
DESKTOP_VIEWPORTS = [((1920, 1080), 30), ((1536, 864), 14), ((1366, 768), 12), ((1440, 900), 9),
                     ((1280, 720), 8), ((2560, 1440), 7), ((1600, 900), 6), ((1280, 800), 5)]
MOBILE_VIEWPORTS = [((390, 844), 3.0, 30), ((412, 915), 2.625, 25), ((393, 873), 2.75, 20), ((360, 800), 3.0, 15)]
MOBILE_SHARE = 0.25
DOWNLOAD_EXT = (".pdf", ".zip", ".epub", ".csv", ".xlsx", ".docx", ".mp3")
MAX_DOWNLOAD = 8_000_000


def find_browser() -> str | None:
    """Locate a Chromium-family browser executable on this machine."""
    env = getenv("BROWSER")
    if env and Path(env).exists():
        return env
    cands: list[str] = []
    if sys.platform == "win32":
        for base in (os.environ.get("PROGRAMFILES", r"C:\Program Files"),
                     os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
                     os.environ.get("LOCALAPPDATA", "")):
            cands += [rf"{base}\Google\Chrome\Application\chrome.exe",
                      rf"{base}\Microsoft\Edge\Application\msedge.exe",
                      rf"{base}\BraveSoftware\Brave-Browser\Application\brave.exe",
                      rf"{base}\Chromium\Application\chrome.exe"]
    elif sys.platform == "darwin":
        cands += ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
                  "/Applications/Chromium.app/Contents/MacOS/Chromium"]
    else:
        for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
                     "microsoft-edge", "microsoft-edge-stable", "brave-browser"):
            p = shutil.which(name)
            if p:
                cands.append(p)
    # Playwright-managed Chromium (e.g. after `python -m playwright install chromium`)
    pw = os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or str(
        Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright" if sys.platform == "win32"
        else Path.home() / ("Library/Caches/ms-playwright" if sys.platform == "darwin" else ".cache/ms-playwright"))
    for pat in ("chromium-*/chrome-linux*/chrome", "chromium-*/chrome-mac*/Chromium.app/Contents/MacOS/Chromium",
                "chromium-*/chrome-win*/chrome.exe"):
        cands += sorted(glob.glob(os.path.join(pw, pat)), reverse=True)
    for c in cands:
        if c and Path(c).exists():
            return c
    return None


def find_playwright_firefox() -> str | None:
    """Playwright's own Firefox build (installed with `python -m playwright install firefox`).
    Playwright cannot drive an ordinary Firefox install, only this build."""
    bases = [os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")]
    home = Path.home()
    if sys.platform == "win32":
        bases.append(os.path.join(os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local")), "ms-playwright"))
        pats = ["firefox-*/firefox/firefox.exe"]
    elif sys.platform == "darwin":
        bases.append(str(home / "Library" / "Caches" / "ms-playwright"))
        pats = ["firefox-*/firefox/Nightly.app/Contents/MacOS/firefox"]
    else:
        bases.append(str(home / ".cache" / "ms-playwright"))
        pats = ["firefox-*/firefox/firefox"]
    for base in filter(None, bases):
        for pat in pats:
            hits = sorted(glob.glob(os.path.join(base, pat)))
            if hits:
                return hits[-1]
    return None


def browser_support() -> tuple[bool, str]:
    """(available, human-readable reason)."""
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False, "Python package 'playwright' is not installed (pip install playwright)"
    exe = find_browser()
    if not exe:
        return False, "No Chrome, Edge, Brave or Chromium found on this computer"
    return True, exe


class PlaywrightActuator:
    """Adapts a Playwright page to HumanDriver's Actuator protocol."""

    def __init__(self, page, mobile: bool, stop: threading.Event | None, cdp=None):
        self.page, self.mobile, self._stop, self.cdp = page, mobile, stop, cdp

    def viewport(self) -> tuple[int, int]:
        v = self.page.viewport_size or {"width": 1280, "height": 720}
        return v["width"], v["height"]

    # Many sites scroll an inner container instead of the page itself; measure whichever
    # element really scrolls, or depth would read 0%.
    _SCROLLER_JS = """() => {
      const se = document.scrollingElement || document.documentElement;
      if (se.scrollHeight > innerHeight + 40) return [se.scrollTop, se.scrollHeight];
      let best = null, bh = 0;
      for (const el of document.querySelectorAll('main, article, div, section')) {
        if (el.clientHeight < innerHeight * 0.5 || el.scrollHeight <= el.clientHeight + 40) continue;
        const oy = getComputedStyle(el).overflowY;
        if ((oy === 'auto' || oy === 'scroll') && el.scrollHeight > bh) { best = el; bh = el.scrollHeight; }
      }
      return best ? [best.scrollTop, best.scrollHeight] : [se.scrollTop, se.scrollHeight];
    }"""

    def _scroller(self) -> tuple[float, int]:
        try:
            y, hgt = self.page.evaluate(self._SCROLLER_JS)
            return float(y), int(hgt)
        except Exception:
            return 0.0, 0

    def page_height(self) -> int:
        return self._scroller()[1]

    def scroll_y(self) -> float:
        return self._scroller()[0]

    def move(self, x: float, y: float) -> None:
        self.page.mouse.move(x, y)

    def wheel(self, dy: float) -> None:
        self.page.mouse.wheel(0, dy)

    def swipe(self, dy: float) -> None:
        """A finger drag (real touch events; Chrome adds its own fling momentum)."""
        if self.cdp is None:
            self.page.mouse.wheel(0, dy)
            return
        w, h = self.viewport()
        x = w * random.uniform(0.35, 0.7)
        travel = max(-h * 0.7, min(h * 0.7, dy * random.uniform(0.55, 0.8)))
        if abs(travel) < 60:          # a very short finger movement would count as a tap on whatever is there
            travel = 60 if travel >= 0 else -60
        y0 = h * (0.72 if travel > 0 else 0.3) + random.uniform(-30, 30)
        n = random.randint(7, 13)
        self.cdp.send("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [{"x": x, "y": y0}]})
        for i in range(1, n + 1):
            t = i / n
            t = t * t * (3 - 2 * t)
            self.cdp.send("Input.dispatchTouchEvent", {"type": "touchMove", "touchPoints": [
                {"x": x + random.uniform(-2, 2) + 6 * t, "y": y0 - travel * t}]})
            self.page.wait_for_timeout(random.uniform(10, 22))
        self.cdp.send("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})

    def sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while not self.stopped():
            left = end - time.monotonic()
            if left <= 0:
                return
            self.page.wait_for_timeout(min(250, left * 1000))

    def select_text(self, x: float, y: float, dx: float) -> bool:
        """Press, drag across a line of plain text, release: only on text, never on a link,
        button or form field, so it can never click anything."""
        try:
            ok = self.page.evaluate(
                "([x, y]) => { const e = document.elementFromPoint(x, y); if (!e) return false;"
                " if (e.closest('a,button,input,select,textarea,label,summary,[onclick],[role=button],[contenteditable]')) return false;"
                " return ['P','SPAN','LI','H1','H2','H3','H4','TD','BLOCKQUOTE','ARTICLE','DIV'].includes(e.tagName)"
                " && (e.innerText || '').trim().length > 40; }", [x, y])
            if not ok:
                return False
            m = self.page.mouse
            m.down()
            for i in range(1, 9):
                m.move(x + dx * i / 8, y + (i % 3 - 1) * 0.6)
                time.sleep(0.03)
            m.up()
            return True
        except Exception:
            return False

    def stopped(self) -> bool:
        return bool(self._stop and self._stop.is_set())


def _site(host: str) -> str:
    """The site a host belongs to: news.example.co.uk -> example.co.uk, www.google.com -> google.com."""
    labels = (host or "").lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    two = ".".join(labels[-2:])
    if labels[-2] in ("co", "com", "org", "net", "ac", "gov", "edu") and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return two


def _born_file(jar: Path) -> Path:
    return jar.with_suffix(".born")


def _jar_born(jar: Path) -> tuple[float, float | None]:
    """(when this cookie jar was first created, its own lifetime in seconds if one was drawn).
    The wipe counts from creation, not from the last save."""
    try:
        parts = _born_file(jar).read_text().split()
        return float(parts[0]), (float(parts[1]) if len(parts) > 1 else None)
    except (OSError, ValueError, IndexError):
        return time.time(), None


class BrowserTransport(Transport):
    is_browser = True

    def __init__(self, proxy: str | None = None, headless: bool = True, executable: str | None = None,
                 stop_event: threading.Event | None = None, scale: Callable[[], float] = lambda: 1.0,
                 download_prob: float = 0.03, on_event: Callable[[str, str], None] | None = None,
                 rng: random.Random | None = None, low_data: bool = False, image_prob: float = 0.04,
                 offscreen: bool = False, engine: str = "chromium", cookie_hours: float = 1.0,
                 cookie_vary: bool = True):
        self.cookie_hours = max(0.0, float(cookie_hours or 0))   # 0 = forget cookies when a session ends
        self.cookie_vary = bool(cookie_vary)
        self.engine = engine if engine in ("chromium", "firefox") else "chromium"
        self.offscreen = offscreen and not headless and self.engine == "chromium"
        self.low_data = low_data
        self.image_prob = 0.0 if low_data else image_prob     # no images loaded in low-data mode
        self.proxy, self.headless = proxy, headless
        self.executable = executable or find_browser()
        self.stop_event, self.scale, self.download_prob = stop_event, scale, download_prob
        self.on_event = on_event or (lambda level, msg: None)
        self.rng = rng or random.Random()
        self.fallback = ClearnetTransport(proxy=proxy)     # DoH and anything non-page
        self.dimmed = False
        self._pw = self._browser = None
        self._sessions: dict[int, dict] = {}               # identity id -> {ctx, page, mobile, cdp}
        self._contexts: dict[tuple, object] = {}           # desktop / phone model -> browser context (tabs live in it)
        self._our_pages: set = set()
        self._expect_tab = False
        self._tab_seq = 0
        self._tabs: dict[int, object] = {}             # tab number -> page
        self._why: dict[int, str] = {}                  # tab number -> what the noise is doing in it right now
        self._burst_warned: dict[int, float] = {}
        from collections import deque
        self.nav_log = deque(maxlen=400)               # troubleshooting: every address change in every tab
        self._sent_to: dict[int, str] = {}             # tab number -> the site the noise last sent it to
        self.blocked_navs = 0
        self._major = "0"

    # ── lifecycle ──────────────────────────────────────────────────────────
    def _ensure(self) -> None:
        if self._browser is not None:
            return
        from playwright.sync_api import sync_playwright
        if self.engine == "firefox":
            # Firefox (Gecko): its own TLS/HTTP fingerprint, the same as people browsing with Firefox.
            self._pw = sync_playwright().start()
            try:
                self._browser = self._pw.firefox.launch(headless=self.headless,
                                                        proxy={"server": self.proxy} if self.proxy else None)
            except Exception:
                self._drop_driver()
                raise
            self._major = (self._browser.version or "0").split(".")[0]
            self.on_event("info", f"Real browser started: Firefox {self._browser.version}"
                                  f" ({'headless' if self.headless else 'visible'})")
            return
        if not self.executable:
            raise RuntimeError("no Chromium-family browser found")
        self._pw = sync_playwright().start()
        args = ["--disable-blink-features=AutomationControlled", "--no-default-browser-check",
                "--no-first-run", "--disable-background-networking"]
        args.append("--log-level=3")                       # the browser's own console chatter (dbus, update checks) stays out of ours
        exe = os.path.basename(str(self.executable or "")).lower()
        if "chromium" in exe or "headless" in exe:
            # A Chromium build has no Google API key, so its Safe Browsing list update is answered with HTTP 400 and
            # retried again and again ("returned a 400 during update request"). Harmless, and Google Chrome / Edge / Brave
            # (which have a key) are left alone because their update is what a real browser does.
            args.append("--safebrowsing-disable-auto-update")
        if self.offscreen:                                 # a real window, placed where no screen is
            args += ["--window-position=-32000,-32000", "--window-size=1366,850"]
        if getenv("NO_SANDBOX") == "1" or (hasattr(os, "geteuid") and os.geteuid() == 0):
            args.append("--no-sandbox")                    # Chromium refuses to sandbox as root
        try:
            self._browser = self._pw.chromium.launch(executable_path=self.executable, headless=self.headless,
                                                     args=args, proxy={"server": self.proxy} if self.proxy else None)
        except Exception:
            self._drop_driver()
            raise
        self._major = (self._browser.version or "0").split(".")[0]
        self.on_event("info", f"Real browser started: {Path(self.executable).name} {self._browser.version}"
                              f" ({'headless' if self.headless else 'off-screen window' if self.offscreen else 'visible'})")

    def _drop_driver(self) -> None:
        """A failed launch must not leave Playwright's driver process behind: every retry would start another."""
        try:
            if self._pw:
                self._pw.stop()
        except Exception:
            pass
        self._pw = self._browser = None

    def close(self) -> None:
        for s in list(self._sessions.values()):
            self._close_session(s)
        self._sessions.clear()
        for ctx in list(self._contexts.values()):
            try:
                ctx.close()
            except Exception:
                pass
        self._contexts.clear()
        for obj, meth in ((self._browser, "close"), (self._pw, "stop")):
            try:
                if obj:
                    getattr(obj, meth)()
            except Exception:
                pass
        self._browser = self._pw = None

    # ── cookies kept for a while (like a real browser), then wiped ──────────────
    def _jar(self, mobile: bool) -> Path:
        from .paths import app_dir
        return app_dir() / "browser" / f"cookies-{self.engine}-{'mobile' if mobile else 'desktop'}.json"

    def _lifetime(self) -> float:
        """Seconds a new jar lives: the setting, or 60-140% of it when 'vary' is on."""
        base = self.cookie_hours * 3600
        return base * random.uniform(0.6, 1.4) if self.cookie_vary else base

    def _load_jar(self, mobile: bool) -> str | None:
        if not self.cookie_hours:
            return None
        f = self._jar(mobile)
        try:
            born, life = _jar_born(f)
            life = life if life is not None else self.cookie_hours * 3600
            if f.exists() and time.time() - born > life:
                f.unlink(missing_ok=True)
                _born_file(f).unlink(missing_ok=True)
                self.on_event("info", f"Cleared the noise browser's cookies (kept {life / 3600:.1f} hours)")
                return None
            return str(f) if f.exists() else None
        except OSError:
            return None

    def _save_jar(self, s: dict) -> None:
        if not self.cookie_hours:
            return
        try:
            f = self._jar(bool(s.get("mobile")))
            f.parent.mkdir(parents=True, exist_ok=True)
            if not _born_file(f).exists():
                _born_file(f).write_text(f"{int(time.time())} {int(self._lifetime())}")
            s["ctx"].storage_state(path=str(f))
        except Exception:
            pass

    def _close_session(self, s: dict) -> None:
        """An identity retires: close its tab (the browser and its other tabs stay)."""
        self._save_jar(s)
        try:
            s["page"].close()
        except Exception:
            pass

    # Sites sometimes try to open new windows (pop-ups, links with target=_blank). The noise
    # stays in its own tab instead, and anything that opens anyway is closed straight away, so
    # no page ever runs without the identity's user agent.
    _NO_POPUPS_JS = """(() => {
        window.open = function () { return null; };
        document.addEventListener('click', e => {
            const a = e.target && e.target.closest && e.target.closest('a[target]');
            if (a) { a.setAttribute('target', '_self'); }
        }, true);
    })();"""

    def _context(self, key: tuple, make):
        """One browser context per kind of device: desktop, or one phone model. Identities are tabs in it."""
        ctx = self._contexts.get(key)
        if ctx is not None:
            return ctx
        ctx = make()
        ctx.add_init_script(self._NO_POPUPS_JS)
        try:
            from . import fingerprint
            ctx.add_init_script(fingerprint.init_script(fingerprint.seed_state()["seed"]))   # canvas, WebGL, fonts, audio
        except Exception:
            pass
        ours = self._our_pages

        def _stray(pg):
            if not self._expect_tab and pg not in ours:
                try:
                    pg.close()
                except Exception:
                    pass
        ctx.on("page", _stray)
        if self.low_data:              # optional: skip images, video and fonts to save data
            ctx.route("**/*", lambda route: route.abort()
                      if route.request.resource_type in ("image", "media", "font") else route.continue_())
        self._contexts[key] = ctx
        return ctx

    def _new_tab(self, ctx):
        """Open a tab in ctx, registered as ours before it can be mistaken for a pop-up."""
        self._expect_tab = True
        try:
            page = ctx.new_page()
        finally:
            self._expect_tab = False
        self._our_pages.add(page)
        self._tab_seq += 1
        tab = self._tab_seq
        self._tabs[tab] = page
        page.on("close", lambda pg: (self._our_pages.discard(pg), self._tabs.pop(tab, None)))

        def _nav(frame):
            if frame is not page.main_frame:
                return
            url = frame.url
            if not url.startswith("http"):
                return
            self._note_nav(tab, url)
        page.on("framenavigated", _nav)
        return page

    # ── troubleshooting: every address each tab shows, and why it changed ─────────
    def _note_nav(self, tab: int, url: str) -> None:
        now = time.time()
        why = self._why.get(tab) or "the page itself (redirect or script)"
        last = next((n for n in reversed(self.nav_log) if n["tab"] == tab), None)
        if last and last["url"] == url:
            return                                     # the same address again (a page updating itself)
        self.nav_log.append({"ts": now, "tab": tab, "url": url, "why": why})
        recent = [n for n in self.nav_log if n["tab"] == tab and now - n["ts"] <= 3]
        sites = {_site(urllib.parse.urlparse(n["url"]).hostname or "") for n in recent}
        if len(sites) >= 4 and now - self._burst_warned.get(tab, 0) > 30:
            self._burst_warned[tab] = now
            self.on_event("warn", f"Tab {tab} went through {len(sites)} different sites in 3 seconds: "
                          + " → ".join(f"{urllib.parse.urlparse(n['url']).hostname} ({n['why']})" for n in recent))

    def _tab_of(self, page) -> int | None:
        return next((k for k, pg in self._tabs.items() if pg is page), None)

    def _doing(self, page, why: str | None, target_url: str | None = None) -> None:
        """Mark what the noise itself is doing in a tab, so the trace can tell it from the page's own moves.
        While it's set, the tab may go anywhere (redirects of the page it was sent to); once cleared, only
        within the site it's on, or to the site it was sent to."""
        tab = self._tab_of(page)
        if tab is None:
            return
        if why:
            self._why[tab] = why
            if target_url:
                self._sent_to[tab] = _site(urllib.parse.urlparse(target_url).hostname or "")
        else:
            self._why.pop(tab, None)

    def _guard_tab(self, page, cdp) -> None:
        """Stop a page from sending its tab somewhere else on its own.

        Some sites (mostly through their ads) redirect the whole tab through a chain of other sites a
        moment after loading, or open an ad when the page is touched. A person would never ask for that,
        so once a page has loaded, the tab may only move within that site (or to the site the noise was
        going to); anything else is blocked and noted in the log. Only page loads are checked, through
        DevTools, so the browser's cache and everything else work as usual."""
        tab = self._tab_of(page)
        try:
            main = cdp.send("Page.getFrameTree")["frameTree"]["frame"]["id"]
        except Exception:
            return

        def paused(ev):
            rid = ev.get("requestId")
            url = (ev.get("request") or {}).get("url", "")
            block = False
            if ev.get("frameId") == main and tab not in self._why and url.startswith("http"):
                to = _site(urllib.parse.urlparse(url).hostname or "")
                here = _site(urllib.parse.urlparse(page.url).hostname or "")
                block = bool(to) and to not in (here, self._sent_to.get(tab))
            try:
                if block:
                    # "No content": the browser stays on the page it's on, as if nothing happened
                    cdp.send("Fetch.fulfillRequest", {"requestId": rid, "responseCode": 204, "responseHeaders": []})
                    self.blocked_navs += 1
                    self.nav_log.append({"ts": time.time(), "tab": tab, "url": url,
                                         "why": "blocked: the page tried to send the tab to another site"})
                    self.on_event("info", f"Blocked {urllib.parse.urlparse(page.url).hostname} from sending the "
                                          f"tab to {urllib.parse.urlparse(url).hostname} (an ad or redirect)")
                else:
                    cdp.send("Fetch.continueRequest", {"requestId": rid})
            except Exception:
                pass
        cdp.on("Fetch.requestPaused", paused)
        cdp.send("Fetch.enable", {"patterns": [{"resourceType": "Document", "requestStage": "Request"}]})

    def _ua_override(self, identity, mobile: bool, ios: bool, lang: str) -> dict:
        """The identity's own user agent, with client hints that agree with it.

        Chromium-family user agents get a matching brand list; Firefox and Safari send no client
        hints at all, so for those none are sent either."""
        ua = getattr(identity, "user_agent", "") or ""
        plat = getattr(identity, "platform", "") or ("Android" if mobile else "Windows")
        nav = {"Windows": "Win32", "macOS": "MacIntel", "Linux": "Linux x86_64", "Android": "Linux armv8l",
               "iOS": "iPhone", "Chrome OS": "Linux x86_64"}.get(plat, "Win32")
        if ios or "iPhone" in ua:
            return {"userAgent": ua, "acceptLanguage": lang, "platform": "iPhone"}
        m = re.search(r"Chrome/(\d+)", ua)
        if not m or "Firefox/" in ua or not getattr(identity, "chromium", True):
            return {"userAgent": ua, "acceptLanguage": lang, "platform": nav}
        major = m.group(1)
        brand = ("Microsoft Edge" if "Edg/" in ua else "Opera" if "OPR/" in ua
                 else None if "Chromium/" in ua else "Google Chrome")
        brands = [{"brand": "Not_A Brand", "version": "8"}, {"brand": "Chromium", "version": major}]
        if brand:
            brands.append({"brand": brand, "version": major})
        return {"userAgent": ua, "acceptLanguage": lang, "platform": nav, "userAgentMetadata": {
            "brands": brands, "platform": plat, "platformVersion": "", "architecture": "" if mobile else "x86",
            "model": "", "mobile": bool(mobile)}}

    def _session(self, identity) -> dict:
        key = getattr(identity, "id", 0)
        s = self._sessions.get(key)
        if s:
            return s
        while len(self._sessions) >= 2:                    # an identity retires: close its tab
            old_key = next(iter(self._sessions))
            self._close_session(self._sessions.pop(old_key))
        rng = random.Random(f"{key}-{id(self)}")
        # The identity decides: phone (and which phone) or desktop. Older identities without
        # that information fall back to a random share.
        mobile = bool(identity.mobile) if hasattr(identity, "mobile") else rng.random() < MOBILE_SHARE
        if self.engine == "firefox":
            mobile = False          # Playwright's Firefox can't emulate a phone; those visits run as desktop
        device_name = getattr(identity, "device", "") or ""
        device = MOBILE_DEVICES.get(device_name)
        ios = bool(mobile and "iPhone" in (getattr(identity, "user_agent", "") or ""))
        if mobile and device is None:
            device_name = DEFAULT_DEVICE if ios else "Pixel 7"
            device = MOBILE_DEVICES[device_name]
        lang = (getattr(identity, "accept_language", "") or "en-US").split(",")[0]
        ua = getattr(identity, "user_agent", "") or None
        if self.engine == "firefox":
            # Firefox has no DevTools user-agent override: the user agent is set on the context instead.
            ctx = self._context(("firefox", ua), lambda: self._browser.new_context(
                user_agent=ua, locale=lang, storage_state=self._load_jar(False)))
        elif mobile:
            (w, h), dpr = device["viewport"], device["dpr"]
            # No user_agent here: Playwright's own override keeps "HeadlessChrome" client hints
            # and a Linux navigator.platform. The DevTools override below sets everything per tab.
            ctx = self._context(("phone", device_name), lambda: self._browser.new_context(
                viewport={"width": w, "height": h}, device_scale_factor=dpr, is_mobile=True, has_touch=True,
                locale=lang, storage_state=self._load_jar(True)))
        else:
            ctx = self._context(("desktop",), lambda: self._browser.new_context(
                locale=lang, storage_state=self._load_jar(False)))
        page = self._new_tab(ctx)
        if not mobile:
            from . import fingerprint
            w, h = fingerprint.window_size(fingerprint.seed_state()["seed"])      # not maximised; steady for hours
            w += rng.choice([0, 0, 8]); vh = h - 85          # browser chrome eats some height
            try:
                page.set_viewport_size({"width": w, "height": vh})
            except Exception:
                pass
        counter = {"bytes": 0}
        try:
            page.on("response", lambda r: counter.__setitem__(
                "bytes", counter["bytes"] + int(r.headers.get("content-length") or 0)))
        except Exception:
            pass
        try:                                   # label this address in the Proof tab's network map
            def _learn(r):
                try:
                    sa = r.server_addr()
                    if sa:
                        from .observe import note
                        note(sa.get("ipAddress", ""), urllib.parse.urlparse(r.url).hostname or "")
                except Exception:
                    pass
            page.on("response", _learn)
        except Exception:
            pass
        cdp = None
        if self.engine == "chromium":
            # Always the identity's own user agent, never the browser's: if it can't be set, the tab
            # is closed and nothing is visited with it.
            try:
                cdp = ctx.new_cdp_session(page)
                cdp.send("Emulation.setUserAgentOverride", self._ua_override(identity, mobile, ios, lang))
                try:
                    self._guard_tab(page, cdp)
                except Exception:
                    pass
            except Exception as exc:
                try:
                    page.close()
                except Exception:
                    pass
                raise RuntimeError(f"couldn't set the user agent: {exc}") from exc
        s = {"ctx": ctx, "page": page, "mobile": mobile, "cdp": cdp, "last_url": None, "counter": counter}
        self._sessions[key] = s
        return s

    # ── a hit ──────────────────────────────────────────────────────────────
    def hit(self, identity, target: Target) -> HitResult:
        if target.kind != "html":
            return self.fallback.hit(identity, target)
        try:
            self._ensure()
            s = self._session(identity)
        except Exception as exc:
            return HitResult(None, error=f"browser unavailable: {exc}")
        page, mobile = s["page"], s["mobile"]
        act = PlaywrightActuator(page, mobile, self.stop_event, s["cdp"])
        bytes_before = s.get("counter", {}).get("bytes", 0)
        driver = HumanDriver(self.rng, act, scale=self.scale())
        how = "open"
        if target.role == "chat" and target.script:
            return self._chat_hit(page, driver, target, s)
        try:
            resp = None
            t_load = time.time()
            from_serp = target.role == "result" and target.referer and s.get("serp_ref") == target.referer
            if from_serp and not s.get("on_serp"):
                try:                                           # back to the results, like pressing Back
                    driver.pause(lognormal_clipped(driver.rng, 1.2, 0.5, 0.4, 4))
                    self._doing(page, "noise: back to the results")
                    page.go_back(wait_until="domcontentloaded", timeout=15000)
                    s["on_serp"] = True
                    driver.pause(lognormal_clipped(driver.rng, 2.5, 0.5, 0.8, 8))   # re-scan the list
                except Exception:
                    pass
            if (from_serp and s.get("on_serp")) or \
                    (target.role == "result" and target.referer and s["last_url"] == target.referer):
                resp, how = self._click_through(page, driver, target, mobile)
            if resp is None and how == "open":
                self._doing(page, f"noise: open ({target.role})", target.url)
                resp = page.goto(target.url, referer=target.referer, wait_until="domcontentloaded",
                                 timeout=int(target.timeout * 1000))
            load_ms = (time.time() - t_load) * 1000.0
            self._doing(page, None)              # from here on, address changes are the page's own
            status = resp.status if resp is not None else 200
            title = (page.title() or "").lower()
            if ("/sorry/" in page.url or "captcha" in page.url.lower()
                    or any(t in title for t in ("captcha", "unusual traffic", "are you a robot", "just a moment",
                                                "access denied", "attention required"))
                    or (status == 202 and "duckduckgo" in page.url)):
                status = 429          # a bot check: back off instead of counting it as a visit
            walled = foreign = False
            if status < 400 and target.role != "search":
                try:
                    lang = (page.evaluate("() => document.documentElement.lang || ''") or "").lower()[:2]
                except Exception:
                    lang = ""
                foreign = bool(lang) and lang != "en"
                from .loginwall import looks_like_login_wall
                try:
                    probe = page.evaluate(
                        "() => [[...document.querySelectorAll('input[type=password]')].filter(e => e.offsetParent).length,"
                        " (document.body ? document.body.innerText : '').slice(0, 3000)]")
                except Exception:
                    probe = [0, ""]
                walled = looks_like_login_wall(page.url, title, probe[1], password_fields=probe[0])
            side = None
            if not (walled or foreign) and target.role != "search":
                side = self._open_side_tab(page, mobile)            # now and then a link is opened in a second tab, as people do
            try:
                if walled or foreign:     # needs an account, or not in English: a quick glance, then elsewhere
                    stats = driver.browse(dwell=self.rng.uniform(2, 6))
                else:
                    stats = driver.serp() if target.role == "search" else driver.browse()
            finally:
                if side is not None:
                    self._glance_and_close(side, page, mobile)
            downloaded = None if walled or foreign else (self._maybe_download(page) or self._maybe_save_image(page))
            s["last_url"] = page.url
            s["on_serp"] = target.role == "search"
            if target.role == "search":
                s["serp_ref"] = target.url
            html = "" if walled or foreign else page.content()[:2_000_000]   # never follow links off these
            parts = [f"{how} {'📱' if mobile else '🖥'}", f"{stats['scrolls']} scrolls",
                     f"{int(stats['depth'] * 100)}% depth", f"{stats['seconds']:.0f}s on page"]
            if stats.get("serp"):
                parts.insert(1, f"results: {stats['serp']}")
            if walled:
                parts.insert(1, "login required: moved on")
            elif foreign:
                parts.insert(1, "not in English: moved on")
            if stats["back_scrolls"]:
                parts.append(f"{stats['back_scrolls']} scroll-back")
            if stats.get("selections"):
                parts.append(f"{stats['selections']} text selected")
            if downloaded:
                parts.append(downloaded)
            self.on_event("debug", f"{urllib.parse.urlparse(page.url).hostname}: " + ", ".join(parts))
            res = HitResult(status, html)
            res.detail = ", ".join(parts)
            res.load_ms = load_ms
            res.login_wall = walled
            res.foreign = foreign
            res.final_url = page.url
            res.on_page_s = stats["seconds"]
            # content-length is missing for some compressed responses, so this is a floor
            res.bytes = max(len(html), s.get("counter", {}).get("bytes", 0) - bytes_before)
            return res
        except Exception as exc:
            msg = str(exc).splitlines()[0][:200]
            if "Target page, context or browser has been closed" in msg:
                self._sessions.pop(getattr(identity, "id", 0), None)
                self._contexts = {k: c for k, c in self._contexts.items() if c is not s.get("ctx")}
            return HitResult(None, error=msg)

    def _chat_hit(self, page, driver: HumanDriver, target: Target, s: dict) -> HitResult:
        """A short chat on a chat site (duck.ai): open it, type each message like a person, wait for the reply to finish
        streaming, read it, then the next message. The messages are made up from a topic (never from you). The site's
        terms screen is clicked through only when the user switched chat noise on (target.accept_terms)."""
        t0 = time.time()
        sc = self.scale()
        try:
            page.goto(target.url, wait_until="domcontentloaded", timeout=int(target.timeout * 1000))
            box = page.locator("textarea").first
            try:
                box.wait_for(state="visible", timeout=15000)
            except Exception:
                return HitResult(None, error="the chat box did not appear")
            self._doing(page, None)
            if not self._consent(page, target.accept_terms):
                driver.browse(dwell=self.rng.uniform(3, 8))
                res = HitResult(200, "")
                res.detail, res.final_url, res.load_ms = "chat not started: its terms screen needs your OK", page.url, 0.0
                return res
            sent = pics = 0
            for i, msg in enumerate(target.script or []):
                if self._stopped():
                    break
                driver.pause(lognormal_clipped(self.rng, 2.0 if i == 0 else 4.0, 0.5, 0.8, 15))     # think about what to ask
                box = page.locator("textarea").first
                box.click()
                if target.images and i > 0 and self.rng.random() < 0.3 and self._attach_picture(page):
                    from .chatpics import PICTURE_QUESTIONS
                    msg = self.rng.choice(PICTURE_QUESTIONS)               # a question about the picture just attached
                    pics += 1
                    box = page.locator("textarea").first
                    box.click()
                self._type_like_a_person(page, msg, sc)
                page.keyboard.press("Enter")
                sent += 1
                self._wait_for_reply(page, sc)
                driver.pause(lognormal_clipped(self.rng, 6.0, 0.6, 2.0, 40))                          # read the answer
            res = HitResult(200, "")
            res.detail = f"chat: {sent} message{'s' if sent != 1 else ''}" + (f", {pics} with a picture" if pics else "")
            res.final_url, res.load_ms = page.url, (time.time() - t0) * 1000.0
            res.on_page_s = time.time() - t0
            res.bytes = 0
            return res
        except Exception as exc:
            return HitResult(None, error=str(exc).splitlines()[0][:200])

    def _stopped(self) -> bool:
        return bool(self.stop_event is not None and self.stop_event.is_set())

    def _attach_picture(self, page) -> bool:
        """Attach a made-up picture through the page's own file button, if it has one (nothing is invented if it does not:
        no file input, no picture). The picture is built in memory (chatpics.py); nothing of yours is read."""
        try:
            fin = page.locator("input[type=file]")
            if not fin.count():
                return False
            from .chatpics import make_png
            fin.first.set_input_files({"name": f"IMG_{self.rng.randrange(1000, 9999)}.png", "mimeType": "image/png",
                                       "buffer": make_png(self.rng)})
            page.wait_for_timeout(int(self.rng.uniform(900, 2200) * max(self.scale(), 0.05)))      # the preview appears
            return True
        except Exception:
            return False

    def _consent(self, page, accept: bool) -> bool:
        """True when nothing blocks the chat (or the terms screen was accepted because the user said so)."""
        try:
            btn = page.get_by_role("button", name=re.compile(r"^(continue|agree and continue|i agree)$", re.I))
            if btn.count() and btn.first.is_visible():
                if not accept:
                    return False
                btn.first.click()
                page.wait_for_timeout(int(800 * self.scale() + 200))
        except Exception:
            pass
        return True

    def _type_like_a_person(self, page, text: str, scale: float) -> None:
        for ch in text:
            page.keyboard.type(ch, delay=0)
            d = self.rng.lognormvariate(-2.6, 0.45) * scale           # about 70 ms a key, with a slow tail
            if ch in " ,." and self.rng.random() < 0.08:
                d += self.rng.uniform(0.2, 0.7) * scale               # a pause between words
            page.wait_for_timeout(int(max(5, d * 1000)))

    def _wait_for_reply(self, page, scale: float, limit: float = 90.0) -> None:
        """The reply is done when the page stops changing for a few seconds (or after `limit` seconds)."""
        end, last, still = time.time() + limit * max(scale, 0.05), -1, 0
        while time.time() < end and not self._stopped():
            page.wait_for_timeout(int(600 * max(scale, 0.05) + 100))
            n = page.evaluate("() => document.body.innerText.length")
            still = still + 1 if n == last else 0
            if still >= 4:
                return
            last = n

    def _open_side_tab(self, page, mobile: bool):
        """About one visit in eight on a desktop: open a link of this page in a second tab (it loads while you read the first)."""
        if mobile or not MULTI_TAB or self.rng.random() > 0.12:
            return None
        try:
            hrefs = page.evaluate(
                "() => [...document.querySelectorAll('a[href]')].filter(a => a.offsetParent && a.origin === location.origin"
                " && a.pathname !== location.pathname && !a.hasAttribute('download')).map(a => a.href).slice(0, 40)")
            if not hrefs:
                return None
            side = self._new_tab(page.context)
            side.goto(self.rng.choice(hrefs), referer=page.url, wait_until="domcontentloaded", timeout=15000)
            page.bring_to_front()
            return side
        except Exception:
            return None

    def _glance_and_close(self, side, page, mobile: bool) -> None:
        """Switch to the second tab, look at it for a few seconds, close it and go back to the first."""
        try:
            side.bring_to_front()
            HumanDriver(self.rng, PlaywrightActuator(side, mobile, self.stop_event, None),
                        scale=self.scale()).browse(dwell=self.rng.uniform(3, 9))
        except Exception:
            pass
        finally:
            try:
                side.close()
                page.bring_to_front()
            except Exception:
                pass

    def _click_through(self, page, driver: HumanDriver, target: Target, mobile: bool):
        """Find the result's link on the results page and click (or tap) it like a person."""
        host = urllib.parse.urlparse(target.url).hostname or ""
        bare = host.removeprefix("www.")
        try:
            loc = page.locator(f'a[href*="{bare}"]').first
            if loc.count() == 0:
                return None, "open"
            loc.evaluate("el => el.removeAttribute('target')")     # stay in this tab
            loc.scroll_into_view_if_needed(timeout=3000)
            box = loc.bounding_box()
            if not box:
                return None, "open"
            x = box["x"] + box["width"] * driver.rng.uniform(0.2, 0.7)
            y = box["y"] + box["height"] * driver.rng.uniform(0.3, 0.7)
            driver.hover_then_click_point(x, y)
            self._doing(page, "noise: click a result", target.url)
            with page.expect_navigation(wait_until="domcontentloaded", timeout=int(target.timeout * 1000)) as nav:
                if mobile:
                    page.touchscreen.tap(x, y)
                else:
                    page.mouse.click(x, y, delay=int(lognormal_clipped(driver.rng, 90, 0.4, 40, 250)))
            return nav.value, ("tap" if mobile else "click")
        except Exception:
            return None, "open"

    # Page JavaScript fetch() goes out through the browser's own network stack (its TLS and
    # HTTP/2 fingerprint, cookies, cache). Playwright's context.request would not: it is a
    # separate HTTP client with its own fingerprint, so it is not used for noise.
    _FETCH_JS = """async ([u, cap, cors]) => {
        const ac = new AbortController(); const t = setTimeout(() => ac.abort(), 30000);
        try {
            const r = await fetch(u, {credentials: 'include', mode: cors ? 'cors' : 'no-cors', signal: ac.signal});
            if (r.type === 'opaque') { return [0, -1]; }            // cross-site image: fetched, size hidden
            const n = +(r.headers.get('content-length') || 0);
            if (n > cap) { ac.abort(); return [r.status, n]; }
            const b = await r.arrayBuffer(); return [r.status, b.byteLength];
        } catch (e) { return [-1, 0]; } finally { clearTimeout(t); }
    }"""

    def _maybe_download(self, page) -> str | None:
        """Occasionally fetch a linked document (same site) the way the browser would, then discard it."""
        if self.rng.random() >= self.download_prob:
            return None
        try:
            hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        except Exception:
            return None
        host = urllib.parse.urlparse(page.url).hostname
        files = [h for h in hrefs if urllib.parse.urlparse(h).hostname == host
                 and urllib.parse.urlparse(h).path.lower().endswith(DOWNLOAD_EXT)]
        if not files:
            return None
        url = self.rng.choice(files)
        try:
            status, size = page.evaluate(self._FETCH_JS, [url, MAX_DOWNLOAD, True])
        except Exception:
            return None
        if status < 0:
            return None
        return f"downloaded {Path(urllib.parse.urlparse(url).path).name} ({max(size, 0) // 1024} KB, discarded)"

    def _maybe_save_image(self, page) -> str | None:
        """Now and then 'save' a picture from the page: fetch it again through the browser, discard it."""
        if self.rng.random() >= self.image_prob:
            return None
        try:
            srcs = page.eval_on_selector_all(
                "img", "els => els.filter(e => e.naturalWidth >= 200 && e.naturalHeight >= 150"
                       " && /^https?:/.test(e.currentSrc || e.src)).map(e => e.currentSrc || e.src)")
        except Exception:
            return None
        if not srcs:
            return None
        src = self.rng.choice(srcs)
        same = urllib.parse.urlparse(src).hostname == urllib.parse.urlparse(page.url).hostname
        try:
            status, _ = page.evaluate(self._FETCH_JS, [src, MAX_DOWNLOAD, same])
        except Exception:
            return None
        return "saved an image (discarded)" if status >= 0 else None


class MixedBrowserTransport:
    """Uses every real browser that was found, one per identity: Firefox-style identities go to Firefox,
    the rest to Chromium. A single identity always stays in one engine, so its fingerprint never flips."""
    is_browser = True

    def __init__(self, chromium: "BrowserTransport", firefox: "BrowserTransport | None"):
        self.chromium, self.firefox = chromium, firefox

    def _pick(self, identity) -> "BrowserTransport":
        wants_firefox = not getattr(identity, "chromium", True) and "Firefox/" in (getattr(identity, "user_agent", "") or "")
        return self.firefox if (wants_firefox and self.firefox) else self.chromium

    def hit(self, identity, target):
        return self._pick(identity).hit(identity, target)

    @property
    def dimmed(self) -> bool:
        return self.chromium.dimmed and (self.firefox is None or self.firefox.dimmed)

    @dimmed.setter
    def dimmed(self, v: bool) -> None:
        self.chromium.dimmed = v
        if self.firefox:
            self.firefox.dimmed = v

    def close(self) -> None:
        for t in (self.chromium, self.firefox):
            if t:
                t.close()

    def __getattr__(self, name):               # nav_log, blocked_navs, ... come from the main (Chromium) one
        return getattr(self.__dict__["chromium"], name)
