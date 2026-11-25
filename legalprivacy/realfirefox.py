"""Browse with YOUR Firefox: the real program, with a copy of your settings, add-ons and bookmarks.

A blank browser looks like a blank browser. To look like you, the noise browser is your own installed
Firefox, started with a private COPY of your profile:

  copied   settings (prefs.js, user.js), add-ons and their settings, search engines, bookmarks,
           site-specific styling (userChrome)
  never    cookies, saved logins and passwords, form history, history of visited pages, sessions, caches
           (your bookmarks keep their places, but the list of pages you visited is wiped from the copy)

Your real profile is only read, never written, and never opened by the noise: Firefox locks a profile
while it is in use, and noise visits must not end up in your own history. The copy lives in the app's own
folder and is thrown away when the noise browser closes.

Firefox is driven with Selenium and geckodriver (Playwright's Firefox is a patched build, not yours).
Not supported: Firefox installed as a Snap or Flatpak (their sandboxes block this); the app says so and
falls back to its own browsers.
"""
from __future__ import annotations

import configparser
import random
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable

from .humanize import HumanDriver
from .transports import ClearnetTransport, HitResult, Target

# What is copied from the profile folder (file or folder names). Everything else is left behind.
COPY_FILES = ("prefs.js", "user.js", "handlers.json", "containers.json", "search.json.mozlz4", "extensions.json",
              "extension-settings.json", "extension-preferences.json", "xulstore.json", "compatibility.ini")
COPY_DIRS = ("extensions", "browser-extension-data", "chrome")
NEVER = ("cookies.sqlite", "logins.json", "logins-backup.json", "key4.db", "cert9.db", "formhistory.sqlite",
         "sessionstore.jsonlz4", "sessionstore-backups", "storage", "cache2", "saved-telemetry-pings")


def find_firefox() -> tuple[str | None, str]:
    """(path, why-not). The system Firefox, or None with the reason it can't be used."""
    cands = [shutil.which("firefox")]
    if sys.platform == "win32":
        cands += [r"C:\Program Files\Mozilla Firefox\firefox.exe", r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"]
    elif sys.platform == "darwin":
        cands += ["/Applications/Firefox.app/Contents/MacOS/firefox"]
    else:
        cands += ["/usr/bin/firefox", "/usr/lib/firefox/firefox", "/opt/firefox/firefox", "/usr/local/bin/firefox"]
    for c in cands:
        if c and Path(c).exists():
            real = str(Path(c).resolve())
            if "/snap/" in real or "/snap/" in c or "flatpak" in real:
                return None, "Firefox from Snap or Flatpak can't be driven (its sandbox blocks it); install Mozilla's own build"
            return real, ""
    return None, "Firefox isn't installed"


def default_profile() -> Path | None:
    """The profile your Firefox uses day to day (the one marked default in profiles.ini)."""
    from .history import _firefox_bases
    best, best_size = None, -1
    for base in _firefox_bases():
        root = Path(base)
        ini = root / "profiles.ini"
        if not ini.exists():
            ini = root.parent / "profiles.ini"
        if ini.exists():
            cp = configparser.RawConfigParser()
            try:
                cp.read(ini, encoding="utf-8")
            except configparser.Error:
                continue
            for sec in cp.sections():
                if sec.startswith("Install") and cp.has_option(sec, "Default"):
                    p = Path(cp.get(sec, "Default"))
                    p = p if p.is_absolute() else ini.parent / p
                    if p.is_dir():
                        return p
            for sec in cp.sections():
                if cp.has_option(sec, "Default") and cp.get(sec, "Default") == "1" and cp.has_option(sec, "Path"):
                    p = Path(cp.get(sec, "Path"))
                    p = p if cp.get(sec, "IsRelative", fallback="1") == "0" else ini.parent / p
                    if p.is_dir():
                        return p
        for places in root.glob("*/places.sqlite"):                    # no ini: the profile with the most in it
            try:
                size = places.stat().st_size
            except OSError:
                continue
            if size > best_size:
                best, best_size = places.parent, size
    return best


def _copy_bookmarks(src: Path, dst: Path) -> None:
    """Bookmarks (and the places they point at) without the list of pages you visited."""
    uri = f"file:{src}?mode=ro&immutable=1"
    try:
        s = sqlite3.connect(uri, uri=True, timeout=5)
    except sqlite3.Error:
        return
    try:
        d = sqlite3.connect(str(dst))
        try:
            s.backup(d)
            for stmt in ("DELETE FROM moz_historyvisits", "DELETE FROM moz_inputhistory",
                         "UPDATE moz_places SET visit_count = 0, last_visit_date = NULL, frecency = -1"):
                try:
                    d.execute(stmt)
                except sqlite3.Error:
                    pass
            d.commit()
            try:
                d.execute("VACUUM")
            except sqlite3.Error:
                pass
        finally:
            d.close()
    except sqlite3.Error:
        dst.unlink(missing_ok=True)
    finally:
        s.close()


def copy_profile(src: Path, dst: Path) -> list[str]:
    """Copy the parts of a Firefox profile that make the browser look like yours. Returns what was copied."""
    dst.mkdir(parents=True, exist_ok=True)
    done = []
    for name in COPY_FILES:
        f = src / name
        if f.is_file():
            shutil.copy2(f, dst / name)
            done.append(name)
    for name in COPY_DIRS:
        d = src / name
        if d.is_dir():
            shutil.copytree(d, dst / name, dirs_exist_ok=True, ignore=shutil.ignore_patterns(*NEVER, "*.lock", "lock"))
            done.append(name + "/")
    if (src / "places.sqlite").is_file():
        _copy_bookmarks(src / "places.sqlite", dst / "places.sqlite")
        if (dst / "places.sqlite").exists():
            done.append("bookmarks")
    return done


class SeleniumActuator:
    """Adapts a Selenium Firefox to HumanDriver's Actuator protocol (a desktop browser)."""
    mobile = False

    def __init__(self, driver, stop: threading.Event | None):
        self.d, self._stop = driver, stop

    def viewport(self) -> tuple[int, int]:
        try:
            w, h = self.d.execute_script("return [window.innerWidth, window.innerHeight]")
            return int(w), int(h)
        except Exception:
            return 1280, 720

    def page_height(self) -> int:
        try:
            return int(self.d.execute_script("return document.documentElement.scrollHeight"))
        except Exception:
            return 0

    def scroll_y(self) -> float:
        try:
            return float(self.d.execute_script("return window.scrollY"))
        except Exception:
            return 0.0

    def move(self, x: float, y: float) -> None:
        try:
            from selenium.webdriver.common.actions.action_builder import ActionBuilder
            ActionBuilder(self.d).pointer_action.move_to_location(int(x), int(y)).perform()
        except Exception:
            pass

    def wheel(self, dy: float) -> None:
        try:
            from selenium.webdriver import ActionChains
            ActionChains(self.d).scroll_by_amount(0, int(dy)).perform()
        except Exception:
            try:
                self.d.execute_script("window.scrollBy(0, arguments[0])", int(dy))
            except Exception:
                pass

    def sleep(self, seconds: float) -> None:
        if self._stop is not None:
            self._stop.wait(max(0.0, seconds))
        else:
            time.sleep(max(0.0, seconds))

    def stopped(self) -> bool:
        return bool(self._stop and self._stop.is_set())


class RealFirefoxTransport:
    """The clearnet lane's browser: your own Firefox, started on a copy of your profile."""
    is_browser = True

    def __init__(self, firefox: str, profile: Path, proxy: str | None = None, headless: bool = True,
                 stop_event: threading.Event | None = None, scale: Callable[[], float] = lambda: 1.0,
                 on_event: Callable[[str, str], None] | None = None, rng: random.Random | None = None,
                 cookie_hours: float = 1.0, driver_factory=None, alt_factory=None):
        self.firefox, self.profile_src, self.proxy, self.headless = firefox, Path(profile), proxy, headless
        self.stop_event, self.scale, self.cookie_hours = stop_event, scale, max(0.0, float(cookie_hours or 0))
        self.on_event = on_event or (lambda level, msg: None)
        self.rng = rng or random.Random()
        self.dimmed = False
        self.fallback = ClearnetTransport(proxy=proxy)           # DoH and anything that isn't a page
        self.nav_log: deque = deque(maxlen=400)
        self.blocked_navs = 0
        self.user_agent: str | None = None
        self._driver = None
        self._copy: Path | None = None
        self._cookies_at = time.time()
        self._factory = driver_factory
        self._alt_factory, self._alt = alt_factory, None       # the app's own browser, if yours can't be started
        self._other = None       # the app's own browsers for identities that are not "you" (another UA, a phone)

    # ── lifecycle ──────────────────────────────────────────────────────────
    def _ensure(self) -> None:
        if self._driver is not None:
            return
        self._copy = Path(tempfile.mkdtemp(prefix="lp-firefox-"))
        done = copy_profile(self.profile_src, self._copy)
        if self._factory is not None:
            self._driver = self._factory(self._copy)
        else:
            from selenium import webdriver
            from selenium.webdriver.firefox.options import Options
            opts = Options()
            opts.binary_location = self.firefox
            opts.add_argument("--no-remote")          # no desktop-bus "remote" listener (it complains when stopped)
            if self.headless:
                opts.add_argument("-headless")
            opts.profile = webdriver.FirefoxProfile(str(self._copy))
            if self.proxy:
                opts.set_preference("network.proxy.type", 1)
            self._driver = webdriver.Firefox(options=opts)
        try:                                          # never maximised and never your real screen size
            from . import fingerprint
            w, h = fingerprint.window_size(fingerprint.seed_state()["seed"])
            self._driver.set_window_size(w, h)
        except Exception:
            pass
        try:
            self.user_agent = self._driver.execute_script("return navigator.userAgent")
        except Exception:
            self.user_agent = None
        self.on_event("info", f"Your Firefox started on a private copy of your profile ({', '.join(done) or 'no settings found'}). "
                              f"Logins, cookies and history were not copied.")

    def close(self) -> None:
        if self._alt is not None and hasattr(self._alt, "close"):
            self._alt.close()
        if self._other is not None and hasattr(self._other, "close"):
            self._other.close()
        d, self._driver = self._driver, None
        if d is not None:
            try:
                d.quit()
            except Exception:
                pass
        if self._copy is not None:
            shutil.rmtree(self._copy, ignore_errors=True)                    # the copy never outlives the browser
            self._copy = None

    # ── a hit ──────────────────────────────────────────────────────────────
    @staticmethod
    def _status(d) -> int:
        try:
            s = d.execute_script("const n = performance.getEntriesByType('navigation')[0]; return n ? n.responseStatus : 0")
            return int(s) or 200
        except Exception:
            return 200

    def _click_through(self, d, hd: HumanDriver, target: Target) -> bool:
        """Click the result on the search page we are still on, like a person (False: open the address instead)."""
        import urllib.parse
        bare = (urllib.parse.urlparse(target.url).hostname or "").removeprefix("www.")
        try:
            from selenium.webdriver import ActionChains
            from selenium.webdriver.common.by import By
            links = d.find_elements(By.CSS_SELECTOR, f'a[href*="{bare}"]')
            if not bare or not links:
                return False
            link = links[0]
            d.execute_script("arguments[0].removeAttribute('target'); arguments[0].scrollIntoView({block:'center'})", link)
            hd.pause(hd.rng.uniform(0.3, 1.2))
            ActionChains(d).move_to_element(link).pause(hd.rng.uniform(0.08, 0.3)).click().perform()
            return True
        except Exception:
            return False

    @staticmethod
    def _not_you(identity) -> bool:
        return bool(getattr(identity, "mobile", False)) or getattr(identity, "persona", "own") not in ("own", "", None)

    def hit(self, identity, target: Target) -> HitResult:
        if target.kind != "html":
            return self.fallback.hit(identity, target)
        if self._alt is not None:
            return self._alt.hit(identity, target)
        if self._alt_factory is not None and self._not_you(identity):
            # User agent "Mix": the identities that don't use your own browser's user agent (and phones, which your
            # Firefox can't be) browse in the app's own browsers, so the noise also looks like other machines.
            if self._other is None:
                self._other = self._alt_factory()
            if self._other is not None:
                return self._other.hit(identity, target)
        try:
            self._ensure()
        except Exception as exc:
            reason = str(exc).splitlines()[0][:150] if str(exc) else repr(exc)
            if self._alt_factory is not None:                    # don't fail forever: use the app's own browser
                self.on_event("warn", f"Your Firefox could not be started ({reason}). Using the app's own browsers instead.")
                self._alt = self._alt_factory()
                if self._alt is not None:
                    return self._alt.hit(identity, target)
            return HitResult(None, error=f"Firefox unavailable: {reason}")
        d = self._driver
        if self.cookie_hours and time.time() - self._cookies_at > self.cookie_hours * 3600 * self.rng.uniform(.6, 1.4):
            try:
                d.delete_all_cookies()
            except Exception:
                pass
            self._cookies_at = time.time()
        hd = HumanDriver(self.rng, SeleniumActuator(d, self.stop_event), scale=self.scale())
        t0 = time.time()
        try:
            d.set_page_load_timeout(max(10.0, float(target.timeout)))
            clicked = False
            if target.role == "result" and target.referer and d.current_url == target.referer:
                clicked = self._click_through(d, hd, target)
            if not clicked:
                d.get(target.url)
            load_ms = (time.time() - t0) * 1000.0
            status = self._status(d)
            html = d.page_source or ""
            self.nav_log.append({"t": time.time(), "url": d.current_url, "via": "click" if clicked else "address"})
            stats = hd.serp() if target.role == "search" else hd.browse(dwell=target.dwell)
            res = HitResult(status, html[:400_000])
            res.load_ms, res.final_url = load_ms, d.current_url
            res.on_page_s = float(stats.get("seconds", 0) or 0)
            res.bytes = len(html)
            res.detail = "your Firefox" + (", clicked a result" if clicked else "")
            res.login_wall = res.foreign = False
            return res
        except Exception as exc:
            msg = str(exc).splitlines()[0][:200] if str(exc) else repr(exc)
            if "timeout" in msg.lower():
                msg = "page took too long to load"
            return HitResult(None, error=msg)


def support() -> tuple[bool, str]:
    """(usable, reason): Selenium installed, Firefox found, and a profile to copy."""
    try:
        import selenium  # noqa: F401
    except ImportError:
        return False, "the 'selenium' package is not installed (pip install selenium)"
    exe, why = find_firefox()
    if not exe:
        return False, why
    if default_profile() is None:
        return False, "no Firefox profile was found to copy"
    return True, exe
