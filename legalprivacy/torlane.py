"""Onion visits with the real Tor Browser, behaving like a person (the Tor lane's browser).

Until now the onion lane was Python `requests` through Tor with Tor Browser's headers: no scrolling, no reading
pauses, no mouse, no JavaScript, and a TLS handshake that does not look like Tor Browser's. This is the real thing:
the verified Tor Browser the app installs, driven with Selenium and geckodriver, going through this app's own Tor and
using the same human behaviour (HumanDriver: scrolling in bursts, reading pauses, back-scrolls, mouse paths, time on
page) as the clearnet lane. Sessions, revisits and the "keeps coming back to one page" or "stepped away" spells are
the scheduler's and work the same on both lanes.

  - its own throw-away profile every time it starts (never your Tor Browser's profile: no shared history or cookies)
  - security level Safest, like the Tor Browser the app opens for you
  - a new identity (= what Tor Browser's "New Identity" does: close it and start fresh) after the same number of
    visits as the old lane; Tor Browser looks the same for everyone, so only the state changes, never the fingerprint
  - if it cannot start (Tor Browser not installed yet, no Selenium, running as the administrator, no display...)
    the old requests lane carries on, and the log says why
"""
from __future__ import annotations

import random
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import torbrowser as TB
from .humanize import HumanDriver
from .realfirefox import SeleniumActuator
from .transports import HitResult, Target, TorTransport


def browser_path() -> Path:
    return TB.tb_dir() / "tor-browser" / "Browser" / "firefox"


def support() -> tuple[bool, str]:
    """(usable, reason): Selenium installed, Tor Browser installed and verified, and not the administrator."""
    try:
        import selenium  # noqa: F401
    except ImportError:
        return False, "the 'selenium' package is not installed"
    if not TB.supported():
        return False, "Tor Browser can't be installed by this app on this system"
    import os
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return False, "Tor Browser must not be run as the administrator (root)"
    if not browser_path().exists() or not TB.installed_version():
        return False, "Tor Browser isn't installed yet (open it once from the Tor tab and it is installed for you)"
    try:
        TB.verify_install()
    except TB.TorBrowserError as exc:
        return False, str(exc)
    return True, str(browser_path())


def explain_navigation_error(msg: str, timeout_s: float = 0.0) -> str:
    """Tor Browser's error pages and Selenium's messages, in words the scheduler's onion handling understands
    (host unreachable / timed out), so an offline onion site is treated like any other."""
    m = (msg or "").lower()
    if "timeout" in m or "timed out" in m or "netTimeout".lower() in m:
        return f"page took too long to load (timed out{f' after {timeout_s:.0f}s' if timeout_s else ''})"
    if any(k in m for k in ("onionservices", "proxyconnectfailure", "connectionfailure", "dnsnotfound", "netreset",
                            "nssfailure", "netinterrupt", "neterror")):
        return "host unreachable: the onion site is offline, moved, or not reachable right now"
    return (msg or "navigation failed").splitlines()[0][:200]


class TorBrowserTransport:
    """The Tor lane's transport when the real Tor Browser is used. Same interface as TorTransport."""
    is_browser = True

    def __init__(self, socks: str = "127.0.0.1:9050", control: str | None = None, cookie_path: str | None = None,
                 identities_per_circuit: int = 8, control_password: str | None = None, share_browser: bool = False,
                 headless: bool = True, stop_event: threading.Event | None = None,
                 scale: Callable[[], float] = lambda: 1.0, on_event: Callable[[str, str], None] | None = None,
                 rng: random.Random | None = None, driver_factory: Callable[[dict[str, str]], Any] | None = None):
        self.fallback = TorTransport(socks=socks, control=control, identities_per_circuit=identities_per_circuit,
                                     control_password=control_password, share_browser=share_browser)
        self.fallback.cookie_path = cookie_path
        self.socks_host, self.socks_port = self.fallback.socks_host, self.fallback.socks_port
        self.control, self.cookie_path = control, cookie_path
        self.identities_per_circuit = identities_per_circuit
        self.share_browser, self.headless = share_browser, headless
        self.stop_event, self.scale = stop_event, scale
        self.on_event = on_event or (lambda level, msg: None)
        self.rng = rng or random.Random()
        self.dimmed = False
        self.nav_log: list[dict] = []
        self.blocked_navs = 0
        self._driver: Any = None
        self._factory = driver_factory
        self._failed: str | None = None          # why the browser can't be used (the old lane is used instead)
        self._announced = False

    # ── what the scheduler and controller expect of a lane's transport ──
    def set_endpoint(self, socks: str, control: str | None, cookie_path: str | None = None) -> None:
        """Re-point at the managed Tor, whose ports were chosen when it started. A browser already open keeps talking
        to the old ones, so it is closed and the next visit starts a fresh one."""
        self.fallback.set_endpoint(socks, control, cookie_path)
        changed = (socks, control) != (f"{self.socks_host}:{self.socks_port}", self.control)
        self.socks_host, self.socks_port = self.fallback.socks_host, self.fallback.socks_port
        self.control, self.cookie_path = control, cookie_path
        if changed:
            self._close_driver()

    def renew_circuits(self) -> bool:
        """A new identity: close the browser (the next visit starts a fresh one with no cookies or history), and ask Tor
        for new circuits unless Tor Browser shares this Tor (then each browser's own SOCKS login keeps them apart)."""
        self._close_driver()
        return self.fallback.renew_circuits()

    def reconnect(self) -> bool:
        self._close_driver()
        self.dimmed = False
        return self.fallback.reconnect()

    def check_status(self) -> dict[str, Any]:
        return self.fallback.check_status()

    def close(self) -> None:
        self._close_driver()

    # ── the browser ──
    def _environment(self) -> dict[str, str]:
        return {**TB.clean_env(), **TB.shared_env(f"{self.socks_host}:{self.socks_port}", self.control, self.cookie_path)}

    def _make_driver(self, env: dict[str, str]):
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        from selenium.webdriver.firefox.service import Service
        opts = Options()
        opts.binary_location = str(browser_path())
        opts.add_argument("--no-remote")
        if self.headless:
            opts.add_argument("-headless")
        opts.set_preference("browser.security_level.security_slider", 1)          # Safest, like the browser we open for you
        opts.set_preference("browser.startup.homepage_override.mstone", "ignore")
        return webdriver.Firefox(options=opts, service=Service(env=env))

    def _ensure(self) -> None:
        if self._driver is not None:
            return
        env = self._environment()
        self._driver = (self._factory or self._make_driver)(env)
        if not self._announced:
            self._announced = True
            self.on_event("info", "Onion sites are visited with the real Tor Browser (through this app's Tor), "
                                  "scrolling and reading like a person.")

    def _close_driver(self) -> None:
        d, self._driver = self._driver, None
        if d is not None:
            try:
                d.quit()
            except Exception:
                pass

    @staticmethod
    def _status(d) -> int:
        try:
            s = d.execute_script("const n = performance.getEntriesByType('navigation')[0]; return n ? n.responseStatus : 0")
            return int(s) or 200
        except Exception:
            return 200

    def hit(self, identity, target: Target) -> HitResult:
        if target.kind != "html" or self._failed:
            return self.fallback.hit(identity, target)
        try:
            self._ensure()
        except Exception as exc:
            self._failed = (str(exc).splitlines()[0][:160] if str(exc) else repr(exc))
            self.on_event("warn", f"The real Tor Browser could not be started ({self._failed}). Onion visits use the "
                                  "plain lane instead until the next start.")
            self._close_driver()
            return self.fallback.hit(identity, target)
        d = self._driver
        hd = HumanDriver(self.rng, SeleniumActuator(d, self.stop_event), scale=self.scale())
        t0 = time.time()
        timeout = max(60.0, float(target.timeout))                           # onion services are slow
        try:
            d.set_page_load_timeout(timeout)
            d.get(target.url)
            load_ms = (time.time() - t0) * 1000.0
            html = d.page_source or ""
            self.nav_log.append({"t": time.time(), "url": d.current_url, "via": "address"})
            del self.nav_log[:-400]
            stats = hd.browse(dwell=target.dwell)
            res = HitResult(self._status(d), html[:2_000_000])
            res.load_ms, res.final_url = load_ms, d.current_url
            res.on_page_s = float(stats.get("seconds", 0) or 0)
            res.bytes = len(html)
            res.detail = "Tor Browser"
            res.login_wall = res.foreign = False
            return res
        except Exception as exc:
            msg = explain_navigation_error(str(exc), timeout)
            if "invalid session" in str(exc).lower() or "no such window" in str(exc).lower() or "disconnected" in str(exc).lower():
                self._close_driver()                                          # the browser went away: start a new one next time
                msg = "the Tor Browser window closed; starting a new one"
            return HitResult(None, error=msg)
