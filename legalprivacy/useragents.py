"""The user-agent pool: browsers from the last two years, desktop and phone.

Nothing here is a raw string copied from one machine. Every browser UA is built from
a template and a release: Chrome, Chromium and Firefox majors come from ua_catalog.py
(which tools/build_ua_catalog.py regenerates from the official release calendars), and
iPhone Safari releases are listed below. Commonness is modelled from release age, so
the newest two or three versions of each browser are the ones most often chosen.

Only real browsers are listed: no command-line or library clients.

Phones: by default noise identities are phones 55% of the time, and phones are an
iPhone 13 (Safari). Other devices, or a mix of phones, can be chosen in Settings.
"""
from __future__ import annotations

import hashlib
import random
import time

from . import ua_catalog

# Desktop browsers, relative to each other (sums to 1).
DESKTOP_WEIGHTS = {
    "desktop-chrome": 0.60,
    "desktop-firefox": 0.34,
    "desktop-chromium": 0.06,
}
DEFAULT_MOBILE_SHARE = 0.55
DEFAULT_DEVICE = "iPhone 13"

# Phones we can emulate. viewport = the page area a person sees in the browser (CSS px).
MOBILE_DEVICES = {
    "iPhone 13": {"kind": "ios", "viewport": (390, 664), "dpr": 3.0},
    "iPhone 15": {"kind": "ios", "viewport": (393, 659), "dpr": 3.0},
    "iPhone SE (3rd gen)": {"kind": "ios", "viewport": (375, 553), "dpr": 2.0},
    "Pixel 7": {"kind": "android", "viewport": (412, 839), "dpr": 2.625},
    "Galaxy S24": {"kind": "android", "viewport": (360, 780), "dpr": 3.0},
}
# "Mix of phones": how often each device is picked.
DEVICE_MIX = {"iPhone 13": 0.45, "iPhone 15": 0.20, "iPhone SE (3rd gen)": 0.10,
              "Pixel 7": 0.15, "Galaxy S24": 0.10}

# iPhone Safari releases (Safari version, OS token in the UA, release month, weight).
# Since iOS 26, Safari freezes the OS token (18_6, then 18_6_2, then 18_7) and only the
# Version/ token tracks the real release. 27.x is assumed to keep 18_7 (not yet confirmed).
# Maintained by hand: Apple publishes no machine-readable calendar.
IOS_SAFARI = [
    ("27.0", "18_7", "2026-09", 1.0),
    ("26.6", "18_7", "2026-07", 0.55),
    ("26.5", "18_7", "2026-05", 0.30),
    ("26.4", "18_7", "2026-03", 0.16),
    ("26.3", "18_7", "2026-01", 0.09),
    ("26.2", "18_7", "2025-12", 0.05),
    ("26.1", "18_6_2", "2025-11", 0.03),
    ("26.0", "18_6", "2025-09", 0.02),
    ("18.6", "18_6", "2025-07", 0.02),
    ("18.5", "18_5", "2025-05", 0.01),
    ("18.4", "18_4", "2025-03", 0.01),
    ("18.3", "18_3", "2025-01", 0.005),
    ("18.2", "18_2", "2024-12", 0.005),
    ("18.1", "18_1", "2024-10", 0.005),
]

_WIN = "Windows NT 10.0; Win64; x64"
_MAC = "Macintosh; Intel Mac OS X 10_15_7"
_LINUX = "X11; Linux x86_64"
PERSONAS = list(DESKTOP_WEIGHTS) + ["mobile-iphone", "mobile-chrome"]


def _entry(ua: str, platform: str, *, persona: str, chromium: bool = False, mobile: bool = False,
           weight: float = 1.0, release: str = "") -> dict:
    return {"ua": ua, "platform": platform, "persona": persona, "chromium": chromium,
            "mobile": mobile, "weight": weight, "release": release, "id": ua_id(ua)}


def ua_id(ua: str) -> str:
    """Short, stable id for a user agent string (used for pinning)."""
    return hashlib.sha1(ua.encode("utf-8")).hexdigest()[:10]


def _chrome(major: int) -> str:
    return f"Chrome/{major}.0.0.0"


def iphone_safari_ua(version: str, os_token: str) -> str:
    return (f"Mozilla/5.0 (iPhone; CPU iPhone OS {os_token} like Mac OS X) AppleWebKit/605.1.15 "
            f"(KHTML, like Gecko) Version/{version} Mobile/15E148 Safari/604.1")


def build_pool() -> dict[str, list[dict]]:
    pool: dict[str, list[dict]] = {p: [] for p in PERSONAS}

    for major, released, w in ua_catalog.CHROME:
        for os_tok, plat in ((_WIN, "Windows"), (_MAC, "macOS"), (_LINUX, "Linux")):
            pool["desktop-chrome"].append(_entry(
                f"Mozilla/5.0 ({os_tok}) AppleWebKit/537.36 (KHTML, like Gecko) "
                f"{_chrome(major)} Safari/537.36", plat, persona="desktop-chrome", chromium=True,
                weight=w / 3, release=released))
        pool["mobile-chrome"].append(_entry(
            f"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"{_chrome(major)} Mobile Safari/537.36", "Android", persona="mobile-chrome",
            chromium=True, mobile=True, weight=w, release=released))

    for major, released, w in ua_catalog.CHROMIUM:
        pool["desktop-chromium"].append(_entry(
            f"Mozilla/5.0 ({_LINUX}) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chromium/{major}.0.0.0 {_chrome(major)} Safari/537.36", "Linux",
            persona="desktop-chromium", chromium=True, weight=w, release=released))

    for major, released, w in ua_catalog.FIREFOX + ua_catalog.FIREFOX_ESR:
        for os_tok, plat in (("Windows NT 10.0; Win64; x64", "Windows"),
                             ("Macintosh; Intel Mac OS X 10.15", "macOS"),
                             ("X11; Linux x86_64", "Linux")):
            pool["desktop-firefox"].append(_entry(
                f"Mozilla/5.0 ({os_tok}; rv:{major}.0) Gecko/20100101 Firefox/{major}.0",
                plat, persona="desktop-firefox", weight=w / 3, release=released))

    for version, os_token, released, w in IOS_SAFARI:      # Safari sends no client hints
        pool["mobile-iphone"].append(_entry(
            iphone_safari_ua(version, os_token), "iOS", persona="mobile-iphone",
            mobile=True, weight=w, release=released))
    return pool


def latest_firefox_esr() -> int:
    return max(m for m, _, _ in ua_catalog.FIREFOX_ESR)


def latest_firefox() -> int:
    return max(m for m, _, _ in ua_catalog.FIREFOX)


def _phone_kinds(device: str) -> dict[str, float]:
    """Share of phones that are iPhones vs Android for a device setting."""
    if device == "mix":
        ios = sum(w for d, w in DEVICE_MIX.items() if MOBILE_DEVICES[d]["kind"] == "ios")
        return {"mobile-iphone": ios, "mobile-chrome": 1 - ios}
    kind = MOBILE_DEVICES.get(device, MOBILE_DEVICES[DEFAULT_DEVICE])["kind"]
    return {"mobile-iphone": 1.0, "mobile-chrome": 0.0} if kind == "ios" else \
        {"mobile-iphone": 0.0, "mobile-chrome": 1.0}


def persona_weights(mobile_share: float = DEFAULT_MOBILE_SHARE, device: str = DEFAULT_DEVICE) -> dict:
    out = {p: (1 - mobile_share) * w for p, w in DESKTOP_WEIGHTS.items()}
    for p, w in _phone_kinds(device).items():
        out[p] = mobile_share * w
    return out


def library(mobile_share: float = DEFAULT_MOBILE_SHARE, device: str = DEFAULT_DEVICE) -> list[dict]:
    """Every browser user agent, flattened, with its share of picks (percent)."""
    pool = build_pool()
    pw = persona_weights(mobile_share, device)
    rows = []
    for persona, entries in pool.items():
        wsum = sum(e["weight"] for e in entries) or 1.0
        for e in entries:
            rows.append({**e, "group": persona, "share": round(100 * pw[persona] * e["weight"] / wsum, 2)})
    return rows


def pick_device(rng: random.Random, device: str, kind: str) -> str:
    """A concrete phone model for this identity."""
    if device != "mix" and MOBILE_DEVICES.get(device, {}).get("kind") == kind:
        return device
    names = [d for d in DEVICE_MIX if MOBILE_DEVICES[d]["kind"] == kind]
    return rng.choices(names, weights=[DEVICE_MIX[d] for d in names])[0]


def sample_entry(rng: random.Random, mobile_share: float = DEFAULT_MOBILE_SHARE,
                 device: str = DEFAULT_DEVICE) -> dict:
    """One user agent drawn the same way new identities are drawn (phones get a device)."""
    pool = build_pool()
    pw = persona_weights(mobile_share, device)
    personas = [p for p in pw if pw[p] > 0]
    persona = rng.choices(personas, weights=[pw[p] for p in personas])[0]
    entries = pool[persona]
    e = dict(rng.choices(entries, weights=[x["weight"] for x in entries])[0])
    if e["mobile"]:
        e["device"] = pick_device(rng, device, "ios" if persona == "mobile-iphone" else "android")
    return e


def entry_from_ua(ua: str) -> dict:
    """Describe a user agent string (e.g. your own browser's) in the same shape as the pool."""
    ua = ua.strip()
    if "iPhone" in ua or "iPad" in ua:
        persona = "mobile-iphone"
    elif "Android" in ua and "Mobile" in ua:
        persona = "mobile-chrome"
    elif "Chromium/" in ua:
        persona = "desktop-chromium"
    elif "Chrome/" in ua:
        persona = "desktop-chrome"
    elif "Firefox/" in ua:
        persona = "desktop-firefox"
    else:
        persona = "own"
    chromium = ("Chrome/" in ua or "Chromium/" in ua) and "CriOS" not in ua
    mobile = "Mobile" in ua or "iPhone" in ua or "iPad" in ua
    if "Android" in ua:
        plat = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        plat = "iOS"
    elif "Windows" in ua:
        plat = "Windows"
    elif "Macintosh" in ua:
        plat = "macOS"
    else:
        plat = "Linux"
    e = _entry(ua, plat, persona=persona, chromium=chromium, mobile=mobile, weight=1.0)
    if mobile:
        e["device"] = DEFAULT_DEVICE if plat == "iOS" else "Pixel 7"
    return e


class UaChooser:
    """Decides which user agent new noise identities use.

    mode "pin": always the pinned one (your own browser, or one library entry).
    mode "rotate": a random library entry, re-drawn every hour or every day.
    mode "mix": each new identity uses your own browser's user agent with probability ua_own_share and a
    freshly drawn random library entry otherwise (so "70% real, 30% random").
    The draw is cached for the whole period, so one period looks like one device.
    `mobile` returns (phone share, device setting) and may change hour to hour.
    """

    def __init__(self, rng: random.Random, cfg, clock=time.time, mobile=None):
        self.rng, self.cfg, self.clock = rng, cfg, clock
        self.mobile = mobile or (lambda: (DEFAULT_MOBILE_SHARE, DEFAULT_DEVICE))
        self._key = None
        self._entry: dict | None = None

    def pinned_entry(self) -> dict | None:
        pin = (self.cfg.ua_pin or "").strip()
        if pin == "own":
            return entry_from_ua(self.cfg.own_ua) if self.cfg.own_ua.strip() else None
        for e in library():
            if e["id"] == pin:
                e = {k: v for k, v in e.items() if k not in ("group", "share")}
                if e["mobile"]:
                    e["device"] = DEFAULT_DEVICE if e["persona"] == "mobile-iphone" else "Pixel 7"
                return e
        return None

    def _period_key(self) -> str:
        t = time.localtime(self.clock())
        if self.cfg.rotate_every == "day":
            return f"{t.tm_year}-{t.tm_yday}"
        return f"{t.tm_year}-{t.tm_yday}-{t.tm_hour}"

    def choose(self) -> dict:
        if self.cfg.ua_mode == "mix":
            own = entry_from_ua(self.cfg.own_ua) if self.cfg.own_ua.strip() else None
            if own is not None and self.rng.random() < float(self.cfg.ua_own_share):
                return own
            share, device = self.mobile()
            return sample_entry(self.rng, share, device)
        if self.cfg.ua_mode == "pin":
            e = self.pinned_entry()
            if e is not None:
                return e
        key = self._period_key()
        if key != self._key or self._entry is None:
            self._key = key
            share, device = self.mobile()
            self._entry = sample_entry(self.rng, share, device)
        return self._entry


def detect_own_ua(timeout: float = 45) -> dict:
    """Read this computer's installed browser user agent by starting it briefly (headless).

    Returns {"ua": ...} or {"error": ...}. Needs the playwright package and a
    Chromium-family browser; otherwise paste your UA by hand (chrome://version).
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"error": "Playwright is not installed here; paste your browser's user agent instead."}
    from .browser import find_browser
    exe = find_browser()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, executable_path=exe, timeout=timeout * 1000)
            try:
                page = browser.new_page()
                ua = page.evaluate("navigator.userAgent")
            finally:
                browser.close()
    except Exception as exc:
        return {"error": f"Could not start your browser to read its user agent: {exc}"}
    return {"ua": ua.replace("HeadlessChrome/", "Chrome/")}
