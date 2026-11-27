"""Free proxy lists, tested and pruned: only proxies that prove themselves are kept.

Most free proxies are dead, slow or worse, so nothing here trusts a list. Candidates come from public lists (GitHub raw
files by default) and from any page the user adds (every `ip:port` on it is picked out); each is tested before it is kept:

  * it must carry an HTTPS request through (CONNECT) and come back with the answer we expect from a known test page,
    so a proxy that rewrites or blocks responses fails;
  * it must answer inside `max_ms` (default 2.5 s);
  * the address the test page sees must NOT be ours (a transparent proxy hides nothing).

A proxy that fails is thrown out at once; one that worked before gets one more try, then goes. Kept ones are re-tested
before they are used again after a few hours. Nothing here is used by the noise: proxies are for jobs the user starts,
such as scraping. They are untrusted third-party machines that can read and change plain traffic, so never send a
login, a cookie or anything private through one.
"""
from __future__ import annotations

import ipaddress
import json
import random
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DEFAULT_SOURCES = [
    ("TheSpeedX/PROXY-List", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"),
    ("monosans/proxy-list", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"),
    ("proxifly/free-proxy-list", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"),
    ("ClearProxy/checked-proxy-list", "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/http/raw/all.txt"),
    ("vakhov/fresh-proxy-list", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt"),
    ("zloi-user/hideip.me", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt"),
    ("Zaeem20/FREE_PROXIES_LIST", "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt"),
]
TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"       # a short text page that names the address it saw
MAX_MS = 2500
RETEST_AFTER_S = 4 * 3600
MAX_SOURCE_BYTES = 5_000_000
_ADDR = re.compile(r"(?:(?P<scheme>https?|socks4|socks5h?)://)?(?P<ip>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{2,5})\b")


def parse(text: str, default_scheme: str = "http") -> list[str]:
    """Every public `ip:port` in a text or an HTML page, as `scheme://ip:port`, de-duplicated, order kept."""
    out, seen = [], set()
    for m in _ADDR.finditer(text or ""):
        try:
            ip = ipaddress.ip_address(m["ip"])
        except ValueError:
            continue
        port = int(m["port"])
        if not (0 < port < 65536) or not ip.is_global:
            continue
        url = f"{m['scheme'] or default_scheme}://{ip}:{port}"
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _http_get(url: str, proxy: str | None, timeout: float) -> tuple[int, str]:
    import requests
    proxies = {"http": proxy, "https": proxy} if proxy else None
    r = requests.get(url, proxies=proxies, timeout=timeout, headers={"User-Agent": "legalPrivacy proxy check"},
                     stream=True)
    body = r.raw.read(MAX_SOURCE_BYTES if not proxy else 4096, decode_content=True)
    return r.status_code, body.decode("utf-8", "replace")


class ProxyManager:
    def __init__(self, path: Path | None = None, get: Callable[[str, str | None, float], tuple[int, str]] = _http_get,
                 clock: Callable[[], float] = time.time, rng: random.Random | None = None):
        self.path, self.get, self.clock, self.rng = path, get, clock, rng or random.Random()
        self.lock = threading.RLock()
        self.proxies: dict[str, dict] = {}
        self.extra_sources: list[str] = []
        self.max_ms = MAX_MS
        self.sources: dict[str, dict] = {}              # name -> {"found": n, "error": str|None, "at": ts}
        self.progress: dict = {"running": False, "tested": 0, "total": 0, "kept": 0, "thrown_out": 0}
        self.my_ip: str | None = None
        self.avoid_banned = True              # drop proxies in a government range (geoban.py)
        self._load()

    # ── persistence ───────────────────────────────────────────────────────
    def _load(self) -> None:
        try:
            d = json.loads(self.path.read_text(encoding="utf-8")) if self.path and self.path.exists() else {}
        except (OSError, ValueError):
            d = {}
        self.proxies = {k: v for k, v in (d.get("proxies") or {}).items() if isinstance(v, dict)}
        self.extra_sources = [u for u in d.get("extra_sources", []) if isinstance(u, str)]
        self.max_ms = int(d.get("max_ms") or MAX_MS)
        self.sources = d.get("sources") or {}

    def save(self) -> None:
        if not self.path:
            return
        with self.lock:
            data = {"proxies": self.proxies, "extra_sources": self.extra_sources, "max_ms": self.max_ms,
                    "sources": self.sources}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            pass

    # ── sources ───────────────────────────────────────────────────────────
    def add_source(self, url: str) -> None:
        if not re.match(r"^https?://", url or ""):
            raise ValueError("A source is a web address that starts with http:// or https://")
        with self.lock:
            if url not in self.extra_sources:
                self.extra_sources.append(url)
        self.save()

    def remove_source(self, url: str) -> None:
        with self.lock:
            self.extra_sources = [u for u in self.extra_sources if u != url]
            self.sources.pop(url, None)
        self.save()

    def all_sources(self) -> list[tuple[str, str]]:
        return list(DEFAULT_SOURCES) + [(u, u) for u in self.extra_sources]

    def fetch_candidates(self) -> list[str]:
        found: list[str] = []
        for name, url in self.all_sources():
            try:
                status, text = self.get(url, None, 20.0)
                if status != 200:
                    raise ValueError(f"HTTP {status}")
                got = parse(text)
                self.sources[name] = {"found": len(got), "error": None, "at": self.clock()}
                found.extend(got)
            except Exception as exc:
                self.sources[name] = {"found": 0, "error": str(exc).splitlines()[0][:120], "at": self.clock()}
        return list(dict.fromkeys(found))

    # ── testing ───────────────────────────────────────────────────────────
    def _own_ip(self) -> str | None:
        if self.my_ip is None:
            try:
                _s, text = self.get(TEST_URL, None, 8.0)
                self.my_ip = _trace_ip(text) or ""
            except Exception:
                self.my_ip = ""
        return self.my_ip or None

    def check(self, proxy: str) -> dict:
        """Test one proxy. {"ok", "ms", "error"}: ok only when the HTTPS test page came back right, fast, and not as us."""
        t0 = time.time()
        try:
            status, text = self.get(TEST_URL, proxy, max(1.0, self.max_ms / 1000.0 * 1.6))
        except Exception as exc:
            return {"ok": False, "ms": None, "error": str(exc).splitlines()[0][:100]}
        ms = round((time.time() - t0) * 1000)
        try:
            from . import geoban
            why = geoban.shared().reason(proxy.split("//")[-1].rsplit(":", 1)[0]) if self.avoid_banned else None
        except Exception:
            why = None
        if why:
            return {"ok": False, "ms": ms, "error": f"in {why}: not used"}
        seen = _trace_ip(text)
        if status != 200 or not seen or "h=" not in text:
            return {"ok": False, "ms": ms, "error": "the test page came back wrong"}
        if self._own_ip() and seen == self._own_ip():
            return {"ok": False, "ms": ms, "error": "transparent: the site saw our own address"}
        if ms > self.max_ms:
            return {"ok": False, "ms": ms, "error": f"too slow ({ms} ms)"}
        return {"ok": True, "ms": ms, "error": None}

    def _apply(self, proxy: str, res: dict) -> bool:
        """Record a result; returns True if the proxy is kept."""
        now = self.clock()
        with self.lock:
            rec = self.proxies.get(proxy)
            if res["ok"]:
                self.proxies[proxy] = {"ms": res["ms"], "ok": True, "fails": 0, "checked": now,
                                       "first": (rec or {}).get("first", now), "last_ok": now}
                return True
            if rec and rec.get("ok") and rec.get("fails", 0) < 1:       # worked before: one more chance
                rec.update(fails=rec.get("fails", 0) + 1, checked=now)
                return True
            self.proxies.pop(proxy, None)
            return False

    def refresh(self, max_new: int = 2500, workers: int = 48, stop: threading.Event | None = None) -> dict:
        """Fetch the sources, test new candidates (up to `max_new`, chosen at random) and every kept proxy that is due, and
        throw out whatever fails. Safe to call from a thread; progress is in `self.progress`."""
        with self.lock:
            if self.progress["running"]:
                return dict(self.progress)
            self.progress = {"running": True, "tested": 0, "total": 0, "kept": 0, "thrown_out": 0, "found": 0}
        try:
            now = self.clock()
            cand = [c for c in self.fetch_candidates() if c not in self.proxies]
            self.rng.shuffle(cand)
            due = [p for p, r in self.proxies.items() if now - r.get("checked", 0) > RETEST_AFTER_S]
            todo = due + cand[:max_new]
            with self.lock:
                self.progress["found"] = len(cand) + len(self.proxies)     # candidates discovered this run (new + known)
                self.progress["total"] = len(todo)

            def one(p: str) -> None:
                if stop is not None and stop.is_set():
                    return
                kept = self._apply(p, self.check(p))
                with self.lock:
                    self.progress["tested"] += 1
                    self.progress["kept" if kept else "thrown_out"] += 1
            with ThreadPoolExecutor(max_workers=workers) as ex:
                list(ex.map(one, todo))
        finally:
            with self.lock:
                self.progress["running"] = False
            self.save()
        return dict(self.progress)

    # ── using them ────────────────────────────────────────────────────────
    def good(self, n: int | None = None) -> list[dict]:
        with self.lock:
            rows = [{"proxy": p, **r} for p, r in self.proxies.items() if r.get("ok") and r.get("ms") is not None and r["ms"] <= self.max_ms]
        rows.sort(key=lambda r: r["ms"])
        return rows[:n] if n else rows

    def clear(self) -> int:
        """Throw out every tested proxy. Returns how many were removed."""
        with self.lock:
            n = len(self.proxies)
            self.proxies = {}
            self.progress = {"running": False, "tested": 0, "total": 0, "kept": 0, "thrown_out": 0, "found": 0}
        self.save()
        return n

    def drop(self, proxy: str) -> None:
        """A proxy failed while in use: it goes at once (the next refresh may find it again if it recovers)."""
        with self.lock:
            self.proxies.pop(proxy, None)
        self.save()

    def pick_checked(self, exclude: set[str] | None = None, tries: int = 6) -> str | None:
        """A good proxy re-tested right now (free proxies die within hours); failures are dropped on the way."""
        for _ in range(tries):
            rows = [r for r in self.good() if r["proxy"] not in (exclude or set())]
            if not rows:
                return None
            p = self.rng.choices([r["proxy"] for r in rows], weights=[1000.0 / max(r["ms"], 50) for r in rows])[0]
            if self._apply(p, self.check(p)) and self.proxies.get(p, {}).get("fails", 0) == 0:
                return p
            self.drop(p)
        return None

    def pick(self) -> str | None:
        """A random good proxy, the faster ones more often. For jobs the user started (scraping); never for noise."""
        rows = self.good()
        if not rows:
            return None
        return self.rng.choices([r["proxy"] for r in rows], weights=[1000.0 / max(r["ms"], 50) for r in rows])[0]

    def state(self) -> dict:
        good = self.good()
        with self.lock:
            return {"kept": len(good), "fastest": good[:25], "sources": [{"name": n, "url": u, **(self.sources.get(n) or {})}
                                                                       for n, u in self.all_sources()],
                    "extra_sources": list(self.extra_sources), "max_ms": self.max_ms, "progress": dict(self.progress),
                    "warning": "Free proxies are untrusted machines run by strangers: they can read and change plain "
                               "traffic and most are dead or slow. Only used for jobs you start, never for logins."}


def _trace_ip(text: str) -> str | None:
    m = re.search(r"^ip=(\S+)", text or "", re.M)
    return m.group(1) if m else None
