"""Addresses the app stays away from: government ranges everywhere, and Virginia for Tor relays only.

Two lists, one switch (Settings, on by default):

  * GOVERNMENT RANGES: the IPv4 /8 blocks that IANA's own registry (iana.org/assignments/ipv4-address-space) lists as the US
    Department of Defense and its agencies: 6, 11, 22, 26, 28, 29, 30, 33, 55, 214, 215. Only blocks listed there are used;
    other governments' ranges are not guessed at (add your own addresses to Tor's exclude list on the Tor tab).
  * VIRGINIA: IPv4 ranges that DB-IP's free "IP to City Lite" database places in Virginia, USA, downloaded once a month and
    kept in the app folder. IP Geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0. A geolocation database is a
    best guess (CDN and cloud addresses can be pinned to a city they do not really sit in), so this is broad rather than exact.

Where it is used: GOVERNMENT ranges: Tor relays are excluded, noise visits skip any site in them, free proxies in them are
never kept, Spray's resolvers avoid them and the load-test tool will not aim at them. VIRGINIA: only Tor relays (the Virginia
relays found in Tor's public relay list are never picked); nothing else is held to it. It cannot reach what a web page loads
on its own (ads, fonts) or the app's own update checks.
"""
from __future__ import annotations

import bisect
import csv
import gzip
import io
import os
import ipaddress
import json
import socket
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from pathlib import Path

GOV_NETS = ["6.0.0.0/8", "11.0.0.0/8", "22.0.0.0/8", "26.0.0.0/8", "28.0.0.0/8", "29.0.0.0/8", "30.0.0.0/8", "33.0.0.0/8",
            "55.0.0.0/8", "214.0.0.0/8", "215.0.0.0/8"]
DBIP_URL = "https://download.db-ip.com/free/dbip-city-lite-{ym}.csv.gz"
ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"
REFRESH_AFTER = 30 * 86400
HOST_TTL = 3600.0


def _ranges(nets: list[str]) -> list[tuple[int, int]]:
    return sorted((int(n.network_address), int(n.broadcast_address)) for n in map(ipaddress.ip_network, nets))


class GeoBan:
    def __init__(self, path: Path | None = None, resolve=None, clock=time.time):
        from .paths import app_dir
        self.path = Path(path) if path else app_dir() / "geoban.json"
        self.clock = clock
        self._resolve = resolve or self._getaddrinfo
        self.gov = _ranges(GOV_NETS)
        self.relays: list[str] = []
        self.unknown_country: list[str] = []     # running relays with no known country (excluded whenever a country is)
        self._unknown_seen: list[str] | None = None
        self.va: list[tuple[int, int]] = []
        self._va_starts: list[int] = []
        self.meta: dict = {}
        self._cache: dict[str, tuple[float, str | None]] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="geoban")
        self.load()

    # -- the Virginia list -----------------------------------------------------
    def load(self) -> None:
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
            self.va = [(int(a), int(b)) for a, b in d["ranges"]]
            self._va_starts = [a for a, _ in self.va]
            self.meta = {k: d.get(k) for k in ("source", "month", "at")}
        except (OSError, ValueError, KeyError, TypeError):
            self.va, self._va_starts, self.meta = [], [], {}
        try:
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            self.relays = [str(f) for f in saved.get("relays", [])]
            self.unknown_country = [str(f) for f in saved.get("unknown_country", [])]
        except (OSError, ValueError, AttributeError):
            self.relays, self.unknown_country = [], []

    def needs_refresh(self) -> bool:
        return not self.va or self.clock() - float(self.meta.get("at") or 0) > REFRESH_AFTER

    def refresh(self, opener=urllib.request.urlopen) -> bool:
        """Download this month's DB-IP City Lite (or last month's) and keep the Virginia IPv4 ranges. True if it worked."""
        now = time.gmtime(self.clock())
        months = [f"{now.tm_year}-{now.tm_mon:02d}"]
        prev = (now.tm_year, now.tm_mon - 1) if now.tm_mon > 1 else (now.tm_year - 1, 12)
        months.append(f"{prev[0]}-{prev[1]:02d}")
        for ym in months:
            try:
                req = urllib.request.Request(DBIP_URL.format(ym=ym), headers={"User-Agent": "legalPrivacy-geoban"})
                with opener(req, timeout=60) as r:                              # nosec - fixed https host
                    rows = csv.reader(io.TextIOWrapper(gzip.GzipFile(fileobj=r), encoding="utf-8", errors="replace"))
                    found = self.parse(rows)
            except Exception:
                continue
            if not found:
                continue
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"source": "DB-IP City Lite", "month": ym, "at": self.clock(), "ranges": found,
                                       "relays": self.relays}), encoding="utf-8")
            tmp.replace(self.path)
            self.load()
            return True
        return False

    @staticmethod
    def parse(rows) -> list[list[int]]:
        """Rows of 'start,end,continent,country,region,...' -> merged [[start, end], ...] of IPv4 ranges in Virginia, US."""
        out: list[list[int]] = []
        for row in rows:
            if len(row) < 5 or row[3] != "US" or row[4] != "Virginia" or ":" in row[0]:
                continue
            try:
                a, b = int(ipaddress.IPv4Address(row[0])), int(ipaddress.IPv4Address(row[1]))
            except ValueError:
                continue
            out.append([a, b])
        out.sort()
        merged: list[list[int]] = []
        for a, b in out:
            if merged and a <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        return merged

    # -- asking ----------------------------------------------------------------
    @staticmethod
    def _in(ranges: list[tuple[int, int]], starts: list[int] | None, x: int) -> bool:
        if starts is None:
            starts = [a for a, _ in ranges]
        i = bisect.bisect_right(starts, x) - 1
        return i >= 0 and ranges[i][0] <= x <= ranges[i][1]

    def reason(self, ip: str, virginia: bool = False) -> str | None:
        """'a government range', 'Virginia' (only when asked: it is for choosing Tor relays, nothing else) or None.
        IPv6 is not covered."""
        try:
            a = ipaddress.ip_address(ip.strip("[]"))
        except ValueError:
            return None
        if a.version != 4:
            return None
        x = int(a)
        if self._in(self.gov, None, x):
            return "a government range"
        if virginia and self.va and self._in(self.va, self._va_starts, x):
            return "Virginia"
        return None

    def contains(self, ip: str, virginia: bool = False) -> bool:
        return self.reason(ip, virginia) is not None

    @staticmethod
    def _getaddrinfo(host: str) -> list[str]:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET)})

    def host_reason(self, host: str, timeout: float = 3.0) -> str | None:
        """Why a site's address is off limits, or None. Looked up through the normal resolver (a lookup the visit would make
        anyway) and remembered for an hour; a name that does not resolve is not banned (the visit will fail by itself)."""
        host = (host or "").lower().strip(".")
        if not host or host.endswith(".onion"):
            return None
        try:
            ipaddress.ip_address(host.strip("[]"))
            return self.reason(host)
        except ValueError:
            pass
        now = self.clock()
        with self._lock:
            hit = self._cache.get(host)
            if hit and now - hit[0] < HOST_TTL:
                return hit[1]
        why = None
        try:
            for ip in self._pool.submit(self._resolve, host).result(timeout=timeout):
                why = self.reason(ip)
                if why:
                    break
        except (FuturesTimeout, OSError, Exception):
            why = None
        with self._lock:
            if len(self._cache) > 20000:
                self._cache.clear()
            self._cache[host] = (now, why)
        return why

    # -- Tor relays ------------------------------------------------------------
    def relay_fingerprints(self, opener=urllib.request.urlopen, max_n: int = 3000) -> list[str]:
        """Fingerprints of running Tor relays whose IPv4 address is in a banned range (Onionoo gives the relay list, not regions,
        so the address is checked here). Saved with the ranges; [] if the list could not be fetched."""
        data = self._onionoo(opener)
        out: list[str] = []
        unknown: list[str] = []
        for rel in data.get("relays", []):
            fp = str(rel.get("fingerprint") or "").upper()
            if len(fp) == 40 and not rel.get("country"):
                unknown.append(fp)            # no country: kept out explicitly (Tor is told to let unknown addresses through,
        self._unknown_seen = unknown          # for Snowflake/meek's placeholder address; see tormanager._write_torrc)
        for rel in data.get("relays", []):
            fp = str(rel.get("fingerprint") or "").upper()
            if len(fp) != 40:
                continue
            for a in rel.get("or_addresses", []):
                if ":" in a and a.count(":") == 1 and self.contains(a.rsplit(":", 1)[0], virginia=True):
                    out.append(fp)
                    break
        return out[:max_n]

    @staticmethod
    def _onionoo(opener) -> dict:
        url = "https://onionoo.torproject.org/details?running=true&fields=fingerprint,or_addresses,country"
        try:
            with opener(urllib.request.Request(url, headers={"User-Agent": "legalPrivacy-geoban"}), timeout=60) as r:   # nosec
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            return {}

    def update_relays(self, **kw) -> int:
        self._unknown_seen = None
        fps = self.relay_fingerprints(**kw)
        if fps or self._unknown_seen:
            self.relays = fps or self.relays
            if self._unknown_seen is not None:
                self.unknown_country = self._unknown_seen
            try:
                d = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                d = {}
            d["relays"] = self.relays
            d["unknown_country"] = self.unknown_country
            d["relays_at"] = self.clock()
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(d), encoding="utf-8")
            tmp.replace(self.path)
        return len(fps)

    def tor_excludes(self) -> list[str]:
        """Entries for Tor's ExcludeNodes: the government ranges and the banned relays found so far."""
        return list(GOV_NETS) + ["$" + f for f in self.relays]

    def state(self) -> dict:
        return {"government_ranges": len(self.gov), "banned_relays": len(self.relays), "virginia_ranges": len(self.va), "month": self.meta.get("month"),
                "updated": self.meta.get("at"), "attribution": ATTRIBUTION}


_shared: GeoBan | None = None
_shared_lock = threading.Lock()


def shared() -> GeoBan:
    """The one GeoBan the whole app uses."""
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = GeoBan()
        return _shared


def maintain(log=None, stop=lambda: False) -> None:
    """Keep the lists fresh: the Virginia ranges monthly, the banned relay list daily. Meant for a background thread."""
    if os.environ.get("LEGALPRIVACY_GEOBAN_DOWNLOADS", "1") == "0":      # tests: never fetch the real lists
        return
    g = shared()
    last_relays = 0.0
    while not stop():
        try:
            if g.needs_refresh() and g.refresh() and log:
                log.info("app", f"Virginia address list updated ({len(g.va)} ranges, DB-IP {g.meta.get('month')}).")
            if time.time() - last_relays > 86400:
                n = g.update_relays()
                last_relays = time.time()
                if n and log:
                    log.info("tor", f"{n} Tor relays in banned address ranges will be avoided the next time Tor starts.")
        except Exception as exc:
            if log:
                log.info("app", f"Address-list update failed: {exc!r}")
        time.sleep(3600)
