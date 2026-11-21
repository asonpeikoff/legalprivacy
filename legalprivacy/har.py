"""Import a browser recording (HAR file) as a baseline of how YOU browse.

A HAR file is what a browser's developer tools save from the Network tab ("Save all as HAR").
It can contain cookies, headers, page addresses and page contents, so this module is strict:

  * the file is parsed in memory only; it is never written anywhere;
  * from every entry only two things are read: its start time and the site name (host) of its address;
  * addresses, paths, query strings, headers, cookies and bodies are dropped immediately and never stored
    or logged (error messages never quote the file);
  * what is kept is derived data only: requests per minute, different sites per minute, and a list of
    site names with counts (which the user can delete).
"""
from __future__ import annotations

import json
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 50 * 1024 * 1024
MAX_ENTRIES = 500_000
TOP_HOSTS = 50
MAX_SPAN_DAYS = 400
MAX_MINUTES = 200_000                       # keeps the saved file small even for odd recordings

_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*(Z|[+-]\d{2}(?::?\d{2})?)?$")
_SECOND_LEVEL = {"co", "com", "org", "net", "ac", "gov", "edu", "or", "ne", "go"}


class HarError(ValueError):
    """A problem with the file, in plain English (never quotes the file's contents)."""


def parse_time(s) -> float | None:
    """ISO 8601 (Chrome: ...Z or +hh:mm, Firefox: +hh:mm) to UTC epoch seconds, or None."""
    if not isinstance(s, str):
        return None
    m = _TS.match(s.strip())
    if not m:
        return None
    y, mo, d, h, mi, sec, frac, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec or 0), tzinfo=timezone.utc)
    except ValueError:
        return None
    t = dt.timestamp() + (float("0." + frac) if frac else 0.0)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        off = int(digits[:2]) * 3600 + (int(digits[2:4]) * 60 if len(digits) >= 4 else 0)
        t -= sign * off
    return t


def site_name(url) -> str | None:
    """The registrable site name of an http(s) address ("a.b.example.com" -> "example.com"), else None.
    Only this name leaves the function; the address itself is not kept."""
    if not isinstance(url, str):
        return None
    m = re.match(r"^(?:https?|wss?)://(?:[^/?#@]*@)?(\[[^\]]*\]|[^/?#:]+)", url.strip(), re.I)
    if not m:
        return None
    host = m.group(1).lower().strip(".")
    if not host or host.startswith("["):
        return None
    labels = host.split(".")
    if len(labels) == 4 and all(p.isdigit() for p in labels):
        return None                                        # bare IP address
    if len(labels) == 1:
        return None                                        # localhost / intranet names
    keep = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL else 2
    return ".".join(labels[-keep:])


def parse_har(source, denylist: set[str] | None = None) -> dict:
    """`source` is the file's text/bytes or an already-parsed object. Returns derived data only:
    {"entries", "first", "last", "minutes": {epoch_minute: [requests, different_sites]}, "top_hosts": [[host, n]]}."""
    if isinstance(source, (bytes, bytearray)):
        if len(source) > MAX_BYTES:
            raise HarError("That file is larger than 50 MB. Record a shorter session and try again.")
        try:
            source = source.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise HarError("That file isn't text. A HAR file is a JSON text file (.har).") from None
    if isinstance(source, str):
        if len(source) > MAX_BYTES:
            raise HarError("That file is larger than 50 MB. Record a shorter session and try again.")
        if not source.strip():
            raise HarError("The file is empty.")
        try:
            source = json.loads(source)
        except (ValueError, RecursionError):
            raise HarError("That doesn't look like a HAR file: it isn't valid JSON (a partly saved or "
                           "cut-off file will do this). Export it again from the Network tab.") from None
    log = source.get("log") if isinstance(source, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise HarError("That doesn't look like a HAR file: it has no list of requests (log → entries).")
    if len(entries) > MAX_ENTRIES:
        raise HarError(f"That recording has more than {MAX_ENTRIES:,} requests. Record a shorter session.")
    per_min: dict[int, list] = {}                          # minute -> [requests, set of sites]
    totals: Counter = Counter()
    used = skipped = 0
    first = last = None
    for e in entries:
        if not isinstance(e, dict):
            skipped += 1
            continue
        t = parse_time(e.get("startedDateTime"))
        req = e.get("request")
        site = site_name(req.get("url")) if isinstance(req, dict) else None
        if t is None or site is None:                       # no time, or not a normal web address
            skipped += 1
            continue
        mn = int(t // 60 * 60)
        slot = per_min.setdefault(mn, [0, set()])
        slot[0] += 1
        slot[1].add(site)
        totals[site] += 1
        used += 1
        first = t if first is None or t < first else first
        last = t if last is None or t > last else last
    if not used:
        raise HarError("No usable requests were found in that file (they need a start time and a web address). "
                       "Make sure the Network tab was recording while you browsed.")
    if len(per_min) > MAX_MINUTES:
        raise HarError("That recording spans too many separate minutes. Record a shorter session.")
    if last - first > MAX_SPAN_DAYS * 86400:        # also keeps the per-minute baseline table a sane size
        raise HarError(f"That recording spans more than {MAX_SPAN_DAYS} days between its first and last "
                       "request, which a normal browsing session never does. Record a shorter session.")
    tops = [[h, n] for h, n in totals.most_common() if not denylist or _ok(h, denylist)][:TOP_HOSTS]
    return {"entries": used, "skipped": skipped, "first": first, "last": last,
            "minutes": {mn: [v[0], len(v[1])] for mn, v in per_min.items()}, "top_hosts": tops}


def _ok(host: str, denylist: set[str]) -> bool:
    from .safety import safe_domain
    return safe_domain(host, denylist)


class HarStore:
    """The derived data on disk (har.json): counts and site names only."""

    def __init__(self, path: Path | None):
        self.path = path
        self._cache: tuple | None = None            # (mtime, data): the Proof tab polls, the file rarely changes

    def save(self, data: dict) -> None:
        if not self.path:
            return
        out = {"imported_at": data.get("imported_at") or time.time(), "entries": data["entries"],
               "first": data["first"], "last": data["last"], "top_hosts": data["top_hosts"],
               "minutes": {str(k): v for k, v in data["minutes"].items()}}
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(out), encoding="utf-8")
        tmp.replace(self.path)

    def load(self) -> dict | None:
        if not self.path:
            return None
        try:
            mt = self.path.stat().st_mtime_ns
            if self._cache and self._cache[0] == mt:
                return self._cache[1]
            d = json.loads(self.path.read_text(encoding="utf-8"))
            d["minutes"] = {int(k): v for k, v in d["minutes"].items()}
            d = d if d.get("minutes") else None
            self._cache = (mt, d)
            return d
        except (OSError, ValueError, KeyError, AttributeError):
            return None

    def forget(self, what: str = "all") -> None:
        if what == "hosts":
            d = self.load()
            if d and self.path:
                d["top_hosts"] = []
                self.save(d)
            return
        if self.path:
            for p in (self.path, self.path.with_suffix(".tmp")):
                try:
                    p.unlink()
                except OSError:
                    pass


def summary(d: dict | None) -> dict:
    if not d:
        return {"present": False}
    span = max(0.0, (d["last"] or 0) - (d["first"] or 0))
    return {"present": True, "entries": d["entries"], "first": d["first"], "last": d["last"],
            "span_hours": round(span / 3600, 2), "active_minutes": len(d["minutes"]),
            "sites": len(d.get("top_hosts") or []), "top_hosts": d.get("top_hosts") or [],
            "imported_at": d.get("imported_at")}
