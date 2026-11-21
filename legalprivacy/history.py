"""Find the sites you visit most, from your own browsers' history, for My List.

Runs only when you ask, entirely on this computer. Each browser's history file is
copied to a private temporary folder (browsers lock the original while open), read,
and the copy deleted. Only site names (domains) and visit counts come out of here,
never full addresses, page titles or times, and nothing is saved until you approve
the sites in the My List tab.

"Recording" needs no extra software: it remembers when you started and, when you
collect, counts only the visits your browsers logged inside that window (it stops
counting at the end of the window, even if you collect later).
"""
from __future__ import annotations

import glob
import ipaddress
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import urllib.parse
from collections import Counter
from pathlib import Path

from .safety import safe_domain

_WEBKIT_OFFSET = 11_644_473_600          # seconds between 1601-01-01 and 1970-01-01


def _chromium_bases() -> list[tuple[str, str]]:
    home = Path.home()
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local"))
        return [("Chrome", rf"{local}\Google\Chrome\User Data"),
                ("Edge", rf"{local}\Microsoft\Edge\User Data"),
                ("Brave", rf"{local}\BraveSoftware\Brave-Browser\User Data"),
                ("Chromium", rf"{local}\Chromium\User Data")]
    if sys.platform == "darwin":
        sup = home / "Library" / "Application Support"
        return [("Chrome", str(sup / "Google" / "Chrome")), ("Edge", str(sup / "Microsoft Edge")),
                ("Brave", str(sup / "BraveSoftware" / "Brave-Browser")), ("Chromium", str(sup / "Chromium"))]
    cfg = home / ".config"
    return [("Chrome", str(cfg / "google-chrome")), ("Edge", str(cfg / "microsoft-edge")),
            ("Brave", str(cfg / "BraveSoftware" / "Brave-Browser")), ("Chromium", str(cfg / "chromium")),
            ("Chromium (snap)", str(home / "snap" / "chromium" / "common" / "chromium")),
            ("Chrome (Flatpak)", str(home / ".var" / "app" / "com.google.Chrome" / "config" / "google-chrome")),
            ("Chromium (Flatpak)", str(home / ".var" / "app" / "org.chromium.Chromium" / "config" / "chromium")),
            ("Brave (Flatpak)", str(home / ".var" / "app" / "com.brave.Browser" / "config" / "BraveSoftware" / "Brave-Browser"))]


def _firefox_bases() -> list[str]:
    home = Path.home()
    if sys.platform == "win32":
        return [os.path.join(os.environ.get("APPDATA", str(home / "AppData" / "Roaming")),
                             "Mozilla", "Firefox", "Profiles")]
    if sys.platform == "darwin":
        return [str(home / "Library" / "Application Support" / "Firefox" / "Profiles")]
    return [str(home / ".mozilla" / "firefox"), str(home / ".config" / "mozilla" / "firefox"),
            str(home / "snap" / "firefox" / "common" / ".mozilla" / "firefox"),
            str(home / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox")]


def history_files() -> list[dict]:
    """Every browser profile history file on this computer: {browser, kind, path}."""
    out = []
    for name, base in _chromium_bases():
        for path in sorted(glob.glob(os.path.join(base, "*", "History"))):
            out.append({"browser": name, "kind": "chromium", "path": path,
                        "profile": os.path.basename(os.path.dirname(path))})
    for base in _firefox_bases():
        for path in sorted(glob.glob(os.path.join(base, "*", "places.sqlite"))):
            out.append({"browser": "Firefox", "kind": "firefox", "path": path,
                        "profile": os.path.basename(os.path.dirname(path))})
    return out


def site_of(url: str) -> str | None:
    """The site name a person would recognise ("www." dropped), or None for non-web addresses."""
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    host = u.hostname.lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    try:
        ipaddress.ip_address(host)
        return None                        # bare IP addresses (routers, local devices)
    except ValueError:
        pass
    if "." not in host or host.endswith((".local", ".lan", ".home", ".internal", ".onion", ".localhost")):
        return None
    return host


def _read_copy(src: str, query: str, args: tuple) -> list[tuple]:
    tmp = tempfile.mkdtemp(prefix="legalprivacy-hist-")
    try:
        dst = os.path.join(tmp, "h.sqlite")
        shutil.copy2(src, dst)
        for suffix in ("-wal", "-journal"):        # include not-yet-merged recent visits
            if os.path.exists(src + suffix):
                shutil.copy2(src + suffix, dst + suffix)
        con = sqlite3.connect(f"file:{dst}?mode=ro", uri=True)
        try:
            return con.execute(query, args).fetchall()
        finally:
            con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def visits(entry: dict, since: float, until: float) -> list[str]:
    """URLs visited in [since, until] (unix seconds) from one history file."""
    if entry["kind"] == "chromium":
        lo = int((since + _WEBKIT_OFFSET) * 1_000_000)
        hi = int((until + _WEBKIT_OFFSET) * 1_000_000)
        rows = _read_copy(entry["path"], "SELECT u.url FROM visits v JOIN urls u ON u.id = v.url "
                                         "WHERE v.visit_time BETWEEN ? AND ?", (lo, hi))
    else:
        rows = _read_copy(entry["path"], "SELECT p.url FROM moz_historyvisits h JOIN moz_places p "
                                         "ON p.id = h.place_id WHERE h.visit_date BETWEEN ? AND ?",
                          (int(since * 1_000_000), int(until * 1_000_000)))
    return [r[0] for r in rows]


def top_sites(since: float, until: float | None = None, files: list[dict] | None = None,
              denylist: set[str] | None = None, limit: int = 200) -> dict:
    """Most-visited sites across all browsers in the window, safety-filtered.

    Returns {"sites": [[domain, visits], ...], "browsers": [...], "errors": [...],
             "filtered": n}  (filtered = sites left out by the safety filter).
    """
    until = until if until is not None else time.time()
    files = history_files() if files is None else files
    counts: Counter[str] = Counter()
    errors, used = [], []
    for f in files:
        try:
            urls = visits(f, since, until)
        except (OSError, sqlite3.Error) as exc:
            errors.append(f"{f['browser']} ({f['profile']}): {exc}")
            continue
        used.append(f"{f['browser']} ({f['profile']})")
        for url in urls:
            s = site_of(url)
            if s:
                counts[s] += 1
    safe = [(d, n) for d, n in counts.most_common() if safe_domain(d, denylist)]
    return {"sites": [list(x) for x in safe[:limit]], "browsers": used, "errors": errors,
            "filtered": len(counts) - len(safe)}


# ── bookmarks ───────────────────────────────────────────────────────────────
def _chromium_bookmark_urls(path: str) -> list[str]:
    import json
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    out: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "url" and node.get("url"):
                out.append(node["url"])
            for child in node.get("children", []) or []:
                walk(child)
    for root in (data.get("roots") or {}).values():
        walk(root)
    return out


def bookmark_sites(denylist: set[str] | None = None) -> dict:
    """Sites in your browsers' bookmarks: {"sites": [[domain, bookmarks], ...], ...}."""
    counts: Counter[str] = Counter()
    errors, used = [], []
    for name, base in _chromium_bases():
        for path in sorted(glob.glob(os.path.join(base, "*", "Bookmarks"))):
            prof = os.path.basename(os.path.dirname(path))
            try:
                urls = _chromium_bookmark_urls(path)
            except (OSError, ValueError) as exc:
                errors.append(f"{name} ({prof}): {exc}")
                continue
            used.append(f"{name} ({prof})")
            counts.update(s for s in map(site_of, urls) if s)
    for base in _firefox_bases():
        for path in sorted(glob.glob(os.path.join(base, "*", "places.sqlite"))):
            prof = os.path.basename(os.path.dirname(path))
            try:
                rows = _read_copy(path, "SELECT p.url FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk "
                                        "WHERE b.type = 1", ())
            except (OSError, sqlite3.Error) as exc:
                errors.append(f"Firefox ({prof}): {exc}")
                continue
            used.append(f"Firefox ({prof})")
            counts.update(s for s in (site_of(r[0]) for r in rows) if s)
    if not used and not errors:
        errors.append("No Firefox or Chrome-type browser profile found on this computer. If your browser is in another "
                      "VM or qube, export its bookmarks to an HTML file there (Firefox: Ctrl+Shift+O, Import and Backup, "
                      "Export Bookmarks to HTML; Chrome: Ctrl+Shift+O, ⋮, Export bookmarks), copy the file here and use "
                      "'From a file'.")
    elif used and not counts and not errors:
        errors.append("Found " + ", ".join(used) + " but it has no bookmarks (or they are all filtered).")
    return _finish(counts, used, errors, denylist)


def sites_from_bookmarks_file(text: str, denylist: set[str] | None = None) -> dict:
    """Sites in a bookmarks export file (the HTML file every browser can export)."""
    import re
    return sites_from_urls(re.findall(r'(?i)href\s*=\s*"([^"]+)"', text), denylist)


def sites_from_urls(urls: list[str], denylist: set[str] | None = None) -> dict:
    """Sites in a list of links (e.g. pulled out of a bookmarks export file)."""
    counts: Counter[str] = Counter(s for s in map(site_of, urls) if s)
    return _finish(counts, ["bookmarks file"], [], denylist)


def _finish(counts: Counter, used: list, errors: list, denylist, limit: int = 300) -> dict:
    safe = [(d, n) for d, n in counts.most_common() if safe_domain(d, denylist)]
    return {"sites": [list(x) for x in safe[:limit]], "browsers": used, "errors": errors,
            "filtered": len(counts) - len(safe)}


def visit_events(since: float, until: float | None = None, files: list[dict] | None = None) -> dict:
    """Every visit in the window as (unix time, site), across browsers. For the self-test only:
    nothing leaves this computer and nothing is saved."""
    until = until if until is not None else time.time()
    files = history_files() if files is None else files
    events, errors = [], []
    for f in files:
        try:
            if f["kind"] == "chromium":
                lo = int((since + _WEBKIT_OFFSET) * 1_000_000)
                hi = int((until + _WEBKIT_OFFSET) * 1_000_000)
                rows = _read_copy(f["path"], "SELECT u.url, v.visit_time FROM visits v JOIN urls u ON u.id = v.url "
                                             "WHERE v.visit_time BETWEEN ? AND ?", (lo, hi))
                conv = [(t / 1_000_000 - _WEBKIT_OFFSET, u) for u, t in rows]
            else:
                rows = _read_copy(f["path"], "SELECT p.url, h.visit_date FROM moz_historyvisits h JOIN moz_places p "
                                             "ON p.id = h.place_id WHERE h.visit_date BETWEEN ? AND ?",
                                  (int(since * 1_000_000), int(until * 1_000_000)))
                conv = [(t / 1_000_000, u) for u, t in rows]
        except (OSError, sqlite3.Error) as exc:
            errors.append(f"{f['browser']} ({f['profile']}): {exc}")
            continue
        for t, u in conv:
            s = site_of(u)
            if s:
                events.append((t, s))
    events.sort()
    return {"events": events, "errors": errors}
