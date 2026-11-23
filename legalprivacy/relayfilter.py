"""Relays to avoid because of what they call themselves or who runs them.

A relay's nickname and contact line are written by whoever runs it, so a name proves nothing, in either
direction: a government relay can call itself anything, and an ordinary relay can pick a scary name. This
is a best-effort filter for relays that look governmental (names like FBI, NSA, Police, Government, or a
.gov / .mil contact address). It finds them in the Tor Project's public relay list (Onionoo), keeps the
result for a day, and the app's Tor then avoids those relays. Whole countries are handled separately,
by the plain "{us}" style entries in the avoid list.
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path

ONIONOO = ("https://onionoo.torproject.org/details?type=relay&running=true"
           "&fields=fingerprint,nickname,contact,country")

# Whole words (or CamelCase / number-separated parts) of a nickname.
_WORDS = {
    "fbi", "cia", "nsa", "gchq", "dhs", "doj", "dea", "atf", "irs", "fsb", "gru", "kgb", "bnd", "dgse", "nca",
    "mi5", "mi6", "gov", "govt", "government", "governmental", "police", "cop", "cops", "sheriff", "military",
    "army", "navy", "usaf", "usmc", "darpa", "pentagon", "whitehouse", "federal", "feds", "fed", "interpol",
    "europol", "spy", "spies", "spook", "spooks", "surveillance", "intelligence", "homeland", "ministry",
    "embassy", "senate", "congress", "parliament", "mossad", "stasi",
}
# Long, distinctive words are also caught inside a longer name ("fbisurveillancevan"). Short ones are not:
# "nsa" is inside "transaction".
_INSIDE = sorted((w for w in _WORDS if len(w) >= 7), key=len, reverse=True)
_CONTACT = re.compile(r"@[\w.-]*\.(?:gov|mil)(?:\.[a-z]{2})?\b|@[\w.-]*\.(?:gouv|gob|bund)\.[a-z]{2}\b", re.I)
# Upper-case acronyms at the start of a name or after a separator, even when stuck to a lower-case word
# ("FBIvan", "NSAhoneypot"). Case matters here, which keeps "transaction" and "special" out.
_ACRONYM = re.compile(r"(?<![A-Za-z])(?:FBI|NSA|CIA|GCHQ|DHS|DOJ|DEA|ATF|IRS|FSB|GRU|KGB|BND|DGSE|NCA)(?![A-Z])")
_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


def looks_governmental(nickname: str, contact: str = "") -> str | None:
    """Why this relay looks governmental, or None."""
    nick = nickname or ""
    words = {t.lower() for t in _TOKEN.findall(nick)}
    m = _ACRONYM.search(nick)
    if m:
        return f"name contains '{m.group(0).lower()}'"
    hit = sorted(words & _WORDS)
    if hit:
        return f"name contains '{hit[0]}'"
    low = nick.lower()
    for w in _INSIDE:
        if w in low:
            return f"name contains '{w}'"
    m = _CONTACT.search(contact or "")
    if m:
        return f"contact address {m.group(0)}"
    return None


def _get(url: str, timeout: float = 60.0) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("refusing a non-HTTPS address")
    req = urllib.request.Request(url, headers={"User-Agent": "legalPrivacy-relayfilter"})
    with urllib.request.urlopen(req, timeout=timeout) as r:          # nosec - fixed https host
        return r.read(30_000_000)


def scan(relays: list[dict]) -> list[dict]:
    """[{fingerprint, nickname, why}] for relays that look governmental."""
    out = []
    for r in relays:
        fp = str(r.get("fingerprint") or "").upper()
        if not re.fullmatch(r"[0-9A-F]{40}", fp):
            continue
        why = looks_governmental(str(r.get("nickname") or ""), str(r.get("contact") or ""))
        if why:
            out.append({"fingerprint": fp, "nickname": str(r.get("nickname") or "")[:40], "why": why})
    return out


def refresh(cache: Path, http=_get, max_age: float = 86400.0) -> list[dict]:
    """The list of relays to avoid by name, fetched at most once a day. Offline: whatever was kept last time."""
    old = cached(cache)
    try:
        saved = json.loads(cache.read_text()).get("at", 0) if cache.exists() else 0
    except (OSError, ValueError):
        saved = 0
    if old and time.time() - saved < max_age:
        return old
    try:
        data = json.loads(http(ONIONOO).decode("utf-8", "ignore"))
        found = scan(data.get("relays", []))
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"at": time.time(), "relays": found}))
        return found
    except Exception:
        return old


def cached(cache: Path) -> list[dict]:
    try:
        return list(json.loads(cache.read_text()).get("relays", []))
    except (OSError, ValueError):
        return []
