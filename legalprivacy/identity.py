"""Per-identity consistent fingerprints.

An identity is a pinned tuple (user agent, client hints, accept-language,
timing persona, query taste). Identities stay consistent for their lifetime
so traffic looks like distinct people instead of one rotating bot.

The UA pool mirrors *real, frequency-weighted* browser populations (several
Chrome majors circulate at once in real traffic — not just the newest).
Client hints are emitted ONLY for Chromium personas: Firefox and Safari do
not send them, and hinting on their UAs would be the giveaway. DNT is dead
(removed from Firefox in v135); Sec-GPC is opt-in and rare, so identities
send it with low probability, pinned per identity.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass

from .useragents import PERSONAS, build_pool, sample_entry

# The pool of user agents (browsers from the last two years, plus a few non-browser
# clients). Built in useragents.py from ua_catalog.py. See that module for why.
UA_POOL: dict[str, list[dict]] = build_pool()

LANGUAGE_POOL = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.6",
    "fr-FR,fr;q=0.9,en;q=0.5",
    "de-DE,de;q=0.9,en;q=0.5",
]

PERSONA_CLASSES = list(PERSONAS)

# fast / normal / slow pacing multipliers per persona
PACE_MULTIPLIERS = {"fast": 0.6, "normal": 1.0, "slow": 1.8}

# GREASE brand-lists observed in the wild (low-entropy client hints).
_CH_ANTIBRANDS = [
    '"Not_A Brand";v="8"',
    '"Not/A)Brand";v="99"',
    '"Not?A_Brand";v="24"',
    '"Not A(Brand";v="99"',
]

_SEC_FETCH_NAV = {
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
}


@dataclass
class Identity:
    id: int
    persona: str
    user_agent: str
    accept_language: str
    pace: str                 # fast | normal | slow
    query_taste: list[str]    # seed words this identity prefers
    chromium: bool = False    # Chromium personas carry client hints; others never
    mobile: bool = False
    platform: str = "Windows"
    gpc: bool = False         # Sec-GPC opt-in, pinned low-rate like real users
    device: str = ""          # phone model to emulate (mobile identities), e.g. "iPhone 13"

    @property
    def pace_multiplier(self) -> float:
        return PACE_MULTIPLIERS[self.pace]


def _client_hints(identity: Identity) -> dict[str, str]:
    """Low-entropy client hints, brand list matched to the UA string.

    Only valid for Chromium personas. Firefox sends none, and a Sec-CH-UA on a
    Firefox UA is an instant non-human tell. Non-browser tools send none either.
    """
    if not identity.chromium:
        return {}
    major = re.search(r"Chrome/(\d+)", identity.user_agent)
    if major is None:                      # defensive: non-chromium UA string
        return {}
    v = major.group(1)
    notbrand = _CH_ANTIBRANDS[identity.id % len(_CH_ANTIBRANDS)]
    if "Chromium/" in identity.user_agent:  # Chromium-branded build
        brand_list = f'"Chromium";v="{v}", {notbrand}'
    else:                                   # Google Chrome
        brand_list = f'{notbrand}, "Chromium";v="{v}", "Google Chrome";v="{v}"'
    return {
        "Sec-CH-UA": brand_list,
        "Sec-CH-UA-Mobile": "?1" if identity.mobile else "?0",
        "Sec-CH-UA-Platform": f'"{identity.platform}"',
    }


def _query_taste(rng: random.Random, wordlist: list[str], size: int = 12) -> list[str]:
    from .engines import REAL_INTERNET_THEMES
    if not wordlist:
        themes = rng.sample(list(REAL_INTERNET_THEMES.values()), k=min(2, len(REAL_INTERNET_THEMES)))
        combined = [t for sub in themes for t in sub]
        return rng.sample(combined, min(size, len(combined)))
    # Sample from wordlist, filtering archaic noise when large dictionary files are used
    clean_pool = [w for w in wordlist if len(w) >= 3 and not w.startswith("'")] if len(wordlist) > 100 else wordlist
    pool = clean_pool or wordlist
    return rng.sample(pool, min(size, len(pool)))


def make_identity(rng: random.Random, ident_id: int, wordlist: list[str],
                  entry: dict | None = None) -> Identity:
    """Build one pinned identity from the shared RNG.

    `entry` is the user agent chosen by the UaChooser (rotation or pin). Without it, a
    user agent is drawn from the library the same way the chooser does.
    """
    if entry is None:
        entry = sample_entry(rng)
    persona = entry.get("persona", "own")
    return Identity(
        id=ident_id,
        persona=persona,
        user_agent=entry["ua"],
        accept_language=rng.choice(LANGUAGE_POOL),
        pace=rng.choice(["fast", "normal", "normal", "slow"]),
        query_taste=_query_taste(rng, wordlist),
        chromium=entry["chromium"],
        mobile=entry["mobile"],
        platform=entry["platform"],
        gpc=rng.random() < 0.06,
        device=entry.get("device", ""),
    )


# What a real Chromium (measured against Chromium 153 on Linux, over HTTP/1.1) sends for a page navigation, in its order.
# `requests` would otherwise put its own User-Agent, Accept-Encoding, Accept and Connection first and use a shorter Accept.
CHROMIUM_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,"
                   "application/signed-exchange;v=b3;q=0.7")


def accept_encoding() -> str:
    """The content encodings this program can really decode, written the way Chrome writes them. A browser of this
    age says "gzip, deflate, br, zstd"; with the optional brotli and zstandard packages installed (the `parity`
    extra) so do we, otherwise we only claim what we can read, since a reply we cannot decode is worse than a tell."""
    try:
        from urllib3.util.request import ACCEPT_ENCODING
        have = [e.strip() for e in ACCEPT_ENCODING.split(",") if e.strip()]
    except Exception:
        have = ["gzip", "deflate"]
    return ", ".join(have or ["identity"])


def _site_relation(url: str, referer: str) -> str:
    """Sec-Fetch-Site for a click from `referer` to `url`: same-origin, same-site or cross-site (as Chromium sends it)."""
    import urllib.parse as up
    a, b = up.urlsplit(referer), up.urlsplit(url)
    if (a.scheme, a.hostname, a.port or {"http": 80, "https": 443}.get(a.scheme)) == \
            (b.scheme, b.hostname, b.port or {"http": 80, "https": 443}.get(b.scheme)):
        return "same-origin"

    def site(h: str) -> str:
        parts = (h or "").lower().split(".")
        if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return "same-site" if site(a.hostname) == site(b.hostname) else "cross-site"


def referer_value(url: str, referer: str) -> str:
    """What Chromium puts in Referer by default (strict-origin-when-cross-origin): the whole address to the same site,
    only the origin to another one, nothing when going from https to http."""
    import urllib.parse as up
    a, b = up.urlsplit(referer), up.urlsplit(url)
    if a.scheme == "https" and b.scheme == "http":
        return ""
    if _site_relation(url, referer) == "same-origin":
        return up.urlunsplit((a.scheme, a.netloc, a.path or "/", a.query, ""))
    return f"{a.scheme}://{a.netloc}/"


def navigation_headers(identity: Identity, url: str = "", referer: str | None = None) -> dict[str, str]:
    """The request headers of a page visit, in the order and with the values a real browser uses. Chromium identities
    get the measured Chromium layout (same order, the full Accept string, Sec-Fetch-User, fetch-metadata that follows
    whether you arrived by click, and Referer where Chromium puts it). Other engines keep the existing header set,
    with only the encodings fixed, because their layout has not been measured here."""
    enc = accept_encoding()
    ref = referer_value(url, referer) if (referer and url) else ""
    if not (identity.chromium and re.search(r"Chrome/(\d+)", identity.user_agent)):
        h = headers_for(identity)
        if ref:
            h["Referer"] = ref
        h["Accept-Encoding"] = enc
        return h
    ch = _client_hints(identity)
    out: dict[str, str] = {"Connection": "keep-alive"}
    out["sec-ch-ua"], out["sec-ch-ua-mobile"], out["sec-ch-ua-platform"] = (
        ch["Sec-CH-UA"], ch["Sec-CH-UA-Mobile"], ch["Sec-CH-UA-Platform"])
    out["Upgrade-Insecure-Requests"] = "1"
    out["User-Agent"] = identity.user_agent
    out["Accept-Language"] = identity.accept_language
    out["Accept"] = CHROMIUM_ACCEPT
    out["Sec-Fetch-Site"] = _site_relation(url, referer) if (referer and url) else "none"
    out["Sec-Fetch-Mode"] = "navigate"
    out["Sec-Fetch-User"] = "?1"
    out["Sec-Fetch-Dest"] = "document"
    if identity.gpc:
        out["Sec-GPC"] = "1"
    if ref:
        out["Referer"] = ref
    out["Accept-Encoding"] = enc
    return out


def headers_for(identity: Identity) -> dict[str, str]:
    """Headers pinned to this identity (no per-request rotation — that is the point)."""
    headers = {
        "User-Agent": identity.user_agent,
        "Accept-Language": identity.accept_language,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        # navigations carry fetch-metadata on every modern engine; it always
        # looks like a fresh top-level visit.
        "Upgrade-Insecure-Requests": "1",
        **_SEC_FETCH_NAV,
    }
    headers.update(_client_hints(identity))
    if identity.gpc:
        headers["Sec-GPC"] = "1"
    return headers
