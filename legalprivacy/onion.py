"""Onion (darknet) noise: v3 .onion address validation, seeds, and target factory.

Seeds are public, well-known sites that run official onion mirrors. Every
address is checked offline with the v3 checksum (sha3-256) so a mistyped or
corrupted address can never be dispatched. Users can add their own seeds.
"""
from __future__ import annotations

import base64
import hashlib
import random
import re
import urllib.parse
from dataclasses import dataclass, field

from .engines import _LinkExtractor
from .transports import Target

# (label, url) — official onion mirrors of lawful, public sites.
# Sources: the curated lists at dark.fail and tor.taxi. A seed is accepted only if
# two independent sources agree on the address (the other directory, or the
# project's own site), which guards against phishing clones; it must also pass
# the offline v3 checksum. Deliberately EXCLUDED: markets, drug/leak/exploit
# forums, adult sites, piracy sites, anonymous imageboards and government/
# law-enforcement sites — noise should
# never touch illicit or unmoderated content.
BUILTIN_ONION_SEEDS: list[tuple[str, str]] = [
    ("DuckDuckGo", "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"),
    ("Tor Project", "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"),
    ("The New York Times", "https://nytimesn7cgmftshazwhfgzm37qxb44r64ytbb2dj3x62d2lljsciiyd.onion/"),
    ("BBC", "https://www.bbcnewsd73hkzno2ini43t4gblxvycyac5aw4gnv7t2rccijh7745uqd.onion/"),
    ("ProPublica", "http://p53lf57qovyuvwsc6xnrppyply3vtqm7l6pcobkmyqsiofyeznfu5uqd.onion/"),
    ("The Intercept", "https://27m3p2uv7igmj6kvd4ql3cct5h3sdwrsajovkkndeufumzyfhlfev4qd.onion/"),
    ("Debian", "http://2s4yqjx5ul6okpp3f2gaunr2syex5jgbfpfvhxxbbjwnrsvbk5v3qbid.onion/"),
    ("Proton", "https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion/"),
    ("Qubes OS", "http://qubesosfasa4zl44o4tws22di6kepyzfeqv3tg4e3ztknltfxqrymdad.onion/"),
    ("Riseup", "http://vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion/"),
    ("Tech Learning Collective", "http://lpiyu33yusoalp5kh3f4hak2so2sjjvjw5ykyvu2dulzosgvuffq6sad.onion/"),
    ("Blockchair", "http://blkchairbknpn73cfjhevhla7rkp4ed5gg2knctvv7it4lioy22defid.onion/"),
    ("Mullvad VPN", "http://o54hon2e2vj6c7m3aqqu6uyece65by3vgoxxhlqlsvkmacw6a7m7kiad.onion/"),
    ("Njalla", "http://njallalafimoej5i4eg7vlnqjvmb6zhdh27qxcatdn647jtwwwui3nad.onion/"),
    ("Facebook", "https://facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion/"),
    ("Keybase", "http://keybase5wmilwokqirssclfnsqrjdsi7jdir5wy7y7iu3tanwmtp6oid.onion/"),
    ("keys.openpgp.org", "http://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad.onion/"),
    ("Archive.today", "http://archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion/"),
    ("dark.fail", "http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion/"),
]

_ONION_RE = re.compile(r"^[a-z2-7]{56}$")


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def onion_label(url: str, user_seeds: list[str] | None = None) -> str:
    """What an onion address is, for the Activity details column: the site's name from the built-in list,
    "your own seed" for one you added, or "other onion site" for one found by following a link."""
    h = _host(url)
    for name, u in BUILTIN_ONION_SEEDS:
        if _host(u) == h:
            return name
    if any(_host(u) == h for u in (user_seeds or [])):
        return "your own onion seed"
    return "other onion site (found by following a link)"


class OnionHealth:
    """Remembers which seed onion sites keep failing, so they are not retried over and over.

    Three misses in a row put a site to rest for 6 hours, doubling with every further miss (capped at 7 days);
    one success clears it. Only addresses from the seed lists (built-in plus yours) are recorded, never the
    sites a random walk wanders onto. With a `path` the record is kept in one small file (onion address,
    miss count, last result time: nothing about what you browse) so a restart doesn't forget it.
    """
    FAILS_TO_REST = 3
    BASE_REST = 6 * 3600
    MAX_REST = 7 * 86400

    def __init__(self, path=None, clock=None, known=None):
        import time as _t
        self.path, self.clock = path, clock or _t.time
        self.known = known or (lambda host: True)         # host -> bool: is this one of the seed sites?
        self.data: dict[str, dict] = {}
        if path:
            try:
                import json
                with open(path, encoding="utf-8") as fh:
                    raw = json.load(fh)
                if isinstance(raw, dict):
                    self.data = {str(k): v for k, v in raw.items() if isinstance(v, dict)}
            except (OSError, ValueError):
                self.data = {}

    def _save(self) -> None:
        if not self.path:
            return
        import json
        import os
        try:
            tmp = str(self.path) + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass                                          # a read-only folder must never stop the noise

    def record(self, url: str, ok: bool) -> bool:
        """Note one result. Returns True when this miss just put the site to rest."""
        h = _host(url)
        if not h or not self.known(h):
            return False
        now = self.clock()
        e = self.data.setdefault(h, {"fails": 0, "until": 0, "last_ok": 0, "last_fail": 0})
        rested = False
        if ok:
            e.update(fails=0, until=0, last_ok=now)
        else:
            e["fails"] = int(e.get("fails", 0)) + 1
            e["last_fail"] = now
            if e["fails"] >= self.FAILS_TO_REST:
                rest = min(self.MAX_REST, self.BASE_REST * 2 ** (e["fails"] - self.FAILS_TO_REST))
                e["until"] = now + rest
                rested = True
        self._save()
        return rested

    def is_resting(self, url: str) -> bool:
        e = self.data.get(_host(url))
        return bool(e) and self.clock() < float(e.get("until", 0))

    def status(self, url: str) -> dict:
        e = self.data.get(_host(url)) or {}
        return {"fails": int(e.get("fails", 0)), "resting_until": float(e.get("until", 0)) if self.is_resting(url) else 0,
                "last_ok": float(e.get("last_ok", 0))}


def is_valid_v3_onion(host: str) -> bool:
    """True iff `host` is a well-formed v3 onion address with a correct checksum."""
    h = host.strip().lower().rstrip(".")
    if h.endswith(".onion"):
        h = h[: -len(".onion")]
    h = h.rsplit(".", 1)[-1]          # ignore subdomains
    if not _ONION_RE.match(h):
        return False
    try:
        raw = base64.b32decode(h.upper())
    except Exception:
        return False
    pubkey, checksum, version = raw[:32], raw[32:34], raw[34:]
    if version != b"\x03":
        return False
    return hashlib.sha3_256(b".onion checksum" + pubkey + version).digest()[:2] == checksum


def is_onion_url(url: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        return False
    return host.endswith(".onion") and is_valid_v3_onion(host)


def clean_seed_list(urls: list[str]) -> tuple[list[str], list[str]]:
    """Split user-supplied seeds into (valid, rejected)."""
    good, bad = [], []
    for raw in urls:
        u = raw.strip()
        if not u or u.startswith("#"):
            continue
        if "://" not in u:
            u = "http://" + u
        (good if is_onion_url(u) else bad).append(u)
    return good, bad


@dataclass
class OnionTargetFactory:
    """Random walk over onion sites: start at a seed, follow links, restart often.

    `follow_offsite` lets the walk hop to other valid onion services it finds
    (organic discovery); off-site non-onion links are always ignored so this
    engine can never leak a clearnet request.
    """
    rng: random.Random
    seeds: list[str] = field(default_factory=lambda: [u for _, u in BUILTIN_ONION_SEEDS])
    max_depth: int = 3
    follow_offsite: bool = True
    timeout: float = 60.0

    def __post_init__(self) -> None:
        good, _ = clean_seed_list(self.seeds)
        self.seeds = good or [u for _, u in BUILTIN_ONION_SEEDS]

    def make(self, identity=None) -> Target:
        return Target(url=self.rng.choice(self.seeds), timeout=self.timeout)

    def next_from(self, html: str, current_url: str) -> Target | None:
        parser = _LinkExtractor()
        try:
            parser.feed(html)
        except Exception:
            pass
        base_host = (urllib.parse.urlparse(current_url).hostname or "").lower()
        links = []
        for href in parser.links:
            absu = urllib.parse.urljoin(current_url, href)
            p = urllib.parse.urlparse(absu)
            if p.scheme not in ("http", "https") or not is_onion_url(absu):
                continue
            if not self.follow_offsite and (p.hostname or "").lower() != base_host:
                continue
            links.append(absu)
        return Target(url=self.rng.choice(links), timeout=self.timeout) if links else None
