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
    # The Tor Project's own published list (onion.torproject.org): its public, human-facing pages.
    # Infrastructure hosts (monitoring, mail, staging, donor systems) are left out.
    ("Tor Project Blog", "http://pzhdfe7jraknpj2qgu5cz2u3i4deuyfwmonvzu5i3nyw4t4bmg7o5pad.onion/"),
    ("Tor Project Community", "http://xmrhfasfg5suueegrnc4gsgyi2tyclcy5oz7f5drnrodmdtob6t2ioyd.onion/"),
    ("Tor Project Support", "http://rzuwtpc4wb3xdzrj3yeajsvm3fkq4vbeubm2tdxaqruzzzgs5dwemlad.onion/"),
    ("Tor Project Forum", "http://v236xhqtyullodhf26szyjepvkbv6iitrhjgrqj4avaoukebkk6n6syd.onion/"),
    ("Tor Browser Manual", "http://dsbqrprgkqqifztta6h3w7i2htjhnq7d3qkh3c7gvc35e66rrcv66did.onion/"),
    ("Tor Specifications", "http://i3xi5qxvbrngh3g6o7czwjfxwjzigook7zxzjmgwg5b7xnjcn5hzciad.onion/"),
    ("Tor Research Portal", "http://xhqthou6scpfnwjyzc3ekdgcbvj76ccgyjyxp6cgypxjlcuhnxiktnqd.onion/"),
    ("Tor Metrics", "http://hctxrvjzfpvmzh2jllqhgvvkoepxb4kfzdjm6h7egcwlumggtktiftid.onion/"),
    ("Tor Project Newsletter", "http://a4ygisnerpgtc5ayerl22pll6cls3oyj54qgpm7qrmb66xrxts6y3lyd.onion/"),
    ("Tor Onion Services Guide", "http://ttevhjjsjxz6uqqcjkbig5cycd7n7xv7cmd6f5fcvrqaaa7f3bj36wad.onion/"),
    ("Snowflake", "http://oljlphash3bpqtrvqpr5gwzrhroziw4mddidi5d2qa4qjejcbrmoypqd.onion/"),
    ("Arti (Tor in Rust)", "http://hjirlp6fu47kox4cnede4zlvaeq672bibss3oxgmsnsc5mdxygqshbqd.onion/"),
    ("Stem (Tor library)", "http://mf34jlghauz5pxjcmdymdqbe5pva4v24logeys446tdrgd5lpsrocmqd.onion/"),
    ("Nyx (Tor monitor)", "http://3ewfgrt4gzfccp6bnquhqb266r3zepiqpnsk3falwygkegtluwuyevid.onion/"),
    ("Tor Style Guide", "http://7khzpw47s35pwo3lvtctwf2szvnq3kgglvzc22elx7of2awdzpovqmqd.onion/"),
    ("ExoneraTor", "http://pm46i5h2lfewyx6l7pnicbxhts2sxzacvsbmqiemqaspredf2gm3dpad.onion/"),
    ("Tor Project GitLab", "http://eweiibe6tdjsdprb4px6rqrzzcsi22m4koia44kc5pcjr7nec2rlxyad.onion/"),
    ("Tails", "http://tzoz3bensgxyzs7da7lpgsn3a74h7hlbm4wa6ytq2tg6ktd57w22vqqd.onion/"),
    ("The Onion Router (history)", "http://tttyx2vwp7ihml3vkhywwcizv6nbwrikpgeciy3qrow7l7muak2pnhad.onion/"),
]

def _host(url: str) -> str:
    return (urllib.parse.urlparse(url).hostname or "").lower()


def builtin_site_name(url: str) -> str | None:
    """The name of a built-in site, e.g. 'BBC', for any address on that site."""
    h = _host(url)
    for name, u in BUILTIN_ONION_SEEDS:
        if _host(u) == h:
            return name
    return None


_ONION_RE = re.compile(r"^[a-z2-7]{56}$")


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

    The walk stays on the current site, or hops to another site that is on the list (`follow_offsite`).
    It never follows a link to an onion address that is not on the list, so it can't wander into
    anything nobody vetted, and non-onion links are always ignored so it can never leak a clearnet request.
    """
    rng: random.Random
    seeds: list[str] = field(default_factory=lambda: [u for _, u in BUILTIN_ONION_SEEDS])
    max_depth: int = 3
    follow_offsite: bool = True
    timeout: float = 60.0

    def __post_init__(self) -> None:
        good, _ = clean_seed_list(self.seeds)
        self.seeds = good or [u for _, u in BUILTIN_ONION_SEEDS]
        # The walk only ever stays on a site from the list or hops to another site ON the list. It never
        # follows a link to an address nobody vetted, however a page links to it.
        self.allowed_hosts = {_host(u) for u in self.seeds}

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
            host = (p.hostname or "").lower()
            if host != base_host and not (self.follow_offsite and host in self.allowed_hosts):
                continue
            links.append(absu)
        return Target(url=self.rng.choice(links), timeout=self.timeout) if links else None
