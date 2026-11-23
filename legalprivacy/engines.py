"""Engines: search-query noise, crawl noise, DNS noise.

Every engine consumes an identity + transport and yields Targets; it does
not know which transport will carry them.
"""

from __future__ import annotations

import random
import socket
import struct
import urllib.parse
from dataclasses import dataclass
from html.parser import HTMLParser

from .transports import Target
from .safety import english_url

# Search engine endpoint probability tiers:
# 1. Most likely group: Google & DuckDuckGo (~70% weight)
# 2. Next most likely group: Bing, Brave, Startpage (~24% weight)
# 3. Less likely group: Ecosia, Mojeek, Qwant, DuckDuckGo Lite (~6% weight)
SEARCH_ENGINE_TIERS: list[tuple[str, float]] = [
    # Tier 1 (Highest probability: Google + DuckDuckGo)
    ("https://www.google.com/search?q=", 35.0),
    ("https://duckduckgo.com/?q=", 35.0),
    # Tier 2 (Next most likely: Bing, Brave, StartPage)
    ("https://www.bing.com/search?q=", 8.0),
    ("https://search.brave.com/search?q=", 8.0),
    ("https://www.startpage.com/sp/search?query=", 8.0),
    # Tier 3 (Less likely group: alternative engines)
    ("https://www.ecosia.org/search?q=", 1.5),
    ("https://www.mojeek.com/search?q=", 1.5),
    ("https://www.qwant.com/?q=", 1.5),
    ("https://lite.duckduckgo.com/lite/?q=", 1.5),
]
SEARCH_ENDPOINTS = [url for url, _ in SEARCH_ENGINE_TIERS]
SEARCH_WEIGHTS = [w for _, w in SEARCH_ENGINE_TIERS]
ENGINE_NAMES = ["Google", "DuckDuckGo", "Bing", "Brave", "Startpage", "Ecosia", "Mojeek", "Qwant", "DuckDuckGo Lite"]
# Settings → Search engines: relative weights by name. Empty = the defaults above.
SEARCH_OPTIONS: dict = {"weights": {}, "typos": False}


# The Ason persona searches almost only with DuckDuckGo (anything chosen in Settings -> Search engines wins).
PERSONA_SEARCH = {"Ason": {"DuckDuckGo": 88.0, "Google": 5.0, "Bing": 3.0, "Brave": 2.0, "Startpage": 1.0,
                           "DuckDuckGo Lite": 1.0}}


def configure_search(weights: dict | None = None, typos: bool = False, persona: str | None = None) -> None:
    SEARCH_OPTIONS["weights"] = dict(weights or PERSONA_SEARCH.get(persona or "", {}))
    SEARCH_OPTIONS["typos"] = bool(typos)


def _current_weights() -> list[float]:
    custom = SEARCH_OPTIONS["weights"]
    if not custom:
        return list(SEARCH_WEIGHTS)
    return [float(custom.get(n, 0.0)) for n in ENGINE_NAMES]


def add_typo(rng, query: str) -> str:
    """One small, human slip in one word: swapped, doubled or dropped letter."""
    words = query.split(" ")
    idx = [i for i, w in enumerate(words) if len(w) >= 5 and w.isalpha()]
    if not idx:
        return query
    i = rng.choice(idx)
    w = words[i]
    j = rng.randint(1, len(w) - 2)
    kind = rng.random()
    if kind < 0.45 and w[j] != w[j + 1]:
        w = w[:j] + w[j + 1] + w[j] + w[j + 2:]          # swap two letters
    elif kind < 0.75:
        w = w[:j] + w[j] + w[j:]                         # double a letter
    else:
        w = w[:j] + w[j + 1:]                            # drop a letter
    words[i] = w
    return " ".join(words)

# No search engine gets more than this many searches from us in any hour, whatever the
# level: well under the volume that triggers CAPTCHAs or rate limits for one address.
MAX_SEARCHES_PER_ENGINE_PER_HOUR = 8
_ENGINE_HITS: dict[str, list[float]] = {}
_ENGINE_LOCK = __import__("threading").Lock()


_ENGINE_COOLDOWN: dict[str, float] = {}     # endpoint -> time it may be used again


def cool_down_engine(url: str, seconds: float, now: float | None = None) -> str | None:
    """A search engine showed its robot check: leave it alone for a while (as a person would)."""
    import time as _t
    now = _t.time() if now is None else now
    for ep in SEARCH_ENDPOINTS:
        host = urllib.parse.urlparse(ep).hostname or ""
        if host and host in url:
            with _ENGINE_LOCK:
                _ENGINE_COOLDOWN[ep] = now + seconds
            return host
    return None


def pick_search_endpoint(rng, now: float | None = None) -> str:
    """Weighted engine choice that skips any engine already at its hourly cap."""
    import time as _t
    now = _t.time() if now is None else now
    with _ENGINE_LOCK:
        for hits in _ENGINE_HITS.values():
            hits[:] = [t for t in hits if now - t < 3600]
        weights = _current_weights()
        allowed = [(ep, w) for ep, w in zip(SEARCH_ENDPOINTS, weights)
                   if w > 0 and len(_ENGINE_HITS.get(ep, [])) < MAX_SEARCHES_PER_ENGINE_PER_HOUR
                   and now >= _ENGINE_COOLDOWN.get(ep, 0)]
        pool = allowed or [(ep, w) for ep, w in zip(SEARCH_ENDPOINTS, weights) if w > 0] \
            or list(zip(SEARCH_ENDPOINTS, SEARCH_WEIGHTS))
        ep = rng.choices([p for p, _ in pool], weights=[w for _, w in pool])[0]
        _ENGINE_HITS.setdefault(ep, []).append(now)
        return ep

# Curated thematic pools of real internet search topics:
REAL_INTERNET_THEMES: dict[str, list[str]] = {
    "tech": [
        "python", "linux", "docker", "kubernetes", "rust language", "git commands",
        "sqlite database", "bash scripting", "ssh keys setup", "arch linux",
        "raspberry pi projects", "home assistant", "nginx reverse proxy", "rest api",
        "tailwind css", "react components", "typescript tutorial", "dns record types",
    ],
    "cooking": [
        "sourdough bread recipe", "cast iron seasoning", "pasta carbonara authentic",
        "easy weeknight dinner", "air fryer chicken breast", "chocolate chip cookies chewy",
        "thai green curry paste", "vegetarian chili slow cooker", "meal prep containers",
        "french press ratio", "roasted root vegetables", "homemade pizza dough cold ferment",
    ],
    "travel": [
        "flight tracker live", "national park annual pass", "hiking boots lightweight",
        "camping checklist essentials", "carry on bag dimensions", "scenic train routes",
        "hotel booking discounts", "travel insurance comparison", "mountain trail conditions",
        "road trip map offline", "campsite reservation tips", "passport renewal expedited",
    ],
    "entertainment": [
        "movie showtimes today", "sci fi novels recommendations", "indie video games 2026",
        "soundtrack vinyl record", "streaming series release dates", "audio drama podcasts",
        "fantasy book series", "director commentary analysis", "concert tour dates",
        "tabletop board games strategy",
    ],
    "health_fitness": [
        "5k running schedule beginner", "morning mobility routine 10 min", "core strength exercises",
        "whey protein isolate reviews", "stretching for lower back", "healthy meal prep ideas",
        "kettlebell workout full body", "sleep tracking accuracy", "electrolyte hydration drinks",
    ],
    "science_nature": [
        "james webb space telescope images", "solar eclipse path map", "bird migration tracker",
        "mycelium network biology", "quantum computing fundamentals", "deep sea exploration discoveries",
        "renewable energy grid battery", "fossil discovery news", "night sky constellation guide",
    ],
    "home_daily": [
        "indoor plants low light tolerant", "compost tumbler bin", "drip irrigation raised bed",
        "soil ph test kit garden", "hand woodworking tools beginner", "post office hours tracking",
        "local public transit schedule", "recycling guidelines city", "lawn aeration schedule",
    ],
}

QUERY_PATTERNS = [
    "{topic}",
    "{topic} tutorial",
    "how to use {topic}",
    "best {topic} guide",
    "{topic} tips",
    "{topic} review",
    "how to fix {topic} issue",
    "what is {topic}",
    "{topic} vs {alt}",
    "{topic} beginner guide",
]

COMMON_TOPICS = [topic for topics in REAL_INTERNET_THEMES.values() for topic in topics]

def load_wordlist(path: str, fallback: list[str] | None = None) -> list[str]:
    from .paths import resolve_resource
    try:
        with open(resolve_resource(path), encoding="utf-8", errors="ignore") as fh:
            words = [w.strip() for w in fh if w.strip()]
        return words if words else (fallback or COMMON_TOPICS)
    except OSError:
        return fallback or COMMON_TOPICS


_SEARCH_HOSTS = ("google.", "duckduckgo.", "bing.", "brave.", "startpage.", "ecosia.", "mojeek.", "qwant.",
                 "yahoo.", "yandex.", "baidu.")


def _unwrap_redirect(href: str, base: str) -> str:
    """Resolve search-engine redirect links (DDG /l/?uddg=, Google /url?q=, Bing ck/a?u=a1<b64>)."""
    import base64
    absu = urllib.parse.urljoin(base, href)
    p = urllib.parse.urlparse(absu)
    qs = urllib.parse.parse_qs(p.query)
    for key in ("uddg", "q", "url"):
        if key in qs and qs[key][0].startswith("http"):
            return qs[key][0]
    if "u" in qs and qs["u"][0].startswith("a1"):
        try:
            raw = qs["u"][0][2:]
            return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode()
        except Exception:
            pass
    return absu


_ENGINE_BRANDS = ("google", "duckduckgo", "bing", "brave", "startpage", "ecosia", "mojeek", "qwant", "microsoft")


def extract_result_links(html: str, search_url: str, limit: int = 12) -> list[str]:
    """Organic result URLs from a SERP's HTML, in page order, one per site."""
    from .safety import safe_domain
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    seen_hosts: set[str] = set()
    out: list[str] = []
    for href, text in zip(parser.links, parser.texts):
        u = _unwrap_redirect(href, search_url)
        p = urllib.parse.urlparse(u)
        host = (p.hostname or "").lower()
        if p.scheme not in ("http", "https") or not host or any(h in host for h in _SEARCH_HOSTS):
            continue
        if any(b in u.lower() for b in _ENGINE_BRANDS):        # the engine's own social profiles, apps…
            continue
        if len(" ".join(text.split())) < 12:                    # organic results have real titles
            continue
        if host in seen_hosts or not safe_domain(host):
            continue
        seen_hosts.add(host)
        out.append(u)
        if len(out) >= limit:
            break
    return out


@dataclass
class SearchTargetFactory:
    """Search noise: realistic queries from live/real sources, weighted engine choice,
    and click-through to a result (position-biased, like real users)."""
    rng: random.Random
    words: list[str]
    queries: object | None = None      # QuerySource; falls back to built-in topics
    html_mode: bool = True             # True for requests-based transport (needs server-rendered SERPs)

    def __post_init__(self) -> None:
        if self.queries is None:
            from .queries import QuerySource
            self.queries = QuerySource(self.rng, None, words=self.words)

    def make(self, identity) -> Target:
        endpoint = pick_search_endpoint(self.rng)
        if self.html_mode and "duckduckgo.com/?q=" in endpoint and "lite." not in endpoint:
            endpoint = "https://html.duckduckgo.com/html/?q="     # the JS-free results page
        query, origin = self.queries.next(identity)
        if SEARCH_OPTIONS["typos"] and self.rng.random() < 0.08:
            query = add_typo(self.rng, query)
        return Target(url=endpoint + urllib.parse.quote_plus(query), note=origin, role="search")

    def for_query(self, query: str, note: str | None = None) -> Target:
        """A search for exactly this query, on a weighted-random engine."""
        endpoint = pick_search_endpoint(self.rng)
        if self.html_mode and "duckduckgo.com/?q=" in endpoint and "lite." not in endpoint:
            endpoint = "https://html.duckduckgo.com/html/?q="
        return Target(url=endpoint + urllib.parse.quote_plus(query), note=note, role="search")

    def result_target(self, html: str, search_url: str, prefer_host: str | None = None) -> Target | None:
        links = [u for u in extract_result_links(html, search_url) if english_url(u)]
        if not links:
            return None
        # the top result about half the time, the rest falling off with position
        weights = [1.0] + [1.0 / (i + 1) ** 1.2 for i in range(1, len(links))]
        rest = sum(weights[1:])
        if rest:
            weights = [rest] + weights[1:]
        if prefer_host:                                   # looking for a particular site: it is the one clicked
            bare = prefer_host.lower().removeprefix("www.").split("/")[0]
            weights = [w * (50.0 if bare in (urllib.parse.urlparse(u).hostname or "").lower() else 1.0)
                       for w, u in zip(weights, links)]
        return Target(url=self.rng.choices(links, weights=weights)[0], referer=search_url, role="result")


class _LinkExtractor(HTMLParser):
    """Collects hrefs (self.links) and, in parallel, each link's visible text (self.texts)."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.texts: list[str] = []
        self._open: int | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for k, v in attrs:
                if k.lower() == "href" and v:
                    self.links.append(v)
                    self.texts.append("")
                    self._open = len(self.links) - 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a":
            self._open = None

    def handle_data(self, data: str) -> None:
        if self._open is not None:
            self.texts[self._open] += data


@dataclass
class CrawlTargetFactory:
    """Random-walk link crawler with same-site containment."""
    rng: random.Random
    seeds: list[str]
    max_depth: int = 4
    same_site_only: bool = True
    domains: object | None = None     # DomainPool: real popular sites as start points
    domain_mix: float = 0.65          # share of walks that start at a ranked domain, not a configured seed

    def make(self, identity) -> Target:
        if self.domains is not None and (not self.seeds or self.rng.random() < self.domain_mix):
            site = self.domains.visit_host()
            return Target(url=f"https://{site}" + ("" if "/" in site else "/"), note="popular site")
        seeds = self.seeds or ["https://en.wikipedia.org/wiki/Special:Random"]
        return Target(url=self.rng.choice(seeds))

    def next_from(self, html: str, current_url: str) -> Target | None:
        parser = _LinkExtractor()
        try:
            parser.feed(html)
        except Exception:
            pass
        base = urllib.parse.urlparse(current_url)
        here = urllib.parse.urldefrag(current_url)[0]
        links: list[str] = []
        for href in parser.links:
            absu = urllib.parse.urldefrag(urllib.parse.urljoin(current_url, href))[0]
            p = urllib.parse.urlparse(absu)
            if p.scheme not in ("http", "https") or absu == here or not _looks_like_page(p):
                continue
            if self.same_site_only and p.netloc.lower() != base.netloc.lower():
                continue
            if not english_url(absu):                    # English-language pages only
                continue
            links.append(absu)
        if not links:
            return None
        return Target(url=self.rng.choice(links), referer=current_url)


_SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".css", ".js", ".json", ".xml",
             ".pdf", ".zip", ".mp4", ".mp3", ".woff", ".woff2", ".rss", ".atom")
_SKIP_PATH = ("login", "signin", "sign-in", "signup", "register", "logout", "account", "cart", "checkout",
              "action=edit", "action=history", "special:", "/edit", "oldid=", "printable=", "share", "mailto")


def _looks_like_page(p) -> bool:
    """A link a reader would plausibly click: an HTML page, not an asset, form or account action."""
    path = (p.path or "/").lower()
    tail = (path + "?" + p.query).lower()
    return not path.endswith(_SKIP_EXT) and not any(x in tail for x in _SKIP_PATH)


# --- raw crafted DNS packets (clearnet DNS engine, stdlib only) ---



QTYPE = {"A": 1, "AAAA": 28, "HTTPS": 65}


def build_dns_query(domain: str, qid: int, qtype: str = "A") -> bytes:
    """One DNS question (A by default; AAAA or HTTPS too), header + punctuated labels."""
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(part)]) + part.encode("ascii", "ignore")
                 for part in domain.split(".") if part) + b"\x00"
    return header + q + struct.pack(">HH", QTYPE[qtype], 1)


def parse_dns_names(answer: bytes) -> list[str]:
    """Minimal parser: names in the answer section only (no compression walk)."""
    names = []
    try:
        qd, an = struct.unpack(">HH", answer[4:8])
        i = 12
        for _ in range(qd):
            while answer[i]:
                i += answer[i] + 1
            i += 5
        for _ in range(an):
            i += 2
            if answer[i] & 0xC0 == 0xC0:
                i += 2
            else:
                while answer[i]:
                    i += answer[i] + 1
                i += 1
            rtype, _, _, rdlen = struct.unpack(">HHIH", answer[i:i + 10])
            i += 10 + rdlen
            # names: header + labels we can recover from the question echo
        _ = names
    except (IndexError, struct.error):
        return []
    return names


class DnsNoise:
    """Lookups of REAL, popular domains (Tranco ranking) to public resolvers, packets crafted by hand.

    Clearnet engine only: the Tor lane visits .onion sites and makes no DNS noise. Invented domains are
    never generated: a stream of NXDOMAINs is itself a tell.
    """

    def __init__(self, rng: random.Random, words: list[str] | None = None, domains=None, plan=None):
        from .domains import DomainPool
        self.rng = rng
        self.domains = domains or DomainPool(rng)
        self.plan = plan                     # DnsPlan; None = your normal (system) resolver

    def make_query(self) -> tuple[bytes, str, str]:
        """(packet, domain, server). server "system" = the OS resolver; else a resolver IP."""
        domain = self.domains.hostname()
        packet = build_dns_query(domain, qid=self.rng.randint(0, 0xFFFF))
        server = self.plan.pick()[0] if self.plan is not None else "system"
        return packet, domain, server

    @staticmethod
    def resolve_system(domain: str, timeout: float = 4.0) -> bool:
        """Look the name up exactly as any app would: through the OS resolver (router/ISP/VPN DNS)."""
        import concurrent.futures
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            res = ex.submit(socket.getaddrinfo, domain, 443, 0, socket.SOCK_STREAM).result(timeout=timeout)
            from .observe import note
            for info in res[:4]:
                note(info[4][0], domain)
            return bool(res)
        except Exception:
            return False
        finally:
            ex.shutdown(wait=False)

    def fire(self, packet: bytes, server: str, timeout: float = 3.0) -> bool:
        """Send one UDP query; return True if a parseable answer came back."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(512)
            return len(data) >= 12
        except OSError:
            return False
        finally:
            sock.close()
