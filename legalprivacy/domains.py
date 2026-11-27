"""Real, popular, safe domains (Tranco ranking) for DNS lookups and page visits."""
from __future__ import annotations

import random
from collections import deque

from .feeds import FeedStore
from .safety import safe_domain

# Used only when the Tranco list has not been downloaded yet. All real, mainstream, non-government.
FALLBACK_DOMAINS = [
    "wikipedia.org", "mozilla.org", "python.org", "github.com", "stackoverflow.com", "bbc.com",
    "nytimes.com", "theguardian.com", "reuters.com", "apnews.com", "npr.org", "weather.com", "imdb.com",
    "reddit.com", "linkedin.com", "amazon.com", "ebay.com", "etsy.com", "walmart.com", "target.com",
    "bestbuy.com", "wired.com", "arstechnica.com", "theverge.com", "medium.com", "quora.com", "yelp.com",
    "tripadvisor.com", "booking.com", "espn.com", "archive.org", "spotify.com", "netflix.com", "twitch.tv",
    "pinterest.com", "cnn.com", "bloomberg.com", "forbes.com", "cnet.com", "techcrunch.com",
    "khanacademy.org", "coursera.org", "duolingo.com", "goodreads.com", "allrecipes.com", "healthline.com",
    "mayoclinic.org", "webmd.com", "stackexchange.com", "wikihow.com",
]


_VISIT_TLDS = (".com", ".org", ".edu", ".io", ".co", ".uk", ".de", ".fr", ".ca", ".au", ".jp", ".in", ".it",
               ".es", ".nl", ".se", ".no", ".ch", ".br", ".mx", ".tv", ".me", ".news", ".info", ".ru", ".pl")
_NOT_A_SITE = ("domaincontrol", "appsflyer", "relay", "update", "sdk", "api", "analytics", "tracking",
               "metrics", "telemetry", "push", "ntp", "ocsp", "crl", "pki", "cert", "gateway", "auth", "login",
               "sso", "edge", "cache", "static", "assets", "dns", "smtp", "mail.", "myfritz", "ddns", "dyndns",
               "no-ip", "goo.gl", "youtu.be", "t.co", "bit.ly", "lnkd.in", "sharepoint", "office", "outlook",
               "windowsupdate", "icloud", "whatsapp.net", "gandi", "h264", "cloud.microsoft", "triplink", "intl",
               "adservice", "adsystem", "ads.", "pixel", "beacon", "consent", "onetrust", "cookielaw",
               "nocookie", "verifier", "security", "ad-tech", "adtech", "cdn", "kazna", "gosuslugi", "nalog",
               "gov.", "mux.com", "eeroup", "cloudapp")


# Celebrity, gossip and tabloid sites: the default (Ason) persona does not browse these, so the generic
# "popular sites" draw skips them. Matched on the site name with "www." and a leading "m." removed.
_ENTERTAINMENT_NEWS = frozenset({
    "people.com", "ew.com", "tmz.com", "usmagazine.com", "eonline.com", "pagesix.com", "dailymail.co.uk",
    "hollywoodreporter.com", "variety.com", "deadline.com", "billboard.com", "rollingstone.com", "vulture.com",
    "buzzfeed.com", "popsugar.com", "justjared.com", "perezhilton.com", "radaronline.com", "okmagazine.com",
    "intouchweekly.com", "lifeandstylemag.com", "hellomagazine.com", "closermag.com", "enstarz.com",
    "celebuzz.com", "thesun.co.uk", "mirror.co.uk", "metro.co.uk", "gossipcop.com", "hollywoodlife.com",
    "etonline.com", "extratv.com", "accesshollywood.com", "entertainmentweekly.com", "tvguide.com",
    "pinkvilla.com", "bollywoodhungama.com", "koimoi.com", "ranker.com", "screenrant.com", "cbr.com",
})


def is_entertainment_news(domain: str) -> bool:
    d = domain.lower().removeprefix("www.").removeprefix("m.")
    return d in _ENTERTAINMENT_NEWS


def looks_browsable(domain: str) -> bool:
    """Heuristic: a site a person would open in a browser, not infrastructure behind one."""
    d = domain.lower()
    label = d.split(".")[0]
    return (d.endswith(_VISIT_TLDS) and not any(p in d for p in _NOT_A_SITE)
            and not any(ch.isdigit() for ch in label) and len(label) <= 18 and label.count("-") <= 1)


class DomainPool:
    def __init__(self, rng: random.Random, store: FeedStore | None = None,
                 my_sites: list[str] | None = None, random_share: float = 0.3,
                 my_weights: dict | None = None):
        self.rng = rng
        self.store = store
        self.my_sites = [s for s in (my_sites or []) if safe_domain(s)]   # most-visited first
        self.random_share = random_share
        self.my_weights = my_weights or {}
        self.interests = None              # Interests (optional personas)
        self.interest_share = 0.0
        self.site_list = "both"            # both | crux | tranco
        self.avoid_entertainment = False   # skip celebrity and gossip sites in the generic popular-sites draw
        self._recent: deque[str] = deque(maxlen=60)
        self._seen_good: deque[str] = deque(maxlen=300)    # sites reached by clicking search results

    def _themed(self, with_path: bool = False) -> str | None:
        """A site from the persona or interests. Some are a section of a site ("reddit.com/r/datascience/");
        with_path=False gives just the site's name (for DNS lookups)."""
        if self.interests is not None and self.rng.random() < self.interest_share:
            s = self.interests.site()
            host = s.split("/", 1)[0]
            if not safe_domain(host):
                return None
            return s if with_path else host
        return None

    def remember(self, host: str) -> None:
        """Record a site the user persona actually reached organically (used as a later start point)."""
        if host and host not in self._seen_good and safe_domain(host):
            self._seen_good.append(host)

    def _mine(self) -> str | None:
        """A site from My List, or None when this draw should come from the other sources."""
        if not self.my_sites or self.rng.random() < self.random_share:
            return None
        if self.my_weights:                                              # your own "how often"
            weights = [float(self.my_weights.get(s, 3.0)) for s in self.my_sites]
        else:
            weights = [1.0 / (i + 3) for i in range(len(self.my_sites))]    # your top sites most often
        return self.rng.choices(self.my_sites, weights=weights)[0]

    def _ranked(self) -> list[str]:
        ranked = self.store.items("tranco") if self.store else []
        deny = self.store.denylist() if self.store else set()
        ranked = [d for d in ranked if safe_domain(d, deny)
                  and not (self.avoid_entertainment and is_entertainment_news(d))]
        return ranked or FALLBACK_DOMAINS

    def _crux_boost(self) -> dict[str, float]:
        """How much more often to pick a site that real Chrome users load a lot (CrUX).
        CrUX is never a source on its own (the global list holds too much adult and gambling
        content to filter reliably): it only re-ranks sites already on the filtered Tranco list."""
        if self.site_list != "both" or not self.store:
            return {}
        if getattr(self, "_boost_cache", None) is None:
            boost = {}
            for it in self.store.items("crux"):
                host, _, rank = it.partition("|")
                boost[host.removeprefix("www.")] = 3.0 if rank == "1000" else 1.5
            self._boost_cache = boost
        return self._boost_cache

    def pick(self, browsable: bool = False) -> str:
        """Zipf-weighted draw: popular sites dominate, like real browsing, but the tail still appears.
        browsable=True restricts to things people open in a browser (DNS lookups use everything)."""
        mine = self._themed() or self._mine()
        if mine:
            self._recent.append(mine)
            return mine
        ranked = self._ranked()
        if browsable:
            ranked = [x for x in ranked[:1500] if looks_browsable(x)] or FALLBACK_DOMAINS
        boost = self._crux_boost()
        weights = [boost.get(x, 1.0) / (i + 8) for i, x in enumerate(ranked)]
        for _ in range(6):
            d = self.rng.choices(ranked, weights=weights)[0]
            if d not in self._recent:
                break
        self._recent.append(d)
        return d

    def hostname(self) -> str:
        d = self.pick()
        return f"www.{d}" if self.rng.random() < 0.45 and d.count(".") == 1 else d

    def visit_host(self) -> str:
        """A site to open: My List first (if set), else one reached earlier via search, else a popular site."""
        themed = self._themed(with_path=True)
        if themed and ("/" in themed or themed.startswith("www.")):
            return themed                                   # exactly as listed
        mine = themed or self._mine()
        if mine:
            return f"www.{mine}" if mine.count(".") == 1 and self.rng.random() < 0.6 else mine
        if self._seen_good and self.rng.random() < 0.5:
            return self.rng.choice(list(self._seen_good))
        d = self.pick(browsable=True)
        return f"www.{d}" if d.count(".") == 1 and self.rng.random() < 0.6 else d
