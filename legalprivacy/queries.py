"""Realistic query generation: a weighted mix of real-world sources.

Why a mix: any single fixed pool (especially a small hand-written one) would be
hit at a far higher rate than real users hit it, which is itself a fingerprint.
So no source dominates, the hand-written list is a minority, and every
generated query is de-duplicated against recent history.
"""
from __future__ import annotations

import random
import re
from collections import deque
from dataclasses import dataclass

from .feeds import FeedStore
from .safety import safe_query

# ---- small built-in fallback (minority source; also used when offline) ------
BUILTIN_THEMES: dict[str, list[str]] = {
    "tech": ["python", "linux", "docker", "kubernetes", "rust language", "git commands", "sqlite database",
             "bash scripting", "ssh keys setup", "raspberry pi projects", "home assistant", "nginx reverse proxy",
             "rest api", "tailwind css", "react components", "typescript tutorial", "dns record types"],
    "cooking": ["sourdough bread recipe", "cast iron seasoning", "pasta carbonara", "easy weeknight dinner",
                "air fryer chicken breast", "chocolate chip cookies", "thai green curry", "vegetarian chili",
                "meal prep containers", "french press ratio", "roasted vegetables", "homemade pizza dough"],
    "travel": ["flight tracker live", "national park annual pass", "hiking boots lightweight",
               "camping checklist", "carry on bag dimensions", "scenic train routes", "hotel booking discounts",
               "travel insurance comparison", "road trip map offline", "campsite reservation tips"],
    "entertainment": ["movie showtimes today", "sci fi novels", "indie video games", "vinyl record player",
                      "streaming series release dates", "audio drama podcasts", "fantasy book series",
                      "concert tour dates", "board games strategy"],
    "health_fitness": ["5k running schedule beginner", "morning mobility routine", "core strength exercises",
                       "stretching for lower back", "healthy meal prep ideas", "kettlebell workout",
                       "sleep tracking accuracy", "electrolyte drinks"],
    "science_nature": ["james webb telescope images", "solar eclipse path", "bird migration tracker",
                       "mycelium network", "quantum computing basics", "deep sea exploration",
                       "renewable energy battery", "night sky constellations"],
    "home_daily": ["indoor plants low light", "compost tumbler", "drip irrigation raised bed",
                   "soil ph test kit", "hand woodworking tools", "local public transit schedule",
                   "recycling guidelines", "lawn aeration schedule"],
}
BUILTIN_TOPICS = [t for v in BUILTIN_THEMES.values() for t in v]
PATTERNS = ["{t}", "{t}", "{t} tutorial", "how to use {t}", "best {t}", "{t} tips", "{t} review",
            "what is {t}", "{t} for beginners", "{t} near me", "{t} reddit", "{t} guide"]
REFINERS = {   # refine in a way that fits where the query came from
    "live": ["news", "wiki", "latest", "explained", "2026", "reddit", "images", "today", "update"],
    "builtin": ["review", "reviews", "price", "near me", "reddit", "for beginners", "cheap", "best",
                "youtube", "examples", "tutorial", "2026"],
    "words": ["meaning", "synonym", "pronunciation", "in a sentence"],
}
_STOP = set(["a", "an", "the", "of", "to", "in", "on", "for", "and", "or", "but", "with", "as", "at", "by", "from", "is", "are", "was", "were", "be", "been", "it", "its", "this", "that", "these", "those", "has", "have", "had", "will", "would", "could", "should", "can", "may", "might", "says", "say", "said", "after", "over", "into", "about", "amid", "than", "then", "just", "more", "most", "new", "why", "how", "what", "who", "when", "where", "which", "watch"])


def headline_to_query(h: str) -> str:
    """News headline -> what a reader would actually type: the main clause, content words, 2-6 of them."""
    h = re.split(r"[:|–—]| - ", h)[0]
    h = re.sub(r"['’]s\b", "", h)
    h = re.sub(r"[\"‘’“”']", "", h)
    words = [w.strip(",.?!()") for w in h.split()]
    words = [w for w in words if w and w.lower() not in _STOP and not w.isdigit()]
    return " ".join(words[:6])

WEIGHTS = {"live": 0.38, "dataset": 0.34, "builtin": 0.10, "words": 0.04}


@dataclass
class QueryConfig:
    live: bool = True
    dataset: bool = True
    builtin: bool = True
    words: bool = True


def _typo(rng: random.Random, q: str) -> str:
    """Rare adjacent-letter swap inside a longer word, the way fast typists err."""
    words = q.split(" ")
    idx = [i for i, w in enumerate(words) if len(w) >= 5 and w.isalpha()]
    if not idx:
        return q
    i = rng.choice(idx)
    w = words[i]
    j = rng.randrange(1, len(w) - 2)
    words[i] = w[:j] + w[j + 1] + w[j] + w[j + 2:]
    return " ".join(words)


class QuerySource:
    def __init__(self, rng: random.Random, store: FeedStore | None, cfg: QueryConfig | None = None,
                 words: list[str] | None = None):
        self.rng = rng
        self.store = store
        self.cfg = cfg or QueryConfig()
        # dictionary words are a small garnish: short common-looking lowercase words only
        self.words = [w for w in (words or []) if 4 <= len(w) <= 8 and w.isalpha() and w.islower()][:200_000]
        self._recent: deque[str] = deque(maxlen=500)
        self._last: dict[int, str] = {}
        self.interests = None              # Interests (optional personas)
        self.interest_share = 0.0
        self.narrative_share = 0.55        # how often a search starts a run of related searches
        self._threads: dict[int, deque[tuple[str, str]]] = {}

    def _pools(self) -> dict[str, list[str]]:
        st = self.store
        pools: dict[str, list[str]] = {}
        if st:
            if self.cfg.live:
                news = [headline_to_query(h) for h in st.items("news")]
                wiki = [re.sub(r"\s*\([^)]*\)$", "", t) for t in st.items("wiki")]   # drop "(disambiguation)"
                live = st.items("trends") + wiki + [q for q in news if len(q.split()) >= 2]
                if live:
                    pools["live"] = live
            if self.cfg.dataset:
                ds = st.items("dataset")
                if ds:
                    pools["dataset"] = ds
        if self.cfg.builtin or not pools:           # never run completely dry
            pools["builtin"] = BUILTIN_TOPICS
        if self.cfg.words and self.words:
            pools["words"] = self.words
        return pools

    def next(self, identity=None) -> tuple[str, str]:
        """Return (query, origin). origin ∈ live|dataset|builtin|words|refine."""
        ident = getattr(identity, "id", None)
        last = self._last.pop(ident, None)            # refine at most once per base query
        prev, prev_origin = last if last else (None, None)
        th = self._threads.get(ident)
        while th:                                     # the run of related searches this identity is in the middle of
            q, org = th.popleft()                     # a follow-up keeps the origin of the search it follows
            if self.rng.random() < 0.88 and safe_query(q) and q.lower() not in self._recent:
                return self._finish(ident, q, org, follow=True)
        if prev and prev_origin in REFINERS and len(prev.split()) <= 4 and "?" not in prev \
                and not prev.startswith(("define ",)) and self.rng.random() < 0.22:
            q = f"{prev} {self.rng.choice(REFINERS[prev_origin])}"     # a person narrows the previous search
            if safe_query(q) and q not in self._recent:
                return self._finish(ident, q, "refine")
        if self.interests is not None and self.rng.random() < self.interest_share:
            for _ in range(4):
                q = self.interests.query()
                if safe_query(q) and q not in self._recent:
                    return self._finish(ident, q, "interest")
        pools = self._pools()
        names = list(pools)
        # de-dup window scales with how much material there is, so small pools aren't starved
        window = max(10, min(500, sum(len(v) for k, v in pools.items() if k != "words") // 4))
        recent = {r.lower() for r in list(self._recent)[-window:]}
        minor = ("builtin", "words")
        major_orig = sum(WEIGHTS[n] for n in names if n not in minor)
        while names:
            # an exhausted major source hands its share to the other major sources, never to the
            # hand-written list — that list must stay a small minority (a big share is a fingerprint)
            major_now = sum(WEIGHTS[n] for n in names if n not in minor)
            scale = (major_orig / major_now) if major_now else 1.0
            origin = self.rng.choices(names, weights=[WEIGHTS[n] * (1 if n in minor else scale)
                                                      for n in names])[0]
            for _ in range(6):              # stay with the chosen source; retry within it on a repeat
                raw = self.rng.choice(pools[origin])
                if origin == "builtin":
                    raw = self.rng.choice(PATTERNS).format(t=raw)
                elif origin == "words":
                    raw = self.rng.choice(["{w}", "{w} meaning", "define {w}", "{w} synonym"]).format(w=raw)
                if raw.lower() not in recent and safe_query(raw):
                    return self._finish(ident, raw, origin)
            names.remove(origin)            # this source is used up for now
        biggest = max(pools, key=lambda n: len(pools[n]))  # everything recently used: allow a repeat
        return self._finish(ident, self.rng.choice(pools[biggest]), biggest)

    def _finish(self, ident, q: str, origin: str, follow: bool = False) -> tuple[str, str]:
        q = re.sub(r"\s+", " ", q).strip()
        if q.endswith("?") and self.rng.random() < 0.7:   # most people don't type the question mark
            q = q[:-1].rstrip()
        if self.rng.random() < 0.85:
            q = q.lower()
        if origin != "dataset" and self.rng.random() < 0.03:
            q = _typo(self.rng, q)
        self._recent.append(q)
        if not follow and origin not in ("refine", "words") and self.rng.random() < self.narrative_share:
            from .narrative import follow_ups
            ups = follow_ups(self.rng, q, list(self._recent)[-60:])
            if ups:
                self._threads[ident] = deque((u, origin) for u in ups)
        if origin != "refine" and not follow:
            self._last[ident] = (q, origin)
        if len(self._last) > 200:
            self._last.pop(next(iter(self._last)))
        if len(self._threads) > 200:
            self._threads.pop(next(iter(self._threads)))
        return q, origin
