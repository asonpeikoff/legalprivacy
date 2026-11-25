"""Search narratives and chat scripts: noise that hangs together the way a person's does.

Researchers separated query-obfuscation noise from real searching by clustering the queries by meaning: a person's
searches come in related runs (a topic, then a narrower question, a comparison, a "best" or "how to"), while random
queries sit alone. So noise should come in runs too. This module makes the runs (follow-up searches for a topic) and the
short scripts for a chat on duck.ai (one topic, a few turns, varied lengths), and measures how related a run is.
"""
from __future__ import annotations

import random
import re
import time

_STOP = frozenset("a an the of to in on for and or but with as at by from is are was were be it its this that these "
                  "those how what which who why when where do does did can could should would my your best vs".split())


def tokens(q: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", q.lower()) if w not in _STOP and len(w) > 1}


def coherence(queries: list[str]) -> float:
    """How related consecutive queries are, 0 (nothing in common) to 1: mean overlap (Jaccard) of the words of each query with
    the one before it. Real search sessions sit well above random queries, which sit near 0."""
    pairs = [(tokens(a), tokens(b)) for a, b in zip(queries, queries[1:], strict=False)]
    vals = [len(a & b) / len(a | b) for a, b in pairs if a | b]
    return sum(vals) / len(vals) if vals else 0.0


def _year() -> int:
    return time.localtime().tm_year


_SUFFIXES = ["review", "reviews", "price", "reddit", "for beginners", "tutorial", "guide", "tips", "examples",
             "alternatives", "problems", "near me", "cheap", "free", "pdf", "youtube", "forum", "history"]
_PREFIXES = ["best", "how to use", "what is", "is {t} worth it", "why is {t}", "how does {t} work", "{t} or"]


def follow_ups(rng: random.Random, query: str, neighbours: list[str] | None = None, limit: int = 4) -> list[str]:
    """The searches that tend to follow `query` in one sitting: narrower, a comparison with a related thing, a quality or
    price check, a how-to. `neighbours` are other queries from the same source; one that shares a word with this one is
    used for a "this vs that" comparison."""
    base = re.sub(r"\s+", " ", query.strip().lower())
    if not base or len(base.split()) > 6:
        return []
    out: list[str] = []
    n = rng.choices([1, 2, 3, 4], weights=[4, 4, 2, 1])[0]
    mine = tokens(base)
    related = [x for x in (neighbours or []) if x.lower() != base and mine & tokens(x) and len(x.split()) <= 4]
    kinds = ["suffix", "prefix", "year", "compare" if related else "suffix", "suffix"]
    rng.shuffle(kinds)
    for kind in kinds:
        if len(out) >= min(n, limit):
            break
        if kind == "suffix":
            q = f"{base} {rng.choice(_SUFFIXES)}"
        elif kind == "prefix":
            pre = rng.choice(_PREFIXES)
            q = pre.format(t=base) if "{t}" in pre else f"{pre} {base}"
        elif kind == "year":
            q = f"{base} {_year()}"
        else:
            q = f"{base} vs {rng.choice(related).lower()}"
        q = re.sub(r"\s+", " ", q).strip()
        if q not in out and q != base:
            out.append(q)
    return out


# ── chat scripts (duck.ai) ─────────────────────────────────────────────────────────────────────────────────────────
_OPENERS = [
    "what is {t}", "can you explain {t}", "tell me about {t}", "i'm new to {t}, where do i start",
    "give me a quick overview of {t}", "how does {t} work", "what are the pros and cons of {t}",
    "i keep hearing about {t}. is it worth learning", "help me understand {t}", "{t}",
]
_CONTEXT = [
    "i have about an hour a week to spend on it.", "i'm mostly interested in the practical side.",
    "i tried reading about it before but it was confusing.", "assume i know the basics.",
    "i want something i can actually use this month.", "keep it simple please.",
    "a friend recommended it but didn't say much.", "i don't have a big budget.",
]
_FOLLOWS = [
    "can you give me an example", "what would you do first", "what are the common mistakes",
    "explain that more simply", "what about the downsides", "is there a cheaper way", "and how long does that take",
    "can you summarize that in three points", "what should i read next", "thanks, one more thing: how do i know it's working",
    "how is that different from the alternatives", "ok and what if that doesn't work",
]


def chat_script(rng: random.Random, topic: str) -> list[str]:
    """A short chat about one topic: an opener (sometimes with a line of context), then 0-3 follow-ups. The number of turns
    and the length of each message vary, because the size and timing of a chat's traffic follows the length of what is
    sent and what comes back, and a fixed shape would be a pattern of its own."""
    t = re.sub(r"\s+", " ", topic.strip().lower())
    opener = rng.choice(_OPENERS).format(t=t)
    if rng.random() < 0.45:
        opener = f"{opener}. {rng.choice(_CONTEXT)}" if not opener.endswith("?") else f"{opener} {rng.choice(_CONTEXT)}"
    if rng.random() < 0.2:                                   # a long, rambling first message now and then
        opener += " " + " ".join(rng.sample(_CONTEXT, k=min(3, len(_CONTEXT))))
    turns = [opener]
    for _ in range(rng.choices([0, 1, 2, 3], weights=[3, 4, 3, 1])[0]):
        turns.append(rng.choice(_FOLLOWS))
    return turns

