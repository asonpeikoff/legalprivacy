"""Directional nudges for the traffic mix: a few buttons that move one share up or down a step.

The mix is three relative weights (web pages in a real browser, web pages over plain HTTP, Tor .onion sites)
plus the share of noise that is a phone. A nudge turns the weights into percentages that add up to 100, moves
one of them by `step` points, and hands that change to the others in proportion (or takes it from them), so
the total stays at 100 and nothing goes negative.
"""
from __future__ import annotations

from .config import ConfigError

KINDS = ("browser", "plain", "onion")
STEP = 10.0          # percentage points per button press
FLOOR = 0.0


def shares(weights: dict[str, float], kinds: tuple[str, ...] = KINDS) -> dict[str, float]:
    """The weights of `kinds` as percentages adding up to 100 (all zero stays all zero)."""
    w = {k: max(0.0, float(weights.get(k, 0.0))) for k in kinds}
    tot = sum(w.values())
    return {k: (v / tot * 100.0 if tot else 0.0) for k, v in w.items()}


def nudge_shares(weights: dict[str, float], kind: str, direction: int,
                 kinds: tuple[str, ...] = KINDS, step: float = STEP) -> dict[str, float]:
    """The new percentages after moving `kind` up (direction > 0) or down (direction < 0) by `step` points.

    The other kinds absorb the change in proportion to their current share; when they all sit at zero, the
    change goes to the first of them (so "less web browser" with only browser on still has somewhere to go).
    The result is rounded to 0.1 and always adds up to 100.
    """
    if kind not in kinds:
        raise ConfigError(f"traffic mix: unknown kind '{kind}'")
    cur = shares(weights, kinds)
    if not any(cur.values()):
        cur = {k: (100.0 if k == kinds[0] else 0.0) for k in kinds}
    others = [k for k in kinds if k != kind]
    if not others:
        return {kind: 100.0}
    delta = step if direction > 0 else -step
    new_kind = min(100.0, max(FLOOR, cur[kind] + delta))
    moved = new_kind - cur[kind]                          # what the others give up (or take back)
    rest = sum(cur[k] for k in others)
    out = {kind: new_kind}
    for k in others:
        if rest > 0:
            out[k] = max(0.0, cur[k] - moved * cur[k] / rest)
        else:
            out[k] = max(0.0, -moved) if k == others[0] else 0.0
    tot = sum(out.values()) or 1.0
    out = {k: round(v / tot * 100.0, 1) for k, v in out.items()}
    out[kind] = round(100.0 - sum(v for k, v in out.items() if k != kind), 1)     # fix rounding drift
    return out


def nudge_phones(share: float, direction: int, step: float = STEP) -> float:
    """The new phone share (0 to 1) after one step."""
    pct = round(float(share) * 100.0 + (step if direction > 0 else -step), 1)
    return round(min(100.0, max(0.0, pct)) / 100.0, 3)
