"""Human-cadence pacing: lognormal delays, diurnal curve, failure backoff."""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field

from .humanize import lognormal_clipped


@dataclass
class Pacer:
    """Randomized pacing within configurable ranges with natural human entropy."""
    rng: random.Random
    min_delay: float = 3.0     # min bound for standard interval
    max_delay: float = 25.0    # max bound for standard interval
    mu: float = 2.2            # legacy parameter preserved for backwards-compatibility
    sigma: float = 0.9         # legacy parameter preserved
    min_gap: float = 1.5       # burst suppression lower bound
    realtime_scale: float = 1.0
    pace_multiplier: float = 1.0
    diurnal: bool = True
    _backoff: float = 0.0
    sleep_fn: object = time.sleep

    def next_delay(self, now_local_hour: float | None = None) -> float:
        """Seconds until next hit: randomly selected within reasonable range."""
        if self._backoff:
            delay = self._backoff          # backoff is real time, never scaled down
            self._backoff = 0.0
            return delay

        # Random sampling across natural human browsing activities:
        roll = self.rng.random()
        if roll < 0.20:
            # Rapid follow-up (clicking a search result or related link)
            base = self.rng.uniform(self.min_gap, max(self.min_gap, self.min_delay))
        elif roll < 0.85:
            # Standard browsing: randomly drawn within the user's reasonable range
            base = self.rng.uniform(self.min_delay, self.max_delay) * self.pace_multiplier
        else:
            # Reading / dwell pause (looking through an article or reading results)
            base = self.rng.uniform(self.max_delay, self.max_delay * 2.2) * self.pace_multiplier

        # Optional diurnal context modulation with high-entropy jitter (never a rigid mathematical divisor)
        if self.diurnal and now_local_hour is not None:
            df = diurnal_factor(now_local_hour)
            jitter = self.rng.uniform(0.85, 1.15)
            base = base / (df * jitter)

        return max(base, self.min_gap) * self.realtime_scale

    def backoff_pending(self) -> float:
        return self._backoff

    def wait(self, now_local_hour: float | None = None) -> float:
        delay = self.next_delay(now_local_hour)
        self.sleep_fn(delay)
        return delay

    def on_failure(self, attempt: int) -> float:
        """Exponential backoff with jitter after a 403/429/timeout."""
        self._backoff = min(2 ** attempt, 600) * (0.8 + 0.4 * self.rng.random())
        return self._backoff


def diurnal_factor(hour: float) -> float:
    """Local-hour activity multiplier: smooth diurnal curve peaking 19:00–22:00, trough 04:00–05:00.

    Returns a factor in [0.35, 1.6]; divide drawn delays by it.
    """
    h = hour % 24.0
    phase = 2 * math.pi * ((h - 4.5) % 24.0) / 24.0
    wave = 0.5 - 0.5 * math.cos(phase)
    d_eve = min((h - 21.0) % 24.0, (21.0 - h) % 24.0)
    eve_boost = math.exp(-0.5 * (d_eve / 2.5) ** 2)
    combined = 0.5 * wave + 0.5 * eve_boost
    norm = max(0.0, min(1.0, (combined - 0.005) / 0.84))
    return 0.35 + 1.25 * norm


@dataclass
class SessionPacer:
    """People come in sittings: a few searches close together, then a long gap, then again.

    Inside a sitting the gaps are seconds to a minute (clicking through, next search).
    Between sittings the gap is sized from the time and the hits left in the hour, so the
    planned hourly total still fits. The result is irregular: never a steady drip.
    """
    rng: random.Random
    left: int = 0                       # hits left in the current sitting

    def next_gap(self, hits_left: int, seconds_left: float, scale: float = 1.0) -> float:
        """Wall-clock seconds to wait before the next hit."""
        if self.left > 0:
            self.left -= 1
            return lognormal_clipped(self.rng, 9.0, 0.7, 2.0, 90.0) * scale
        self.left = max(0, int(round(self.rng.lognormvariate(math.log(3.0), 0.6))) - 1)
        sittings_left = max(1.0, hits_left / 3.6)                 # ~3.6 hits per sitting
        mean_idle = max(20.0, seconds_left / sittings_left)
        idle = lognormal_clipped(self.rng, mean_idle * 0.7, 0.8, 20.0, 7200.0)
        return min(idle, max(30.0, seconds_left))


@dataclass
class Budget:
    """Daily per-engine budget drain."""
    per_day: int
    spent: int = 0
    failures: int = 0
    history: list[float] = field(default_factory=list)  # spent timestamps for shrinkage

    @property
    def remaining(self) -> int:
        return max(0, self.per_day - self.spent)

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0

    def record_hit(self, t: float) -> None:
        self.spent += 1
        self.history.append(t)

    def record_failure(self, t: float) -> None:
        """Failures don't drain the hit budget and never stop the run (they are only counted for the statistics)."""
        self.failures += 1
        self.history.append(t)
