"""How much noise per hour.

The user picks an activity LEVEL (1-10) on a slider. The recommended mode,
"random", varies the amount every hour around that level (log-normal), follows
a day/night curve, and leaves some hours almost empty, the way a person is busy,
then away. "steady" keeps the same amount every hour.

Benchmark used to label the slider: active US desktop users run about 126 Google
searches a month (SparkToro/Datos, 2024), roughly 4 a day on average. That is a mean
pulled up by heavy users (median ~53 a month, under 2 a day) and excludes mobile apps. Noise only hides you if it is at least comparable to your real
activity, so even the middle levels are deliberately busier than that average.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass

from .pacing import diurnal_factor

# searches per hour at each slider level (1..10), the average. In random mode busy hours go well above it.
# A busy person searches far more than the population average below (heavy phone users search over a hundred
# times in a busy hour), so the upper levels are meant to cover that. engines.py caps every engine at
# MAX_SEARCHES_PER_ENGINE_PER_HOUR, so at the top levels the searches spread over more engines.
SEARCHES_PER_HOUR = [1, 2, 4, 7, 11, 17, 25, 36, 50, 70]
LEVEL_NAMES = ["barely there", "very light", "light", "light-moderate", "moderate",
               "moderate-busy", "busy", "very busy", "heavy", "very heavy"]
AVG_PERSON_SEARCHES_PER_DAY = 4.2      # SparkToro 2024, active US desktop users (126/month)


@dataclass
class RateConfig:
    mode: str = "random"          # random (recommended) | steady
    level: float = 5.0            # 1..10 slider: the average amount, in both modes
    randomness: float = 1.0       # 0 = steady .. 1 = fully random; in between = partly each
    auto_correct: bool = True     # plan more noise in the hours you are away and less in your busy ones (see Proof)

    def validate(self) -> None:
        if self.mode not in ("random", "steady"):
            raise ValueError("rate.mode must be random or steady")
        if not 1 <= float(self.level) <= 10:
            raise ValueError("rate.level must be between 1 and 10")
        if not 0 <= float(self.randomness) <= 1:
            raise ValueError("rate.randomness must be between 0 and 1")


def searches_per_hour(level: float) -> float:
    """Interpolate the table for fractional slider positions."""
    lv = min(10.0, max(1.0, float(level))) - 1
    lo, hi = int(math.floor(lv)), min(9, int(math.floor(lv)) + 1)
    f = lv - lo
    return SEARCHES_PER_HOUR[lo] * (1 - f) + SEARCHES_PER_HOUR[hi] * f


def describe(level: float, search_share: float) -> dict:
    """Numbers for the UI slider label."""
    s = searches_per_hour(level)
    total = s / max(search_share, 0.05)
    return {"level": level, "name": LEVEL_NAMES[int(round(level)) - 1],
            "searches_per_hour": round(s, 1), "actions_per_hour": round(total),
            "searches_per_day_awake": round(s * 15), "vs_average_person": round(s * 15 / AVG_PERSON_SEARCHES_PER_DAY, 1)}


class RatePlanner:
    """Hourly plan. Real activity drifts: it never jumps from busy to dead in one hour.

    * busy/quiet level is a smoothed random walk (each hour keeps most of the last one),
    * each day gets its own overall volume (some days heavier than others),
    * "away" spells last several hours and ramp in and out instead of switching off.
    """

    def __init__(self, rng: random.Random, cfg: RateConfig):
        self.rng, self.cfg = rng, cfg
        self._wobble = 0.0            # log of the smoothed busy/quiet level
        self._away = False
        self._away_level = 1.0        # 1.0 when at the computer, ramps toward 0.1 when away
        self._day_mult = 1.0
        self._last_hour = -1
        self.gain_fn = None           # hour -> multiplier, from what the observer saw of your own traffic

    def actions_for_hour(self, hour: int, search_share: float) -> float:
        """Total actions (all engines) planned for the given local hour, corrected toward your own rhythm."""
        v = self._plan_hour(hour, search_share)
        if self.gain_fn is not None and getattr(self.cfg, "auto_correct", False):
            try:
                v *= float(self.gain_fn(hour))
            except Exception:
                pass
        return v

    def _plan_hour(self, hour: int, search_share: float) -> float:
        base = searches_per_hour(self.cfg.level) / max(search_share, 0.05)
        r = 0.0 if self.cfg.mode == "steady" else min(1.0, max(0.0, float(self.cfg.randomness)))
        if r == 0:
            return base
        if self._last_hour < 0 or hour <= self._last_hour:     # first plan, or a new day
            self._day_mult = self.rng.lognormvariate(0.0, 0.25)
        self._last_hour = hour
        self._wobble = 0.65 * self._wobble + self.rng.gauss(0.0, 0.3)
        self._away = self.rng.random() < (0.6 if self._away else 0.06)   # spells of several hours
        target = 0.05 if self._away else 1.0
        step = 0.6 if self._away else 0.35                            # settle away over ~2-3 h, return slower
        self._away_level += (target - self._away_level) * step          # glide, don't cut
        day = diurnal_factor(hour + self.rng.uniform(0, 1)) / 0.95
        random_factor = math.exp(self._wobble) * day * self._day_mult * self._away_level
        return base * ((1 - r) + r * random_factor)        # partly steady, partly random
