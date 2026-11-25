"""Household masking (optional; idea from NoisyCompany).

The noise comes from a small virtual household instead of one person: 2-5 members, each
with their own device and browser and their own usual hours. Someone watching the
connection then can't easily tell how many people live there, or when the home is empty.

Member 1 is "you": your own user-agent setting (pin or rotation) applies. The others get a
device and browser drawn once from the library, and keep it. The household is redrawn
every 30-90 days, seeded from a private random value saved in your settings.
"""
from __future__ import annotations

import hashlib
import random
import time

# Typical daily rhythms (local hours, start inclusive, end exclusive; may wrap past midnight).
RHYTHMS = [
    ("early riser", [(6, 9), (17, 22)]),
    ("office hours", [(8, 12), (13, 18)]),
    ("evenings", [(18, 24)]),
    ("night owl", [(21, 24), (0, 2)]),
    ("student", [(10, 14), (16, 24)]),
    ("home all day", [(9, 23)]),
]


class Household:
    def __init__(self, size: int = 3, salt: str = "", clock=time.time, sample_entry=None,
                 mobile_share: float = 0.10, device: str = "iPhone 13"):
        self.size = max(2, min(5, int(size)))
        self.salt, self.clock = salt or "default", clock
        self.sample_entry, self.mobile_share, self.device = sample_entry, mobile_share, device
        self._period, self._members = None, []

    def _period_key(self) -> int:
        # periods of 30-90 days: fixed boundaries derived from the salt
        seed = int(hashlib.sha256(self.salt.encode()).hexdigest()[:8], 16)
        length = 30 + seed % 61
        return int(self.clock() // (length * 86400))

    def members(self) -> list[dict]:
        key = self._period_key()
        if key != self._period:
            rng = random.Random(hashlib.sha256(f"{self.salt}:{key}".encode()).hexdigest())
            self._members = []
            for i in range(self.size):
                name, hours = rng.choice(RHYTHMS)
                entry = None
                if i > 0 and self.sample_entry is not None:
                    entry = self.sample_entry(rng, self.mobile_share, self.device)
                self._members.append({"id": i, "rhythm": name, "hours": hours, "entry": entry,
                                      "weight": rng.uniform(0.6, 1.4)})
            self._period = key
        return self._members

    @staticmethod
    def _awake(hours, h: int) -> bool:
        return any(a <= h < b for a, b in hours)

    def pick(self, rng: random.Random, hour: int | None = None) -> dict:
        """The member making the next request: mostly someone whose usual hours these are."""
        h = time.localtime(self.clock()).tm_hour if hour is None else hour
        ms = self.members()
        w = [m["weight"] * (1.0 if self._awake(m["hours"], h) else 0.08) for m in ms]
        return rng.choices(ms, weights=w)[0]

    def describe(self) -> list[str]:
        out = []
        for m in self.members():
            who = "you" if m["id"] == 0 else (m["entry"] or {}).get("device") or (m["entry"] or {}).get("persona", "?")
            out.append(f"{who} ({m['rhythm']})")
        return out
