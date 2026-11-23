"""Numbers for the Proof tab's activity graphs, plus a plain-language verdict for each.

  intended  what the current settings are meant to produce: expected requests per hour of the day.
            It comes from running the same rate planner the noise uses (level, random/steady, how random)
            for many simulated days, then masking hours outside "active hours". The band is the 10th to
            90th percentile of the planner's own hour-to-hour variation, the line is the median.
            (The persona changes WHICH sites are visited, not how many or when, so it is only named.)
  session   what the noise actually did over the last hours, in 10-minute steps, against that band.
  baseline  how you browse by hour of day (share of your day's activity), next to the noise's, plus how long
            your bursts and quiet gaps last. `baseline` is the selection from baseline.py.
"""
from __future__ import annotations

import random
import time

from .observe import runs
from .rate import RateConfig, RatePlanner

BIN_EDGES = [1, 2, 3, 5, 10, 20]                 # minutes: 1, 2, 3-4, 5-9, 10-19, 20+
BIN_LABELS = ["1", "2", "3-4", "5-9", "10-19", "20+"]


def hh(h: int) -> str:
    h %= 24
    return f"{h % 12 or 12} {'AM' if h < 12 else 'PM'}"


def _in_active(h: int, a: int, b: int) -> bool:
    return (a <= h < b) if a < b else (h >= a or h < b) if a > b else True


def _local_hour_start(t: float) -> int:
    """Start (epoch seconds) of the local clock hour containing t. Not `t // 3600 * 3600`: in zones with a
    30- or 45-minute UTC offset (India, Nepal...) that would cut every local hour in two."""
    lt = time.localtime(t)
    return int(t) - lt.tm_min * 60 - lt.tm_sec


def intended(rate: RateConfig, search_share: float, active_hours: bool = False, a: int = 8, b: int = 22,
             persona: str = "", days: int = 120, seed: int = 11) -> dict:
    """Expected requests per hour of the day: {"p10","p50","p90","mean": [24 floats], "verdict", ...}."""
    rng = random.Random(seed)
    per_hour: list[list[float]] = [[] for _ in range(24)]
    for _ in range(max(1, days if rate.mode == "random" and rate.randomness > 0 else 1)):
        pl = RatePlanner(rng, rate)
        for h in range(24):
            per_hour[h].append(pl.actions_for_hour(h, search_share))

    def pct(vals, q):
        v = sorted(vals)
        return v[min(len(v) - 1, int(q * (len(v) - 1) + 0.5))]
    out = {k: [] for k in ("p10", "p50", "p90", "mean")}
    for h in range(24):
        on = (not active_hours) or _in_active(h, a, b)
        vals = per_hour[h]
        out["p10"].append(round(pct(vals, 0.1), 1) if on else 0.0)
        out["p50"].append(round(pct(vals, 0.5), 1) if on else 0.0)
        out["p90"].append(round(pct(vals, 0.9), 1) if on else 0.0)
        out["mean"].append(round(sum(vals) / len(vals), 1) if on else 0.0)
    total = sum(out["mean"])
    mx = max(out["p50"]) or 1.0
    busy = [h for h in range(24) if out["p50"][h] >= 0.7 * mx]
    quiet = [h for h in range(24) if out["p50"][h] <= 0.2 * mx]
    mode = ("steady: the same amount every hour" if rate.mode == "steady" or rate.randomness == 0
            else "random: hour-to-hour variation around a day/night curve")
    bits = [f"about {round(total)} requests a day"]
    if busy and len(busy) < 24:
        bits.append(f"busiest around {hh(min(busy))}–{hh(max(busy) + 1)}" if busy == list(range(min(busy), max(busy) + 1))
                    else f"busiest around {', '.join(hh(h) for h in busy[:3])}")
    if quiet and len(quiet) < 24:
        bits.append(f"nearly quiet {hh(min(quiet))}–{hh(max(quiet) + 1)}" if quiet == list(range(min(quiet), max(quiet) + 1))
                    else "nearly quiet at some hours")
    out.update({"level": rate.level, "mode": rate.mode, "randomness": rate.randomness,
                "active": [a, b] if active_hours else None, "persona": persona or "",
                "per_day": round(total),
                "verdict": f"Reads as: {'; '.join(bits)}. Level {rate.level:g}, {mode}"
                           + (f", active hours {hh(a)}–{hh(b)}" if active_hours else ", all day")
                           + (f"; persona “{persona}” changes which sites, not when" if persona else "") + "."})
    return out


# ── this session ────────────────────────────────────────────────────────────
def session(timeline: list[dict], plan: dict, running: bool, step: int = 10) -> dict:
    """timeline: observer.timeline() minute rows. Returns 10-minute buckets, the planned band for each,
    and the hours that were off plan."""
    buckets, i = [], 0
    while i < len(timeline):
        chunk = timeline[i:i + step]
        t = chunk[0]["t"]
        h = time.localtime(t).tm_hour
        buckets.append({"t": t, "req": sum(r["req"] for r in chunk), "you": max(r["you"] for r in chunk),
                        "on": any(r["on"] for r in chunk),
                        "lo": round(plan["p10"][h] * len(chunk) / 60, 2), "hi": round(plan["p90"][h] * len(chunk) / 60, 2)})
        i += step
    # judge whole local hours in which the noise was on for at least 30 minutes
    by_hour: dict[int, list] = {}
    for r in timeline:
        by_hour.setdefault(_local_hour_start(r["t"]), []).append(r)
    flags = []
    for t0, rs in sorted(by_hour.items()):
        on_min = sum(1 for r in rs if r["on"])
        h = time.localtime(t0).tm_hour
        if on_min < 30 or len(rs) < 55:             # partial hours are not judged
            continue
        got, lo, hi = sum(r["req"] for r in rs), plan["p10"][h], plan["p90"][h]
        if got > max(hi * 1.5, hi + 6):
            flags.append({"t0": t0, "t1": t0 + 3600, "dir": "busier", "got": got, "planned": [lo, hi]})
        elif lo >= 3 and got < lo * 0.4:
            flags.append({"t0": t0, "t1": t0 + 3600, "dir": "quieter", "got": got, "planned": [lo, hi]})
    judged = sum(1 for rs in by_hour.values() if sum(1 for r in rs if r["on"]) >= 30 and len(rs) >= 55)
    if not any(b["on"] for b in buckets):
        verdict = ("The noise is off, so there is nothing to compare with the plan yet." if not running else
                   "The noise just started: the first full hour will be compared with the plan.")
        state = "empty"
    elif not judged:
        verdict, state = "Too early to judge: the noise has not run a full hour yet.", "early"
    elif not flags:
        verdict, state = f"✓ On plan: the last {judged} full hour{'s' if judged > 1 else ''} stayed inside the planned range.", "ok"
    else:
        spans: list[list] = []                     # merge consecutive hours that went the same way
        for f in flags:
            if spans and spans[-1][0] == f["dir"] and spans[-1][2] == f["t0"]:
                spans[-1][2] = f["t1"]
            else:
                spans.append([f["dir"], f["t0"], f["t1"]])
        parts = [f"{d} than planned between {hh(time.localtime(a).tm_hour)} and {hh(time.localtime(b).tm_hour)}"
                 for d, a, b in spans]
        verdict, state = "✗ Off plan: noise was " + "; ".join(parts) + ".", "off"
    return {"buckets": buckets, "flags": flags, "verdict": verdict, "state": state, "running": running}


# ── baseline vs noise ───────────────────────────────────────────────────────
def hour_shares(rows: list[dict], key: str) -> tuple[list[float], int]:
    """Share of all activity that falls in each local hour (sums to 1), and how many different hours were seen."""
    cnt = [0.0] * 24
    for r in rows:
        if r[key] > 0:
            cnt[time.localtime(r["t"]).tm_hour] += r[key]
    tot = sum(cnt)
    return ([round(c / tot, 4) for c in cnt] if tot else cnt), sum(1 for c in cnt if c > 0)


def histogram(lengths: list[int]) -> list[float]:
    cnt = [0] * len(BIN_LABELS)
    for n in lengths:
        k = sum(1 for e in BIN_EDGES[1:] if n >= e)
        cnt[k] += 1
    tot = sum(cnt)
    return [round(c / tot, 3) if tot else 0.0 for c in cnt]


def _median(v: list[int]) -> float:
    s = sorted(v)
    return float(s[len(s) // 2]) if s else 0.0


def baseline_vs_noise(sel: dict, noise_rows: list[dict]) -> dict:
    """sel: baseline.select() result (with rows). noise_rows: observer rows."""
    pub = {k: v for k, v in sel.items() if k != "rows"}
    nrows = [{"t": r["t"], "n": max(r["req"], r["noise"])} for r in noise_rows if r["on"]]
    noise_shares, noise_hours = hour_shares(nrows, "n")
    out = {"baseline": pub, "noise_minutes": sum(1 for r in nrows if r["n"] > 0), "noise": noise_shares,
           "labels": BIN_LABELS}
    if not sel.get("enough"):
        out.update({"you": [0.0] * 24, "similarity": None, "state": "none", "verdict": pub["status"],
                    "bursts": None, "gaps": None})
        return out
    rows = sel["rows"]
    you, you_hours = hour_shares(rows, "n")
    out["you"] = you
    out["noise_hours"], out["you_hours"] = noise_hours, you_hours
    # burst and quiet-gap lengths
    b_on, b_off = runs([r["n"] > 0 for r in rows])
    n_on, n_off = runs([r["n"] > 0 for r in nrows]) if nrows else ([], [])
    out["bursts"] = {"you": histogram(b_on), "noise": histogram(n_on), "median_you": _median(b_on), "median_noise": _median(n_on)}
    out["gaps"] = {"you": histogram(b_off), "noise": histogram(n_off), "median_you": _median(b_off), "median_noise": _median(n_off)}
    if out["noise_minutes"] < 30:
        out.update({"similarity": None, "state": "early",
                    "verdict": "Run the noise for a while (about 30 busy minutes) to compare its day with yours."})
        return out
    if you_hours < 8:
        out.update({"similarity": None, "state": "short",
                    "verdict": f"Your baseline covers only {you_hours} hour{'s' if you_hours != 1 else ''} of the day, "
                               "so the two days can't be fairly compared yet. A recording that spans more of the day "
                               "(or several days) fixes that."})
        return out
    sim = 1 - 0.5 * sum(abs(a - b) for a, b in zip(you, noise_shares))
    out["similarity"] = round(sim, 3)
    worst = max(range(24), key=lambda h: abs(noise_shares[h] - you[h]))
    gap = noise_shares[worst] - you[worst]
    if sim >= 0.75:
        v, st = f"✓ Close: the noise's day follows yours ({round(sim * 100)}% overlap).", "ok"
    else:
        st = "off"
        if abs(gap) < 0.02:
            v = f"✗ Different shape ({round(sim * 100)}% overlap), spread over many hours."
        elif gap > 0:
            who = "you are not" if you[worst] < 0.01 else f"you are much less active ({round(you[worst] * 100)}% of your day)"
            v = f"✗ Noise active at {hh(worst)}, {who}. ({round(sim * 100)}% overlap)"
        else:
            v = f"✗ You are active at {hh(worst)} but the noise is quiet. ({round(sim * 100)}% overlap)"
    out.update({"state": st, "verdict": v})
    return out
