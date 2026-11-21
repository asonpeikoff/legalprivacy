"""Where "how you browse" comes from.

Browser history may be old, erased (legalPrivacy has tools that erase it) or never kept, so the
comparisons never assume it. Your baseline is the FIRST of these that has enough data:

  1. a browser recording (HAR file) you imported,
  2. what the traffic observer saw of your own apps in minutes when the noise was OFF,
  3. your browser history (if present).

If none has enough, there is no baseline and nothing is scored: `select()` says so and how to fix it.
Each source is turned into the same shape: one row per minute, {"t", "n", "hosts"} where n is the amount
of activity that minute (requests, connections or visits) and hosts the number of different sites.
"""
from __future__ import annotations

import random

HAR_MIN_ACTIVE = 20          # busy minutes needed from an imported recording
OBS_MIN_ACTIVE = 60
HIST_MIN_ACTIVE = 60
HIST_MIN_VISITS = 50
HOWTO = ("Browse as usual with the noise off for a while (about an hour of activity), or import a browser "
         "recording: open your browser's developer tools, go to the Network tab, keep it recording while you "
         "browse as usual, then use “Save all as HAR” and choose that file in the Proof tab.")


def human_span(seconds: float) -> str:
    if seconds < 90 * 60:
        return f"{max(1, round(seconds / 60))} min"
    if seconds < 48 * 3600:
        h = seconds / 3600
        return f"{h:.0f} h" if h >= 10 else f"{h:.1f} h".replace(".0 h", " h")
    return f"{round(seconds / 86400)} days"


def har_rows(har: dict) -> list[dict]:
    """Every minute from the first to the last request, quiet minutes included."""
    mins = har["minutes"]
    lo, hi = min(mins), max(mins)
    return [{"t": t, "n": mins[t][0] if t in mins else 0, "hosts": mins[t][1] if t in mins else 0}
            for t in range(lo, hi + 60, 60)]


def history_rows(events: list[tuple[float, str]]) -> list[dict]:
    per: dict[int, list] = {}
    for t, s in events:
        slot = per.setdefault(int(t // 60 * 60), [0, set()])
        slot[0] += 1
        slot[1].add(s)
    if not per:
        return []
    lo, hi = min(per), max(per)
    return [{"t": t, "n": per[t][0] if t in per else 0, "hosts": len(per[t][1]) if t in per else 0}
            for t in range(lo, hi + 60, 60)]


def observer_rows(rows: list[dict]) -> list[dict]:
    """Minutes when the noise was off; "you" counts the different addresses your apps used."""
    return [{"t": r["t"], "n": r["you"], "hosts": r["you"]} for r in rows if not r["on"]]


def _active(rows: list[dict]) -> int:
    return sum(1 for r in rows if r["n"] > 0)


def select(har: dict | None, observer: list[dict], history: list[tuple[float, str]] | None,
           history_pending: bool = False) -> dict:
    """Pick the baseline. Returns {source, label, status, enough, rows, min_active, sources[], howto}.
    `observer` is TrafficObserver.rows(); `history` is [(time, site)] or None if not read (yet)."""
    srcs = []
    cands = []
    # 1. HAR
    if har:
        rows = har_rows(har)
        act = _active(rows)
        span = (har["last"] - har["first"]) if har.get("last") else 0
        ok = act >= HAR_MIN_ACTIVE
        label = f"{human_span(span)} from your HAR file"
        detail = f"{human_span(span)}, {len(har.get('top_hosts') or [])} top sites, {har['entries']:,} requests"
        srcs.append({"id": "har", "name": "HAR file you imported", "detail": detail,
                     "state": "available" if ok else "short",
                     "note": "" if ok else f"only {act} busy minutes; needs about {HAR_MIN_ACTIVE}"})
        if ok:
            cands.append(("har", rows, label, HAR_MIN_ACTIVE))
    else:
        srcs.append({"id": "har", "name": "HAR file you imported", "detail": "none imported", "state": "none",
                     "note": "import one from the box above"})
    # 2. observer, noise off
    orows = observer_rows(observer)
    oact = _active(orows)
    ook = oact >= OBS_MIN_ACTIVE
    srcs.append({"id": "observer", "name": "Minutes seen with noise off",
                 "detail": f"{oact} busy minutes so far" if orows else "nothing seen yet",
                 "state": "available" if ook else "short",
                 "note": "" if ook else f"needs about {OBS_MIN_ACTIVE}"})
    if ook:
        cands.append(("observer", orows, f"{human_span(oact * 60)} of your own traffic seen with noise off",
                      OBS_MIN_ACTIVE))
    # 3. history
    if history is None:
        srcs.append({"id": "history", "name": "Browser history",
                     "detail": "reading…" if history_pending else "not read", "state": "pending", "note": ""})
    else:
        hrows = history_rows(history)
        hact = _active(hrows)
        hok = hact >= HIST_MIN_ACTIVE and len(history) >= HIST_MIN_VISITS
        if history:
            days = (history[-1][0] - history[0][0]) / 86400 if len(history) > 1 else 0
            detail = f"{human_span(max(days, 0.01) * 86400)} of history, {len(history):,} visits"
        else:
            detail = "empty, erased or not found"
        srcs.append({"id": "history", "name": "Browser history", "detail": detail,
                     "state": "available" if hok else ("short" if history else "none"),
                     "note": "" if hok else ("too little to use" if history else "")})
        if hok:
            cands.append(("history", hrows, f"{human_span(history[-1][0] - history[0][0])} of browser history",
                          HIST_MIN_ACTIVE))
    out = {"sources": srcs, "howto": HOWTO}
    if cands:
        src, rows, label, need = cands[0]
        for s in srcs:
            if s["id"] == src:
                s["state"] = "in use"
            elif s["state"] == "available":
                s["state"] = "not needed"
        out.update({"source": src, "label": label, "status": f"Your baseline: {label}.", "enough": True,
                    "rows": rows, "min_active": need})
    else:
        have = [s for s in srcs if s["state"] == "short"]
        out.update({"source": "none", "label": "not enough yet", "enough": False, "rows": [], "min_active": OBS_MIN_ACTIVE,
                    "status": "Not enough data yet to say how you browse, so nothing is scored. " + HOWTO
                              + (" (Some data exists but it is too little to use.)" if have else "")})
    return out


def public(sel: dict) -> dict:
    """The selection without its per-minute rows, for sending to the page."""
    return {k: v for k, v in sel.items() if k != "rows"}


def har_events(har: dict, seed: int = 3, cap: int = 6000) -> list[tuple[float, str]]:
    """Stand-in (time, site) visits for the self-test, rebuilt from the recording's derived counts only.
    One event per different site per minute (what a network observer sees as separate lookups), with sites
    drawn from the saved top-sites list in proportion to their counts. Revisit patterns are therefore
    approximate; the hour and rhythm come from the recording itself."""
    hosts = har.get("top_hosts") or []
    if not hosts:
        return []
    rng = random.Random(seed)
    names, weights = [h for h, _ in hosts], [n for _, n in hosts]
    ev = []
    for mn, (_, k) in sorted(har["minutes"].items()):
        k = max(1, int(k))
        picked: set[str] = set()
        for _ in range(k * 4):                       # about k different sites, favouring the common ones
            picked.add(rng.choices(names, weights=weights)[0])
            if len(picked) >= min(k, len(names)):
                break
        for site in picked:
            ev.append((mn + rng.uniform(0, 60), site))
    ev.sort()
    if len(ev) > cap:
        ev = sorted(rng.sample(ev, cap))
    return ev
