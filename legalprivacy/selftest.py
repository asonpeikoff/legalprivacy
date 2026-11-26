"""Self-test: how easily could someone watching your connection tell the noise from you?

Idea from NoisyCompany's "study". Everything runs on this computer; nothing is sent or saved.

  real   your browser history for the last N days: (time, site) of each visit
  noise  the same N days of noise, simulated from your current settings (no network), or
         this session's actual noise activity when there is enough of it

Both are merged into one timeline, as an ISP or DNS provider would see it, and described
only by what such an observer can see: hour, weekday, gap since the previous request,
how popular the site is, whether it is a revisit, and the domain ending. A small Naive
Bayes classifier then tries to tell them apart (5-fold cross-validation). The score is
its ROC AUC: 50% = can't tell at all, 100% = trivially separable. Each feature is also
scored alone, to show the biggest giveaways and what setting reduces each.
"""
from __future__ import annotations

import math
import random
import time
from collections import Counter, defaultdict

FEATURES = ["hour", "weekday", "gap", "popularity", "revisit", "ending"]
# What a stronger observer also sees: how bunched the requests are (page-shaped bursts), whether a request stays on
# the same site as the one before, and combinations of the signals above (habits live in the combinations).
STRONG_FEATURES = FEATURES + ["burst", "stay", "hour_pop", "gap_burst", "rev_pop"]
ADVICE = {
    "hour": "Noise runs at hours you don't browse. Turn on Settings → Extras → Active hours, or "
            "“Mostly when I'm active”.",
    "weekday": "Your browsing differs between weekdays and weekends but the noise doesn't. "
               "“Mostly when I'm active” follows your real days.",
    "gap": "The rhythm differs (time between requests). Keep “How random” at 100% and try "
           "“Mostly when I'm active”.",
    "popularity": "The noise visits more (or less) popular sites than you do. Turn on My List with your "
                  "own sites, and Interests.",
    "revisit": "You keep returning to the same sites; the noise rarely does. Add your top sites to My List "
               "and lower “Mix in other sites”.",
    "ending": "Your sites' endings (.com, .org, your country's) differ from the noise's. Import your "
              "history into My List.",
}


# ── features ────────────────────────────────────────────────────────────────
def _gap_bucket(sec: float) -> int:
    return min(17, int(math.log2(max(1.0, sec))))


def _ending(site: str) -> str:
    tld = site.rsplit(".", 1)[-1]
    return tld if tld in ("com", "org", "net", "io", "edu", "gov") else ("cc" if len(tld) == 2 else "other")


def featurize(events: list[tuple[float, str, int]], ranks: dict[str, int]) -> list[tuple[dict, int]]:
    """events: (time, site, label) merged and sorted. Returns (features, label)."""
    out, last_t, last_site = [], None, None
    recent: dict[str, list[float]] = defaultdict(list)
    window: list[float] = []                      # request times in the last minute, whatever the site
    for t, site, label in events:
        lt = time.localtime(t)
        window = [x for x in window if t - x < 60.0]
        n60 = len(window)
        window.append(t)
        burst = "0" if n60 == 0 else "1" if n60 == 1 else "2-3" if n60 <= 3 else "4-7" if n60 <= 7 else "8+"
        gap = _gap_bucket(t - last_t) if last_t is not None else 17
        hits = [x for x in recent[site] if t - x < 86400]
        recent[site] = hits + [t]
        r = ranks.get(site.removeprefix("www."))
        pop = "top100" if r is not None and r < 100 else "top1k" if r is not None and r < 1000 else \
              "top10k" if r is not None and r < 10000 else "ranked" if r is not None else "unranked"
        rev = "0" if not hits else "1" if len(hits) == 1 else "2-5" if len(hits) <= 5 else "6+"
        out.append(({"hour": lt.tm_hour, "weekday": lt.tm_wday, "gap": gap, "popularity": pop,
                     "revisit": rev, "ending": _ending(site), "burst": burst,
                     "stay": "1" if site == last_site else "0",
                     "hour_pop": f"{lt.tm_hour // 3}|{pop}", "gap_burst": f"{gap}|{burst}", "rev_pop": f"{rev}|{pop}"},
                    label))
        last_t, last_site = t, site
    return out


# ── Naive Bayes + AUC ───────────────────────────────────────────────────────
def _train(rows, feats):
    counts = {c: defaultdict(Counter) for c in (0, 1)}
    n = Counter()
    for x, y in rows:
        n[y] += 1
        for f in feats:
            counts[y][f][x[f]] += 1
    vocab = {f: {x[f] for x, _ in rows} for f in feats}
    return counts, n, vocab


def _score(model, x, feats) -> float:
    counts, n, vocab = model
    s = math.log((n[1] + 1) / (n[0] + 1))
    for f in feats:
        v = len(vocab[f]) + 1
        p1 = (counts[1][f][x[f]] + 1) / (n[1] + v)
        p0 = (counts[0][f][x[f]] + 1) / (n[0] + v)
        s += math.log(p1 / p0)
    return s


def auc(scores: list[tuple[float, int]]) -> float:
    """Probability a random noise event scores above a random real one (ties count half)."""
    pos = [s for s, y in scores if y == 1]
    neg = [s for s, y in scores if y == 0]
    if not pos or not neg:
        return 0.5
    allv = sorted([(s, y) for s, y in scores])
    rank_sum, i = 0.0, 0
    while i < len(allv):
        j = i
        while j < len(allv) and allv[j][0] == allv[i][0]:
            j += 1
        avg = (i + j + 1) / 2                      # 1-based average rank of the tie group
        rank_sum += avg * sum(1 for k in range(i, j) if allv[k][1] == 1)
        i = j
    return (rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def cross_val_auc(rows, feats, folds: int = 5, seed: int = 1) -> float:
    rng = random.Random(seed)
    idx = list(range(len(rows)))
    rng.shuffle(idx)
    scores = []
    for k in range(folds):
        test = set(idx[k::folds])
        model = _train([rows[i] for i in idx if i not in test], feats)
        scores += [(_score(model, rows[i][0], feats), rows[i][1]) for i in test]
    return auc(scores)


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-max(-30.0, min(30.0, x))))


def roc_points(scores: list[tuple[float, int]], max_points: int = 60) -> list[list[float]]:
    pos = sum(1 for _, y in scores if y == 1) or 1
    neg = sum(1 for _, y in scores if y == 0) or 1
    pts, tp, fp = [[0.0, 0.0]], 0, 0
    for _s, y in sorted(scores, key=lambda t: -t[0]):
        tp, fp = tp + (y == 1), fp + (y == 0)
        pts.append([fp / neg, tp / pos])
    step = max(1, len(pts) // max_points)
    out = pts[::step]
    if out[-1] != pts[-1]:
        out.append(pts[-1])
    return [[round(a, 4), round(b, 4)] for a, b in out]


def rates_at_fpr(scores: list[tuple[float, int]], fprs=(0.01, 0.001)) -> dict[float, float]:
    """True-positive rate (share of noise caught) when the observer allows only this share of false alarms on you."""
    neg = sorted((s for s, y in scores if y == 0), reverse=True)
    pos = [s for s, y in scores if y == 1]
    out = {}
    for f in fprs:
        if not neg or not pos:
            out[f] = 0.0
            continue
        k = max(1, int(math.ceil(len(neg) * f)))            # the k-th highest "you" score sets the threshold
        thr = neg[k - 1]
        out[f] = sum(1 for s in pos if s > thr) / len(pos)
    return out


def precision_at_prevalence(tpr: float, fpr: float, prevalence: float) -> float:
    """Of everything flagged as noise, the share that really is, when only `prevalence` of all events are noise
    (the base-rate view: a small false-alarm rate still buries a rare thing under false alarms)."""
    flagged = tpr * prevalence + fpr * (1 - prevalence)
    return tpr * prevalence / flagged if flagged else 0.0


def strong_attack(rows: list[tuple[dict, int]], seed: int = 1, folds: int = 5, prevalence: float = 0.01) -> dict:
    """A tougher observer than the six-signal Naive Bayes: it also sees bursts, same-site runs and combinations of
    signals, is judged on future events only (trained on the first 70% of the timeline, tested on the last 30%),
    and on the number that matters in practice: how much noise it catches while falsely accusing you rarely."""
    rng = random.Random(seed)
    idx = list(range(len(rows)))
    rng.shuffle(idx)
    pooled = []
    for k in range(folds):
        test = set(idx[k::folds])
        model = _train([rows[i] for i in idx if i not in test], STRONG_FEATURES)
        pooled += [(_score(model, rows[i][0], STRONG_FEATURES), rows[i][1]) for i in test]
    overall = auc(pooled)
    flip = overall < 0.5
    sc = [(-s if flip else s, y) for s, y in pooled]
    rates = rates_at_fpr(sc)
    cut = int(len(rows) * 0.7)
    train, test_rows = rows[:cut], rows[cut:]
    fwd = None
    if {y for _, y in train} == {0, 1} and {y for _, y in test_rows} == {0, 1}:
        m = _train(train, STRONG_FEATURES)
        fs = [(_score(m, x, STRONG_FEATURES), y) for x, y in test_rows]
        fwd = max(auc(fs), 1 - auc(fs))
    neg = sum(1 for _, y in sc if y == 0)
    out = {"auc": round(max(overall, 1 - overall) * 100, 1),
           "forward_auc": round(fwd * 100, 1) if fwd is not None else None,
           "tpr_at_1pct_fpr": round(rates[0.01] * 100, 1), "tpr_at_01pct_fpr": round(rates[0.001] * 100, 1),
           "precision_at_prevalence": round(precision_at_prevalence(rates[0.01], 0.01, prevalence) * 100, 1),
           "prevalence": prevalence, "features": len(STRONG_FEATURES)}
    if neg < 1000:
        out["note"] = (f"Only {neg} of your visits were compared, so the catch rate at 0.1% false alarms rests on "
                       f"{max(1, int(math.ceil(neg * 0.001)))} of them: treat it as rough.")
    return out


def evaluate(real: list[tuple[float, str]], noise: list[tuple[float, str]], ranks: dict[str, int],
             cap: int = 3000, seed: int = 1, folds: int = 5) -> dict:
    rng = random.Random(seed)
    warnings = []
    if len(real) < 50 or len(noise) < 50:
        return {"error": f"Not enough to compare ({len(real)} of your visits, {len(noise)} noise events; "
                         "at least 50 of each are needed)."}
    n = min(len(real), len(noise), cap)
    if n < 200:
        warnings.append(f"Small sample ({n} of each): the score can move by several points between runs.")
    if max(len(real), len(noise)) > n:
        warnings.append(f"Balanced by sampling {n} of each (from {len(real)} visits and {len(noise)} noise events).")
    real_s, noise_s = rng.sample(real, n), rng.sample(noise, n)
    merged = sorted([(t, s, 0) for t, s in real_s] + [(t, s, 1) for t, s in noise_s])
    rows = featurize(merged, ranks)

    # cross-validated scores, fold by fold
    idx = list(range(len(rows)))
    rng.shuffle(idx)
    pooled, fold_aucs = [], []
    for k in range(folds):
        test = set(idx[k::folds])
        model = _train([rows[i] for i in idx if i not in test], FEATURES)
        sc = [(_score(model, rows[i][0], FEATURES), rows[i][1]) for i in test]
        fold_aucs.append(round(auc(sc) * 100, 1))
        pooled += sc
    overall = auc(pooled)
    flip = overall < 0.5                              # direction doesn't matter: separable is separable
    a = max(overall, 1 - overall)
    boot = []
    for _ in range(200):                              # 95% interval by bootstrap over events
        smp = [pooled[rng.randrange(len(pooled))] for _ in range(len(pooled))]
        v = auc(smp)
        boot.append(max(v, 1 - v))
    boot.sort()
    tp = sum(1 for s, y in pooled if y == 1 and s > 0)
    fp = sum(1 for s, y in pooled if y == 0 and s > 0)
    tn = sum(1 for s, y in pooled if y == 0 and s <= 0)
    fn = sum(1 for s, y in pooled if y == 1 and s <= 0)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    logloss = -sum(math.log(max(1e-12, _sigmoid(s) if y == 1 else 1 - _sigmoid(s))) for s, y in pooled) / len(pooled)

    per = sorted(((f, cross_val_auc(rows, [f])) for f in FEATURES), key=lambda x: -x[1])
    verdict = ("hard to tell apart" if a < 0.6 else "somewhat easy to tell apart" if a < 0.75
               else "easy to tell apart" if a < 0.9 else "very easy to tell apart")
    tells = [{"feature": f, "auc": round(max(v, 1 - v) * 100), "advice": ADVICE[f]}
             for f, v in per if max(v, 1 - v) >= 0.6][:3]

    full = _train(rows, FEATURES)                      # the model kept for predictions
    counts, ncls, _ = full
    giveaways = []
    for f in FEATURES:
        for val in set(counts[0][f]) | set(counts[1][f]):
            c1, c0 = counts[1][f][val], counts[0][f][val]
            if c1 + c0 < 10:
                continue
            ratio = ((c1 + 1) / (ncls[1] + 2)) / ((c0 + 1) / (ncls[0] + 2))
            giveaways.append({"feature": f, "value": str(val), "noise": c1, "you": c0,
                              "ratio": round(ratio, 2), "strength": abs(math.log(ratio)),
                              "leans": "noise" if ratio > 1 else "you"})
    giveaways.sort(key=lambda g: -g["strength"])
    for g in giveaways:
        g["strength"] = round(g["strength"], 2)
    hours = [[0] * 24, [0] * 24]
    for t, _, y in merged:
        hours[y][time.localtime(t).tm_hour] += 1
    roc = roc_points([(-s if flip else s, y) for s, y in pooled])
    return {"score": round(a * 100), "verdict": verdict, "compared": n, "tells": tells,
            "per_feature": {f: round(max(v, 1 - v) * 100) for f, v in per},
            "auc": round(a * 100, 1), "ci95": [round(boot[4] * 100, 1), round(boot[194] * 100, 1)],
            "folds": fold_aucs, "roc": roc,
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "accuracy": round((tp + tn) / len(pooled) * 100, 1), "precision": round(prec * 100, 1),
            "recall": round(rec * 100, 1), "f1": round(2 * prec * rec / (prec + rec) * 100, 1) if prec + rec else 0.0,
            "log_loss": round(logloss, 3), "giveaways": giveaways[:8], "hours": {"you": hours[0], "noise": hours[1]},
            "strong": strong_attack(rows, seed=seed, folds=folds),
            "warnings": warnings, "_model": full}


def predict(model, site: str, hour: int, weekday: int, ranks: dict[str, int]) -> float:
    """Probability that one request (a site at that hour and weekday) is noise, per the last model.
    Uses only what describes a single request: hour, weekday, the site's popularity and ending
    (rhythm and revisits need a sequence of requests, so they are left out)."""
    t = time.mktime((2026, 1, 5 + weekday, hour, 30, 0, 0, 0, -1))
    x = featurize([(t, site, 0)], ranks)[0][0]
    return round(_sigmoid(_score(model, x, ["hour", "weekday", "popularity", "ending"])) * 100, 1)


# ── a built-in typical person, for the demo ─────────────────────────────────
DEMO_HABITS = [("www.youtube.com", 10), ("www.reddit.com", 9), ("mail.google.com", 8), ("www.google.com", 8),
               ("en.wikipedia.org", 6), ("www.amazon.com", 6), ("news.ycombinator.com", 4), ("github.com", 4),
               ("www.nytimes.com", 3), ("www.weather.com", 3), ("www.imdb.com", 2), ("www.netflix.com", 2),
               ("stackoverflow.com", 2), ("www.ebay.com", 2), ("maps.google.com", 2), ("www.bbc.com", 2)]


def demo_person(since: float, until: float, tail_sites: list[str] | None = None, seed: int = 21) -> list[tuple[float, str]]:
    """What a typical person's browsing looks like to someone watching their connection: sessions on weekday evenings
    (and a lunch break) and across weekend days, a few favourite sites visited again and again, runs on one site,
    and a long tail of other sites. Made up, not recorded from anyone: it exists so the ML tab can be tried without
    your own history."""
    rng = random.Random(seed)
    sites = [h for h, _ in DEMO_HABITS]
    weights = [w for _, w in DEMO_HABITS]
    tail = list(tail_sites or [f"site{i}.example.com" for i in range(60)])
    events: list[tuple[float, str]] = []
    day = since - (since % 86400)
    while day < until:
        wd = time.localtime(day + 43200).tm_wday
        starts = ([12.2 + rng.uniform(0, 0.8)] if wd < 5 else [9.5 + rng.uniform(0, 2.0), 14.0 + rng.uniform(0, 2.0)]) \
            + [19.0 + rng.uniform(0, 3.0)] * (1 if rng.random() < 0.9 else 0)
        for hr in starts:
            t = day + hr * 3600
            site = rng.choices(sites, weights=weights)[0]
            for _ in range(max(3, int(rng.lognormvariate(2.6, 0.6)))):         # one sitting: a run of visits
                if rng.random() < 0.38 and events:                              # stay on the same site a while
                    pass
                else:
                    site = rng.choices(sites, weights=weights)[0] if rng.random() < 0.78 else rng.choice(tail)
                events.append((t, site))
                t += max(2.0, rng.lognormvariate(3.3, 0.9))                      # seconds between requests
        day += 86400
    return sorted(e for e in events if since <= e[0] < until)


# ── noise: simulate from settings ───────────────────────────────────────────
def simulate_noise(profile, pool, since: float, until: float, seed: int = 7) -> list[tuple[float, str]]:
    """What the noise would have done over [since, until] with these settings (no network)."""
    from .engines import SEARCH_ENDPOINTS, _current_weights
    from .pacing import SessionPacer
    from .rate import RatePlanner
    import urllib.parse as up
    rng = random.Random(seed)
    planner, pacer = RatePlanner(rng, profile.rate), SessionPacer(rng)
    eng = {n: c.budget_per_day for n, c in profile.engines.items() if c.enabled and n != "onion"}
    tot = sum(eng.values()) or 1
    names, weights = list(eng), [eng[n] / tot for n in eng]
    ex = getattr(profile, "extras", None)
    sw = [w if w > 0 else 0.0 for w in _current_weights()] or [1.0] * len(SEARCH_ENDPOINTS)
    events, t = [], since
    last_site = None
    while t < until:
        hour_start = t - (t % 3600)
        lt = time.localtime(t)
        active = True
        if ex is not None and ex.active_hours:
            a, b = ex.active_from, ex.active_to
            h = lt.tm_hour
            active = (a <= h < b) if a < b else (h >= a or h < b) if a > b else True
        total = planner.actions_for_hour(lt.tm_hour, max(weights[names.index("search")] if "search" in names else 0.3, 0.05)) \
            if active else 0
        left, end = int(total) + (1 if rng.random() < total - int(total) else 0), hour_start + 3600
        while left > 0 and t < end:
            kind = rng.choices(names, weights=weights)[0] if names else "dns"
            if kind == "search":
                site = up.urlparse(rng.choices(SEARCH_ENDPOINTS, weights=sw)[0]).hostname
            elif kind == "crawl" and last_site and rng.random() < 0.6:
                site = last_site
            elif kind == "dns":
                site = pool.hostname()
            else:
                site = pool.visit_host()
            site = (site or "").removeprefix("www.")
            if site:
                events.append((t, site))
                last_site = site
            left -= 1
            t += pacer.next_gap(left, max(60.0, end - t))
        t = max(t, end)
    return [e for e in events if since <= e[0] < until]
