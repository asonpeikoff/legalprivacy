"""Proof that it works: what this computer's traffic looks like, with and without the noise.

A light background sampler (every 5 s, only while the app is open) lists this
computer's open network connections and sorts each one by the program that owns it:

  noise  legalPrivacy itself and the browsers it started
  tor    the Tor that legalPrivacy runs
  you    every other program on this computer (your browser, apps, updates…)

Nothing is captured or inspected: only which remote addresses are connected, and
how many bytes the network interfaces moved in total. No reverse-DNS lookups are
made (they would leak). Site names appear only for addresses the noise itself
looked up. Per-minute COUNTS are kept for 7 days in the app folder; addresses of
your own traffic are kept in memory only and never written to disk.

`compare()` answers "does the noise look like you?" by comparing the rhythm of the
noise with the rhythm of your own traffic from the minutes when the noise was OFF:
hour of day, how long bursts of activity last, how long the quiet gaps are, and how
busy an active minute is. Each comparison is a similarity from 0 to 100%
(100% = indistinguishable distributions, 1 - Kolmogorov-Smirnov distance).
"""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from collections import deque
from pathlib import Path
from collections.abc import Callable

try:
    import psutil
except ImportError:            # pragma: no cover - psutil is a declared dependency
    psutil = None

KEEP_DAYS = 7


_ACTIVE: TrafficObserver | None = None


def note(ip: str, name: str) -> None:
    """Called by the noise engines: `name` was looked up / visited at address `ip`."""
    if _ACTIVE is not None:
        _ACTIVE.learn(ip, name)


def _bucket(ts: float) -> int:
    return int(ts // 60 * 60)


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_private)


def ks_similarity(a: list[float], b: list[float]) -> float | None:
    """1 - two-sample Kolmogorov-Smirnov distance (1.0 = same distribution)."""
    if len(a) < 5 or len(b) < 5:
        return None
    xs = sorted(set(a) | set(b))
    sa, sb = sorted(a), sorted(b)
    import bisect
    d = 0.0
    for x in xs:
        fa = bisect.bisect_right(sa, x) / len(sa)
        fb = bisect.bisect_right(sb, x) / len(sb)
        d = max(d, abs(fa - fb))
    return round(1 - d, 3)


def ks_p(a: list[float], b: list[float]) -> float | None:
    """Two-sample Kolmogorov-Smirnov p-value (asymptotic): the chance of a gap this large between two samples of the
    same distribution. It treats each minute as independent, which neighbouring minutes are not, so the true p-value is
    larger than shown; read it as a rough guide, not a verdict."""
    s = ks_similarity(a, b)
    if s is None:
        return None
    import math
    d = 1.0 - s
    en = math.sqrt(len(a) * len(b) / (len(a) + len(b)))
    lam = (en + 0.12 + 0.11 / en) * d
    if lam < 0.2:
        return 1.0
    p = 2.0 * sum((-1) ** (j - 1) * math.exp(-2.0 * j * j * lam * lam) for j in range(1, 101))
    return round(min(1.0, max(0.0, p)), 4)


def runs(active: list[bool]) -> tuple[list[int], list[int]]:
    """Lengths (minutes) of consecutive active runs and of the quiet gaps between them."""
    on, off, cur, state = [], [], 0, None
    for x in active:
        if state is None or x == state:
            cur += 1
        else:
            (on if state else off).append(cur)
            cur = 1
        state = x
    if state is not None and cur:
        (on if state else off).append(cur)
    return on, off


class TrafficObserver:
    def __init__(self, noise_on: Callable[[], bool], noise_requests: Callable[[float], int],
                 tor_pid: Callable[[], int | None] = lambda: None, path: Path | None = None,
                 interval: float = 5.0, conn_fn=None, clock=time.time):
        self.noise_on, self.noise_requests, self.tor_pid = noise_on, noise_requests, tor_pid
        self.path, self.interval, self.clock = path, interval, clock
        self.conn_fn = conn_fn or self._connections
        self.minutes: dict[int, dict] = {}
        self.live: dict[str, dict] = {}            # ip -> {kind, first, last, seen, label}
        self.names: dict[str, str] = {}             # ip -> site name the noise looked up
        self.recent_you: deque[tuple[float, str]] = deque(maxlen=5000)
        self.available = psutil is not None
        self.limited = False                         # True when the OS only shows our own connections
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._last_bytes = None
        self.baseline_fn: Callable[[], dict | None] | None = None   # set by the controller: where "you" comes from
        self._last_save = 0.0
        self._load()

    # ── lifecycle ──────────────────────────────────────────────────────────
    def start(self) -> None:
        global _ACTIVE
        _ACTIVE = self
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="observer")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._save()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def learn(self, ip: str, name: str) -> None:
        """The noise resolved/visited `name` at `ip` (used only to label noise nodes)."""
        if ip and name and len(self.names) < 20000:
            self.names[ip] = name

    # ── sampling ───────────────────────────────────────────────────────────
    def _own_pids(self) -> set[int]:
        pids = {os.getpid()}
        try:
            for c in psutil.Process(os.getpid()).children(recursive=True):
                pids.add(c.pid)
        except Exception:
            pass
        return pids

    def _connections(self) -> list[tuple]:
        """[(remote ip, pid, local port)] for open connections; falls back to our own processes."""
        out = []
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.raddr and (c.status in ("ESTABLISHED", "SYN_SENT") or c.type == 2):
                    out.append((c.raddr.ip, c.pid, c.laddr.port if c.laddr else 0))
            self.limited = False
        except (psutil.AccessDenied, PermissionError, OSError):
            self.limited = True                     # macOS without admin: only our own processes
            for pid in self._own_pids():
                try:
                    for c in psutil.Process(pid).net_connections(kind="inet"):
                        if c.raddr:
                            out.append((c.raddr.ip, pid, c.laddr.port if c.laddr else 0))
                except Exception:
                    pass
        return out

    def sample(self) -> None:
        if not self.available:
            return
        now = self.clock()
        own = self._own_pids()
        tor = self.tor_pid()
        seen: dict[str, str] = {}
        ports: dict[str, set] = {}
        total = public = 0
        for item in self.conn_fn():
            ip, pid = item[0], item[1]
            total += 1
            if not _is_public(ip):
                continue
            public += 1
            ports.setdefault(ip, set()).add(item[2] if len(item) > 2 else 0)
            kind = "tor" if (tor and pid == tor) else ("noise" if pid in own else "you")
            if seen.get(ip) != "noise":            # if both, the noise owns the label
                seen[ip] = kind
        self.last_sample = {"at": now, "connections": total, "internet": public}
        with self._lock:
            for ip, kind in seen.items():
                n = self.live.setdefault(ip, {"kind": kind, "first": now, "seen": 0, "ports": set()})
                n["kind"], n["last"] = kind, now
                n["seen"] += 1
                if len(n["ports"]) < 500:
                    n["ports"] |= ports.get(ip, set())     # each new local port = a new connection
                if kind == "you":
                    self.recent_you.append((now, ip))
            for ip in [k for k, v in self.live.items() if now - v.get("last", 0) > 180]:
                del self.live[ip]
            m = self.minutes.setdefault(_bucket(now), {"you": set(), "noise": set(), "tor": 0,
                                                        "on": False, "req": 0, "bytes": 0})
            for key in ("you", "noise"):              # a minute restored from disk holds counts, not sets
                if not isinstance(m[key], set):
                    m[key] = set()
            for ip, kind in seen.items():
                if kind == "you":
                    m["you"].add(ip)
                elif kind == "noise":
                    m["noise"].add(ip)
                else:
                    m["tor"] = 1
            m["on"] = m["on"] or bool(self.noise_on())
            try:
                from .netwatch import total_bytes
                b = total_bytes()
                if b is not None and self._last_bytes is not None and b >= self._last_bytes:
                    m["bytes"] += b - self._last_bytes
                self._last_bytes = b
            except Exception:
                pass
            # prune
            cutoff = now - KEEP_DAYS * 86400
            for k in [k for k in self.minutes if k < cutoff]:
                del self.minutes[k]
        if now - self._last_save > 600:
            self._save()

    # ── views for the UI ──────────────────────────────────────────────────
    def _row(self, t: int, m: dict) -> dict:
        req = self.noise_requests(t) if m.get("on") else 0
        return {"t": t, "on": bool(m.get("on")), "you": len(m["you"]) if isinstance(m["you"], set) else m["you"],
                "noise": len(m["noise"]) if isinstance(m["noise"], set) else m["noise"],
                "tor": m.get("tor", 0), "req": max(req, m.get("req", 0)), "bytes": m.get("bytes", 0)}

    def timeline(self, hours: float = 6.0) -> list[dict]:
        now = self.clock()
        start = _bucket(now - hours * 3600)
        with self._lock:
            return [self._row(t, self.minutes[t]) if t in self.minutes else
                    {"t": t, "on": False, "you": 0, "noise": 0, "tor": 0, "req": 0, "bytes": 0, "gap": True}
                    for t in range(start, _bucket(now) + 60, 60)]

    def nodes(self, window: float = 120.0) -> list[dict]:
        now = self.clock()
        out = []
        with self._lock:
            for ip, n in self.live.items():
                if now - n.get("last", 0) > window:
                    continue
                name = self.names.get(ip, "") if n["kind"] != "you" else ""
                who = {"you": "Your apps", "noise": "legalPrivacy", "tor": "Tor (legalPrivacy)"}[n["kind"]]
                conns = max(1, len(n.get("ports", ())))
                out.append({"id": ip, "label": name or (ip if n["kind"] != "you" else ""),
                            "kind": n["kind"], "weight": conns, "active": now - n["last"] < self.interval * 1.5,
                            "detail": f"{who} · {ip} · {conns} connection{'s' if conns > 1 else ''} · "
                                      f"connected {int(now - n['first'])} s"})
        return out

    def rows(self) -> list[dict]:
        with self._lock:
            return [self._row(t, m) for t, m in sorted(self.minutes.items())]

    def compare(self, baseline: dict | None = None) -> dict:
        """Does the noise's rhythm look like yours? `baseline` (from baseline.select) says where "yours" comes
        from: an imported recording or browser history. Without one, minutes with noise OFF are the baseline."""
        rows = self.rows()
        noisy = [r for r in rows if r["on"]]
        if baseline is None and self.baseline_fn:
            baseline = self.baseline_fn()
        if baseline and baseline.get("source") in ("har", "history"):
            base, need = baseline["rows"], baseline["min_active"]
        else:
            base, need = [{"t": r["t"], "n": r["you"], "hosts": r["you"]} for r in rows if not r["on"]], 60
        base_active = [r["n"] > 0 for r in base]
        noise_active = [(r["req"] > 0 or r["noise"] > 0) for r in noisy]
        out = {"baseline_minutes": len(base), "noise_minutes": len(noisy),
               "baseline_active": sum(base_active), "noise_active": sum(noise_active), "metrics": []}
        if baseline:
            out["baseline"] = {k: v for k, v in baseline.items() if k != "rows"}
        if sum(base_active) < need or sum(noise_active) < 30:
            out["verdict"] = "collecting"
            out["needed"] = {"baseline_active": max(0, need - sum(base_active)),
                             "noise_active": max(0, 30 - sum(noise_active))}
            return out

        def hours(rs, pred):
            return [time.localtime(r["t"]).tm_hour + time.localtime(r["t"]).tm_min / 60 for r in rs if pred(r)]

        b_on, b_off = runs(base_active)
        n_on, n_off = runs(noise_active)
        hb = hours(base, lambda r: r["n"] > 0)
        hn = hours(noisy, lambda r: r["req"] > 0 or r["noise"] > 0)
        # comparing time of day is only fair once both sides have been seen across much of the day
        fair = len({int(h) for h in hb}) >= 8 and len({int(h) for h in hn}) >= 8
        metrics = [
            ("Time of day", "When activity happens" + ("" if fair else " (needs a few days of both)"),
             ks_similarity(hb, hn) if fair else None),
            ("Burst length", "How many minutes in a row stay busy", ks_similarity(b_on, n_on)),
            ("Quiet gaps", "How long the pauses between bursts last", ks_similarity(b_off, n_off)),
            ("Busyness", "How many sites in a busy minute",
             ks_similarity([r["hosts"] for r in base if r["n"] > 0], [max(r["noise"], r["req"]) for r in noisy
                                                                      if r["noise"] or r["req"]])),
        ]
        pvals = {"Time of day": ks_p(hb, hn) if fair else None, "Burst length": ks_p(b_on, n_on),
                 "Quiet gaps": ks_p(b_off, n_off),
                 "Busyness": ks_p([r["hosts"] for r in base if r["n"] > 0],
                                  [max(r["noise"], r["req"]) for r in noisy if r["noise"] or r["req"]])}
        out["metrics"] = [{"name": n, "what": w, "similarity": s, "difference": None if s is None else round(1 - s, 3),
                           "p": pvals.get(n)} for n, w, s in metrics]
        out["correction"] = self.correction()
        vals = [s for _, _, s in metrics if s is not None]
        score = sum(vals) / len(vals) if vals else None
        out["score"] = round(score, 3) if score is not None else None
        out["verdict"] = ("similar" if score is not None and score >= 0.7 else
                          "somewhat" if score is not None and score >= 0.5 else "different")
        worst = min((m for m in out["metrics"] if m["similarity"] is not None), key=lambda m: m["similarity"],
                    default=None)
        out["weakest"] = worst["name"] if worst else None
        return out

    # ── automatic correction ───────────────────────────────────────────────
    def hour_gains(self, min_minutes: int = 20, kind: str | None = None) -> dict[int, float]:
        """How much more (or less) noise to plan in each hour of the day so the traffic an observer sees, yours plus the
        noise, is about as busy at every hour as your busy hours are. In an hour when you are rarely here the noise gets
        up to twice its normal share; in hours when you are busy it eases to about half. Needs `min_minutes` of recorded
        minutes in an hour; other hours stay at 1. `kind` "weekday" (Mon-Fri) or "weekend" (Sat-Sun) uses only those days,
        for people whose week has a rhythm (the record is kept for 7 days); None uses every day."""
        with self._lock:
            rows = [(t, (len(m["you"]) if isinstance(m["you"], set) else m["you"])) for t, m in self.minutes.items()]
        by_hour: dict[int, list[float]] = {}
        for t, n in rows:
            lt = time.localtime(t)
            if kind is not None and (lt.tm_wday >= 5) != (kind == "weekend"):
                continue
            by_hour.setdefault(lt.tm_hour, []).append(float(n))
        means = {h: sum(v) / len(v) for h, v in by_hour.items() if len(v) >= min_minutes}
        if len(means) < 4:
            return {}
        vals = sorted(means.values())
        target = vals[int(0.75 * (len(vals) - 1))]
        if target < 0.5:                                  # you barely use the connection: nothing to match
            return {}
        return {h: round(min(2.0, max(0.5, 1.0 + (target - m) / target)), 2) for h, m in means.items()}

    def _today_kind(self) -> str:
        return "weekend" if time.localtime(self.clock()).tm_wday >= 5 else "weekday"

    def _gains_now(self) -> tuple[str, dict[int, float]]:
        """(which record the gains come from, gains): today's kind of day (weekday or weekend) once there are enough hours of
        it recorded, otherwise every day together. Cached for ten minutes."""
        now = self.clock()
        kind = self._today_kind()
        cache = getattr(self, "_gain_cache", None)
        if cache is None or now - cache[0] > 600 or cache[1] != kind:
            g = self.hour_gains(kind=kind)
            label = kind
            if not g:
                g, label = self.hour_gains(), "all days"
            cache = self._gain_cache = (now, kind, label, g)
        return cache[2], cache[3]

    def hour_gain(self, hour: int) -> float:
        return self._gains_now()[1].get(int(hour), 1.0)

    def correction(self) -> dict:
        label, g = self._gains_now()
        moves = sorted(((h, v) for h, v in g.items() if abs(v - 1.0) >= 0.1), key=lambda x: -abs(x[1] - 1.0))
        return {"active": bool(moves), "basis": label, "hours": [{"hour": h, "gain": v} for h, v in sorted(moves)[:24]]}

    def onoff(self) -> dict:
        """Average per-minute picture for minutes with the noise off vs on (last 24 h)."""
        now = self.clock()
        with self._lock:
            rows = [self._row(t, m) for t, m in self.minutes.items() if t > now - 86400]

        def avg(rs, key):
            return round(sum(r[key] for r in rs) / len(rs), 2) if rs else None
        off = [r for r in rows if not r["on"]]
        on = [r for r in rows if r["on"]]
        return {"off": {"minutes": len(off), "you": avg(off, "you"), "noise": avg(off, "noise"),
                        "bytes": avg(off, "bytes")},
                "on": {"minutes": len(on), "you": avg(on, "you"), "noise": avg(on, "noise"),
                       "bytes": avg(on, "bytes"), "req": avg(on, "req")}}

    def state(self) -> dict:
        return {"available": self.available, "limited": self.limited, "nodes": self.nodes(),
                "last_sample": getattr(self, "last_sample", None),
                "timeline": self.timeline(6), "compare": self.compare(), "onoff": self.onoff()}

    # ── persistence (counts only) ──────────────────────────────────────────
    def _save(self) -> None:
        if not self.path:
            return
        with self._lock:
            data = {str(t): {"you": len(m["you"]) if isinstance(m["you"], set) else m["you"],
                             "noise": len(m["noise"]) if isinstance(m["noise"], set) else m["noise"],
                             "tor": m.get("tor", 0), "on": m.get("on", False), "bytes": m.get("bytes", 0),
                             "req": self.noise_requests(t) if m.get("on") else m.get("req", 0)}
                    for t, m in self.minutes.items()}
        try:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            tmp.replace(self.path)
            self._last_save = self.clock()
        except OSError:
            pass

    def _load(self) -> None:
        if not self.path:
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        cutoff = self.clock() - KEEP_DAYS * 86400
        for k, v in data.items():
            try:                                   # a damaged entry must not stop the app from starting
                t = int(k)
                if t >= cutoff and isinstance(v, dict):
                    self.minutes[t] = dict(v)
            except (TypeError, ValueError):
                continue
