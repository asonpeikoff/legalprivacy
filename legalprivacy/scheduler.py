"""Scheduler: identity lifetimes, budgets, engine dispatch across transports."""

from __future__ import annotations

import math
import random
import sys
import threading
import time
import urllib.parse
from collections import deque
from dataclasses import dataclass
from collections.abc import Callable

from .config import Profile
from .identity import Identity, make_identity
from .useragents import UaChooser
from .events import EventLog
from .pacing import Budget, Pacer, SessionPacer
from .transports import ClearnetTransport, HitResult, Target, TorTransport, Transport


def _onion_offline(result) -> bool:
    """Tor reports an unreachable .onion (offline, moved, or descriptor not found) with these."""
    e = (result.error or "").lower()
    return any(k in e for k in ("host unreachable", "ttl expired", "general socks server failure",
                                "0x04", "0x06", "0x01", "connection refused", "timed out", "timeout",
                                "sslerror", "ssl:", "certificate", "wrong version number"))   # a broken certificate: unusable too


class MaxFailuresExceeded(RuntimeError):
    """Raised when total failures exceed daily_max_failures."""


@dataclass
class Lane:
    """One transport + its budget state and currently pinned identity."""
    name: str
    transport: Transport
    engines: list[str]
    budgets: dict[str, Budget]
    identity: Identity | None = None
    pacer: Pacer | None = None
    hits_by_identity: int = 0
    consecutive_failures: int = 0
    crawl_factory: object | None = None
    crawl_next: Target | None = None
    crawl_depth: int = 0
    follow_next: Target | None = None         # click-through chain: search -> result -> page
    search_factory: object | None = None
    onion_factory: object | None = None
    onion_next: Target | None = None
    onion_depth: int = 0
    gate: Callable[[], bool] | None = None    # e.g. "is Tor bootstrapped?"; closed = lane idles
    hits_total: int = 0
    failures_total: int = 0
    last_error: str | None = None
    last_hit_ts: float | None = None
    last_latency_ms: float | None = None
    pending_visit: Target | None = None       # a site we are searching for; the search's click goes to it
    linger: dict | None = None                # a long session on one page: {mode, url, engine, until, next_at}

    @property
    def open(self) -> bool:
        return self.gate is None or bool(self.gate())


def build_lanes(profile: Profile, wordlist: list[str],
                rng: random.Random | None = None,
                tor_gate: Callable[[], bool] | None = None,
                tor_endpoint: Callable[[], tuple[str, str | None]] | None = None,
                clearnet_transport: Transport | None = None,
                plain_transport: Transport | None = None) -> list[Lane]:
    """Build the active lanes.

    The tor lane exists only when Tor is enabled and carries the onion engine only; ordinary web noise,
    DNS and package installs never go through Tor.
    `tor_endpoint` lets a managed Tor supply its (dynamic) socks/control address.
    """
    rng = rng or random.Random()
    lanes = []
    tr = profile.transports
    share = profile.clearnet_lane_count()

    def _budget(name: str, divisor: int) -> Budget:
        return Budget(per_day=max(1, profile.engines[name].budget_per_day // divisor))

    if tr.get("clearnet") and tr["clearnet"].enabled:
        names = profile.active_engines("clearnet")
        lanes.append(Lane(
            name="clearnet",
            transport=clearnet_transport or ClearnetTransport(proxy=tr["clearnet"].proxy),
            engines=names,
            budgets={n: _budget(n, share) for n in names},
        ))
        page_engines = [n for n in names if n not in ("dns", "packages")]   # not browser work
        if plain_transport is not None and page_engines:
            lanes.append(Lane(name="clearnet-plain", transport=plain_transport, engines=page_engines,
                              budgets={n: _budget(n, share) for n in page_engines}))

    if tr.get("tor") and tr["tor"].enabled:
        t = tr["tor"]
        socks, control = (tor_endpoint() if tor_endpoint else (t.socks, t.control))
        names = profile.active_engines("tor")
        lanes.append(Lane(
            name="tor",
            transport=TorTransport(socks=socks, control=control,
                                   identities_per_circuit=t.identities_per_circuit,
                                   control_password=t.control_password),
            engines=names,
            budgets={n: _budget(n, 1 if n == "onion" else share) for n in names},
            gate=tor_gate,
        ))
    return [lane for lane in lanes if lane.engines]


@dataclass
class Runner:
    profile: Profile
    lanes: list[Lane]
    wordlist: list[str]
    clock: object = time.time          # injectable for tests
    local_hour_fn: object = None       # injectable: () -> float hour
    sleep_fn: object = time.sleep
    probe_fn: object = None            # injectable: (lane, identity, target) -> HitResult
    max_iterations: int = 10_000       # safety net for --once-style testing
    verbose: bool = False
    log: EventLog | None = None        # shared event log (UI visibility)
    stop_event: threading.Event | None = None
    tor_seeds: list[str] | None = None  # extra onion seeds from the profile
    queries: object | None = None      # QuerySource shared by all lanes (live/real queries)
    domains: object | None = None      # DomainPool (real popular domains)
    click_prob: float = 0.85           # chance a search is followed by opening a result
    rate: object | None = None         # RatePlanner: hourly plan (app mode). None = daily budgets (CLI/tests)
    dns_plan: object | None = None     # DnsPlan: which resolver DNS noise uses
    mix: bool = False                  # app mode: lane shares + pattern from profile.traffic
    side_streams: tuple = ()           # engines that run on their own thread, alongside the main stream

    def __post_init__(self) -> None:
        self.rng = random.Random()
        self._ident_counter = 0
        if self.clock is None:
            self.clock = time.time
        self.hit_log: deque[dict] = deque(maxlen=500)
        self.started_at = time.time()
        self.day = time.localtime().tm_yday
        self.paused = False
        self._hit_seq = 0
        self.day_failures = 0           # daily failure caps (independent of hourly budget resets)
        self.day_onion_failures = 0
        self.hour: int | None = None
        self.hour_target = 0.0
        self._pace: tuple[float, float] | None = None   # (min_delay, max_delay) for this hour
        self._rec_lock = threading.Lock()                # the main stream and side streams both record hits
        self._side_threads: list[threading.Thread] = []
        self._sessions = SessionPacer(self.rng)          # app mode: irregular "sittings"
        tc = getattr(self.profile, "traffic", None)
        self._mobile_now = tc.mobile_share if tc else 0.35
        self._lane_factor: dict[str, float] = {}
        self._lane_wobble: dict[str, float] = {}
        self._mobile_wobble = 0.0
        self._alt_lane, self._alt_left = None, 0
        self.bytes_today = 0
        self._host_last: dict[str, float] = {}
        ex = getattr(self.profile, "extras", None)
        if ex is not None:
            from .engines import configure_search
            configure_search(ex.search_engines, ex.typos)
        self._ua = UaChooser(self.rng, self.profile.identity,
                             mobile=lambda: (self._mobile_now, tc.device if tc else "iPhone 13"))
        self._hour_end = 0.0

    def _emit(self, level: str, source: str, msg: str, **data) -> None:
        if self.log:
            self.log.add(level, source, msg, data or None)

    def _stopped(self) -> bool:
        return bool(self.stop_event and self.stop_event.is_set())

    def stats(self) -> dict:
        """Snapshot for the UI: per-lane and per-engine budgets and health."""
        lanes = []
        for lane in self.lanes:
            lanes.append({
                "name": lane.name, "open": lane.open,
                "dimmed": bool(getattr(lane.transport, "dimmed", False)),
                "hits": lane.hits_total, "failures": lane.failures_total,
                "last_error": lane.last_error, "last_hit_ts": lane.last_hit_ts,
                "latency_ms": lane.last_latency_ms,
                "linger": (lane.linger or {}).get("mode"),
                "identity": (lane.identity.persona if lane.identity and hasattr(lane.identity, "persona") else None),
                "engines": {e: {"spent": b.spent, "per_day": b.per_day, "failures": b.failures}
                            for e, b in lane.budgets.items()},
            })
        ex = getattr(self.profile, "extras", None)
        return {"lanes": lanes, "paused": self.paused, "uptime": int(time.time() - self.started_at),
                "current": dict(self.current) if getattr(self, "current", None) else None,
                "bytes_today": self.bytes_today, "data_cap_mb": ex.daily_data_mb if ex else 0}

    # ── hourly plan (app mode) ──────────────────────────────────────────────
    def _lane_base(self) -> dict[str, float]:
        """Relative weight of each lane from Settings → Traffic mix."""
        tc = self.profile.traffic
        names = {l.name for l in self.lanes}
        has_plain = "clearnet-plain" in names
        main_is_browser = type(next((l.transport for l in self.lanes if l.name == "clearnet"), None)).__name__ \
            == "BrowserTransport"
        base = {"clearnet": tc.browser + (0 if has_plain or main_is_browser else tc.plain),
                "clearnet-plain": tc.plain, "tor": tc.onion}
        return {n: max(0.0, base.get(n, 1.0)) for n in names}

    def _update_mix(self) -> None:
        """Once an hour: move the lane shares and the phone share according to the pattern."""
        tc = self.profile.traffic
        base = self._lane_base()
        if tc.pattern == "drift":                         # wander slowly; each hour keeps most of the last
            for n in base:
                self._lane_wobble[n] = 0.7 * self._lane_wobble.get(n, 0.0) + self.rng.gauss(0, 0.35)
                self._lane_factor[n] = math.exp(self._lane_wobble[n])
            self._mobile_wobble = 0.7 * self._mobile_wobble + self.rng.gauss(0, 0.3)
            self._mobile_now = min(0.95, max(0.0, tc.mobile_share * math.exp(self._mobile_wobble)))
        elif tc.pattern == "alternate":                   # one kind at a time, for 1-3 hours
            if self._alt_left <= 0 or self._alt_lane not in base:
                live = [n for n, w in base.items() if w > 0] or list(base)
                self._alt_lane = self.rng.choices(live, weights=[base[n] or 1 for n in live])[0]
                self._alt_left = self.rng.randint(1, 3)
                self._mobile_now = 0.9 if self.rng.random() < tc.mobile_share else 0.05
            self._alt_left -= 1
            # the active kind gets ~95% of this hour whatever its weight; the rest share ~5%
            others = sum(w for n, w in base.items() if n != self._alt_lane) or 1.0
            self._lane_factor = {n: (1.0 / (base[n] or 1.0) if n == self._alt_lane else 0.05 / others)
                                 for n in base}
        else:                                             # blend: the same mix every hour
            self._lane_factor = {n: 1.0 for n in base}
            self._mobile_now = tc.mobile_share

    def engine_shares(self) -> dict[tuple[str, str], float]:
        """(lane, engine) -> share of all actions.

        App mode (mix): lane shares from Settings → Traffic mix (moved by the pattern), then
        the engines' relative weights inside each lane. Otherwise: engine weights only."""
        if self.mix and getattr(self.profile, "traffic", None) is not None:
            base = self._lane_base()
            lane_w = {n: base[n] * self._lane_factor.get(n, 1.0) for n in base}
            tot_l = sum(lane_w.values()) or 1.0
            out = {}
            for lane in self.lanes:
                ew = {e: max(0.0, float(self.profile.engines[e].budget_per_day)) for e in lane.engines}
                tot_e = sum(ew.values()) or 1.0
                for e, v in ew.items():
                    out[(lane.name, e)] = lane_w[lane.name] / tot_l * v / tot_e
            return out
        w = {}
        for lane in self.lanes:
            for e in lane.engines:
                w[(lane.name, e)] = max(0.0, float(self.profile.engines[e].budget_per_day))
        tot = sum(w.values()) or 1.0
        return {k: v / tot for k, v in w.items()}

    def _apply_pace(self, pacer: Pacer | None) -> None:
        if pacer is None or self._pace is None:
            return
        pacer.min_delay, pacer.max_delay = self._pace
        pacer.min_gap = min(pacer.min_gap, self._pace[0])
        pacer.diurnal = False              # the hourly plan already follows the day/night curve

    def plan_hour(self, hour: int) -> float:
        """Set this hour's per-engine allowances and pacing from the RatePlanner."""
        if self.mix:
            self._update_mix()
        if not self._active_hour(hour):                  # outside your active hours: nothing this hour
            self.hour, self.hour_target = hour, 0.0
            for lane in self.lanes:
                for b in lane.budgets.values():
                    b.per_day, b.spent = 0, 0
            self._emit("info", "scheduler", f"Hour {hour:02d}:00 is outside your active hours: resting.")
            return 0.0
        shares = self.engine_shares()
        if self.side_streams:
            # side streams (DNS lookups, package installs) run alongside, not instead: the main kinds share
            # 100% between themselves, and each side stream adds its own proportional amount on top.
            main = sum(v for (ln, e), v in shares.items() if e not in self.side_streams) or 1.0
            shares = {k: v / main for k, v in shares.items()}
        search_share = sum(v for (ln, e), v in shares.items() if e == "search") or 0.3
        total = self.rate.actions_for_hour(hour, search_share)
        self.hour, self.hour_target = hour, total
        now = time.localtime()
        self._hour_end = self.clock() + (3600 - now.tm_min * 60 - now.tm_sec)
        for lane in self.lanes:
            for e, b in lane.budgets.items():
                x = total * shares.get((lane.name, e), 0)
                b.per_day = int(x) + (1 if self.rng.random() < x - int(x) else 0)   # unbiased rounding
                b.spent = 0
        gap = 3600.0 / max(total, 0.25)
        self._pace = (max(1.0, gap * 0.35), max(2.0, gap * 1.35))
        for lane in self.lanes:
            self._apply_pace(lane.pacer)
        self._emit("info", "scheduler", f"Hour {hour:02d}:00 plan: about {total:.0f} actions "
                   f"({self.profile.rate.mode}, level {self.profile.rate.level:g}).")
        return total

    def _activity_says_wait(self) -> bool:
        """Settings → Extras → Your own activity. True = skip a turn (after sleeping)."""
        ex = getattr(self.profile, "extras", None)
        if ex is None or ex.activity == "off":
            return False
        if not hasattr(self, "_netwatch"):
            from .netwatch import NetWatch
            self._netwatch, self._nw_next, self._nw_bytes, self._nw_said = NetWatch(), 0.0, 0, ""
        now = time.monotonic()
        if now >= self._nw_next:
            self._netwatch.sample(self.bytes_today - self._nw_bytes)
            self._nw_bytes, self._nw_next = self.bytes_today, now + 15
        nw = self._netwatch
        if ex.activity == "backoff" and nw.rate_kbps > ex.busy_kbps:
            if self._nw_said != "busy":
                self._emit("info", "scheduler", f"You're using the connection ({nw.rate_kbps:.0f} kbit/s): "
                                                "pausing noise until it quietens.")
                self._nw_said = "busy"
            self.sleep_fn(30.0)
            return True
        if ex.activity == "follow" and nw.idle_for() > 600 and self.rng.random() < 0.8:
            if self._nw_said != "idle":
                self._emit("info", "scheduler", "You've been idle for 10 minutes: noise slows down until you're back.")
                self._nw_said = "idle"
            self.sleep_fn(30.0)
            return True
        self._nw_said = ""
        return False

    def _entry_for_next_identity(self) -> dict:
        """Whose browser makes the next requests: you, or (household masking) another member."""
        ex = getattr(self.profile, "extras", None)
        if ex is None or not ex.household:
            return self._ua.choose()
        if not hasattr(self, "_household"):
            from .household import Household
            from .useragents import sample_entry
            tc = self.profile.traffic
            self._household = Household(ex.household_size, ex.interest_salt, sample_entry=sample_entry,
                                        mobile_share=tc.mobile_share, device=tc.device)
        member = self._household.pick(self.rng)
        return member["entry"] if member["entry"] is not None else self._ua.choose()

    def _tor_patience(self, lane: Lane, eng_name: str, target: Target, result: HitResult) -> None:
        """Act like a patient person on Tor: reload a failed page once a minute or so later, get a new
        identity after a run of failures, and let circuits change every so often on their own."""
        now = self.clock()
        st = self.__dict__.setdefault("_tor_state", {"streak": 0, "retried": set(),
                                                     "next_newnym": now + self.rng.uniform(600, 2400)})
        st.setdefault("limit", self.rng.randint(2, 5))
        if result.ok:
            st["streak"] = 0
        else:
            st["streak"] += 1
            # People don't react the same way every time: sometimes reload a bit later, sometimes just
            # go elsewhere, sometimes ask for a new identity first and then reload.
            r = self.rng.random()
            if eng_name == "onion" and target.url not in st["retried"] and len(st["retried"]) < 500 and r < 0.65:
                st["retried"].add(target.url)
                lane.__dict__["onion_retry"] = (target.url, now + self.rng.uniform(30, 180))
                if r < 0.15:                             # new identity first, then the reload
                    st["streak"] = st["limit"]
            if st["streak"] >= st["limit"]:
                st["streak"] = 0
                st["limit"] = self.rng.randint(2, 5)
                ok = getattr(lane.transport, "reconnect", lambda: False)()
                self._emit("info", "tor", "Several Tor requests failed in a row; asked Tor for a new identity "
                           f"(fresh circuits){'' if ok else ' — control port unavailable, new circuits only'}.")
                st["next_newnym"] = now + self.rng.uniform(600, 2400)
                return
        if now >= st["next_newnym"]:
            st["next_newnym"] = now + self.rng.uniform(600, 2400)
            if getattr(lane.transport, "renew_circuits", lambda: False)():
                self._emit("info", "tor", "Switched to new Tor circuits (routine, every 10-40 minutes).")

    def _rest_host(self, host: str, seconds: float) -> None:
        self.__dict__.setdefault("_rested", {})[host] = time.time() + seconds

    def _host_rested(self, url: str) -> bool:
        import urllib.parse as _up
        h = (_up.urlparse(url).hostname or "").removeprefix("www.")
        return time.time() < self.__dict__.get("_rested", {}).get(h, 0.0)

    def _dead_path(self):
        from .paths import app_dir
        return app_dir() / "onion_dead.json"

    def _dead_sites(self) -> dict:
        """Onion sites that kept failing: host -> (misses, rest until). Kept between runs, so a site that is
        down is not retried every time the app starts."""
        d = self.__dict__.get("_onion_dead")
        if d is None:
            import json
            try:
                if self.rate is None:                       # tests and the command line keep it in memory only
                    raise OSError
                raw = json.loads(self._dead_path().read_text(encoding="utf-8"))
                d = {h: (int(v[0]), float(v[1])) for h, v in raw.items()}
            except (OSError, ValueError, TypeError, IndexError):
                d = {}
            self.__dict__["_onion_dead"] = d
        return d

    def _onion_seen_dead(self, url: str) -> None:
        import urllib.parse as _up
        host = _up.urlparse(url).hostname or ""
        dead = self._dead_sites()
        fails, _ = dead.get(host, (0, 0.0))
        fails += 1
        # two misses: rest it 6 hours; the longer it keeps failing, the longer the rest (up to 3 days)
        dead[host] = (fails, time.time() + (min(6 * 3600 * (fails - 1) ** 2, 72 * 3600) if fails >= 2 else 0))
        self._save_dead()

    def _onion_seen_alive(self, url: str) -> None:
        import urllib.parse as _up
        host = _up.urlparse(url).hostname or ""
        if self._dead_sites().pop(host, None) is not None:
            self._save_dead()

    def _save_dead(self) -> None:
        import json
        if self.rate is None:
            return
        try:
            self._dead_path().write_text(json.dumps({h: list(v) for h, v in self._dead_sites().items()}), encoding="utf-8")
        except OSError:
            pass

    def _onion_is_dead(self, url: str) -> bool:
        import urllib.parse as _up
        fails, until = self._dead_sites().get(_up.urlparse(url).hostname or "", (0, 0.0))
        return fails >= 2 and time.time() < until

    def _active_hour(self, hour: int) -> bool:
        ex = getattr(self.profile, "extras", None)
        if ex is None or not ex.active_hours:
            return True
        a, b = int(ex.active_from), int(ex.active_to)
        return (a <= hour < b) if a < b else (hour >= a or hour < b) if a > b else True

    def _data_capped(self) -> bool:
        ex = getattr(self.profile, "extras", None)
        return bool(ex and ex.daily_data_mb > 0 and self.bytes_today >= ex.daily_data_mb * 1_000_000)

    def reset_budgets(self) -> None:
        for lane in self.lanes:
            for b in lane.budgets.values():
                b.spent = b.failures = 0
                b.history.clear()
            lane.hits_by_identity = lane.consecutive_failures = 0
        self.day_failures = self.day_onion_failures = 0
        self.bytes_today = 0
        self._emit("info", "scheduler", "New day — daily budgets reset.")

    def _probe(self, lane: Lane, identity: Identity, target: Target) -> HitResult:
        if self.probe_fn:
            return self.probe_fn(lane, identity, target)
        if target.kind == "dns":
            return self._dns_probe(target)
        if target.kind == "pkg":
            return self._pkg_probe(lane, target)
        t0 = time.time()
        res = lane.transport.hit(identity, target)
        total = (time.time() - t0) * 1000.0
        res.latency_ms = getattr(res, "load_ms", None) or total     # page load only; time on page separate
        return res

    def _dns_probe(self, target: Target) -> HitResult:
        """Raw crafted-UDP DNS on the clearnet lane; the hit IS the packet."""
        from .engines import DnsNoise, build_dns_query
        rest = target.url[len("dns://"):]
        server, _, domain = rest.partition("/")
        if not domain:
            return HitResult(None, error="malformed dns target")
        packet = build_dns_query(domain, qid=self.rng.randint(0, 0xFFFF))
        ex = getattr(self.profile, "extras", None)
        if server == "system":
            if DnsNoise.resolve_system(domain, timeout=target.timeout):
                res = HitResult(200, "")
                res.bytes = 100 * (1 + self._dns_burst(server, domain, None))
                return res
            return HitResult(None, error="lookup via your normal DNS failed")
        noise = DnsNoise(self.rng, self.wordlist, self.domains)
        if noise.fire(packet, server, timeout=target.timeout):
            if ex is not None and ex.browser_dns:        # browsers also ask for IPv6 and HTTPS records
                for qtype in ("AAAA", "HTTPS"):
                    noise.fire(build_dns_query(domain, self.rng.randint(0, 0xFFFF), qtype), server, timeout=1.5)
            res = HitResult(200, "")
            res.bytes = (300 if ex is not None and ex.browser_dns else 100) * (1 + self._dns_burst(server, domain, noise))
            return res
        return HitResult(None, error=f"dns query to {server} failed")

    DNS_BURST_CHANCE = 0.85          # most lookups in real traffic come from a page load, so most are followed by a burst

    def _dns_burst(self, server: str, domain: str, noise) -> int:
        """The lookups a page load makes right after the site's own (fonts, scripts, other sites), a few tens of
        milliseconds apart. Returns how many were made. They are part of the one DNS hit, not extra hits."""
        ex = getattr(self.profile, "extras", None)
        if ex is None or not getattr(ex, "dns_bursts", False) or self.rng.random() >= self.DNS_BURST_CHANCE:
            return 0
        from .engines import DnsNoise, build_dns_query, burst_hosts
        n = 0
        for host in burst_hosts(self.rng, self.domains, domain):
            if self._stopped():
                break
            self.sleep_fn(self.rng.uniform(0.02, 0.35))
            if server == "system":
                n += bool(DnsNoise.resolve_system(host, timeout=2.0))
            else:
                n += bool(noise.fire(build_dns_query(host, self.rng.randint(0, 0xFFFF)), server, timeout=1.5))
        return n

    def _packages(self, lane: Lane):
        pk = self.__dict__.get("_pkg")
        if pk is None:
            from .packages import PackageNoise
            from .paths import app_dir
            proxy = getattr(lane.transport, "proxy", None)
            pk = self.__dict__["_pkg"] = PackageNoise(app_dir() / "packages", self.rng,
                                                      persona=self.profile.extras.persona,
                                                      proxy=proxy if isinstance(proxy, str) else None)
        return pk

    def _pkg_probe(self, lane: Lane, target: Target) -> HitResult:
        """A real pip/npm command in legalPrivacy's own throwaway environment."""
        action, _, pkg = target.url[len("pkg://"):].partition("/")
        t0 = time.time()
        r = self._packages(lane).do(action, pkg)
        res = HitResult(200 if r["ok"] else None, "", error=r["error"])
        res.bytes, res.latency_ms = r["bytes"], (time.time() - t0) * 1000.0
        return res

    def _dns_label(self, server: str) -> str:
        if self.dns_plan is not None:
            for ip, label in self.dns_plan.secure_servers():
                if ip == server:
                    return f"{label} ({ip})"
        return server

    def _local_hour(self) -> float | None:
        if self.local_hour_fn:
            return self.local_hour_fn()
        return ((time.localtime().tm_hour * 60 + time.localtime().tm_min) / 60.0)

    def _identity_pacer_for(self, lane: Lane) -> tuple[Identity, Pacer]:
        """Pin one identity (and its pacer) per circuit/proxy lifetime.

        Tor rotations also signal NEWNYM so the circuit itself turns over,
        not just the fingerprint.
        """
        limit = getattr(lane.transport, "identities_per_circuit", None) or 10
        if lane.identity is None or lane.hits_by_identity >= limit:
            self._ident_counter += 1
            lane.identity = make_identity(self.rng, self._ident_counter, self.wordlist,
                                          entry=self._entry_for_next_identity())
            lane.pacer = Pacer(self.rng,
                               pace_multiplier=lane.identity.pace_multiplier,
                               realtime_scale=self.profile.realtime_scale)
            lane.pacer.sleep_fn = self.sleep_fn
            self._apply_pace(lane.pacer)
            lane.hits_by_identity = 0
            renew = getattr(lane.transport, "renew_circuits", None)
            if renew is not None:
                renew()
        return lane.identity, lane.pacer

    def run_once(self, wait: bool = True) -> bool:
        """Run one scheduled job if any lane wants it. Returns True if a hit was made."""
        hour = self._local_hour()
        options: list[tuple[Lane, str]] = [
            (lane, eng_name)
            for lane in self.lanes for eng_name in lane.engines
            if not lane.budgets[eng_name].exhausted and lane.open and eng_name not in self.side_streams
            and not self._lane_away(lane) and not self._staying_on_page(lane, eng_name)
        ]
        forced = self._follow_due(options) or self._linger_due(options)
        if not options and forced is None:
            return False
        weights = []
        for lane, eng_name in options or []:
            w = float(lane.budgets[eng_name].remaining)
            if getattr(lane.transport, "dimmed", False):
                w *= 0.1  # down-weight dimmed transport so traffic prefers healthy lanes
            weights.append(max(w, 0.01))
        if forced is not None:
            lane, eng_name, target = forced
            identity, pacer = self._identity_pacer_for(lane)
        else:
            lane, eng_name = self.rng.choices(options, weights=weights)[0]
            identity, pacer = self._identity_pacer_for(lane)
            target = self._make_target(lane, eng_name, identity)
        ex = getattr(self.profile, "extras", None)
        if ex is not None and ex.polite and target.kind == "html" and target.role != "search":
            import urllib.parse as _up
            for _ in range(3):                            # polite: no site twice within a minute
                host = _up.urlparse(target.url).hostname or ""
                if self.clock() - self._host_last.get(host, -1e9) >= 60:
                    break
                target = self._make_target(lane, eng_name, identity)
        if target.kind == "html" and target.role != "search" and self._host_rested(target.url):
            for _ in range(4):                     # that site asked for a login recently: go elsewhere
                target = self._make_target(lane, eng_name, identity)
                if target.kind != "html" or target.role == "search" or not self._host_rested(target.url):
                    break
        if target.role == "search" and eng_name != "search":           # a visit that starts with a search
            eng_name = "search"
        if lane.linger and lane.linger["mode"] == "work" and lane.linger["engine"] == eng_name \
                and target.role != "linger" and self.clock() >= lane.linger.get("other_at", 0.0):
            lane.linger["other_at"] = self.clock() + self._other_site_gap()     # a detour: the next one is far off
        elif lane.linger and lane.linger["mode"] == "away" and target.role != "linger" \
                and self.clock() >= lane.linger.get("other_at", math.inf):
            lane.linger["other_at"] = self.clock() + self._away_detour_gap()    # a detour while away, then quiet again
        self.current = {"lane": lane.name, "engine": eng_name, "url": target.url, "started": time.time(),
                        "role": target.role}
        try:
            result = self._probe(lane, identity, target)
        finally:
            self.current = None
        if target.kind == "html" and target.role != "search" and result.ok:
            if not getattr(lane.transport, "is_browser", False):
                from .safety import page_language
                lang = page_language(result.html or "")
                if lang and not lang.startswith("en"):
                    result.foreign, result.html = True, ""
                    result.detail = "not in English: moved on"
            if getattr(result, "foreign", False):          # not in English: leave that site alone for a week
                import urllib.parse as _up
                h = (_up.urlparse(getattr(result, "final_url", "") or target.url).hostname or "").removeprefix("www.")
                if h:
                    self._rest_host(h, self.rng.uniform(5, 9) * 86400)
            if not getattr(result, "login_wall", False) and not getattr(result, "foreign", False) \
                    and not getattr(lane.transport, "is_browser", False):
                from .loginwall import looks_like_login_wall
                if looks_like_login_wall(target.url, html=result.html or ""):
                    result.login_wall, result.html = True, ""
                    result.detail = "login required: moved on"
            if getattr(result, "login_wall", False):
                import urllib.parse as _up
                for u in (target.url, getattr(result, "final_url", "") or ""):
                    h = (_up.urlparse(u).hostname or "").removeprefix("www.")
                    if h and not any(x in h for x in ("accounts.", "login.", "auth.")):
                        self._rest_host(h, self.rng.uniform(3, 8) * 3600)    # rest the site for a few hours
        if eng_name == "onion" and not result.ok and _onion_offline(result):
            result.error = "site offline (common for .onion sites; skipped for a while)"
            result.offline = True
            self._onion_seen_dead(target.url)
        if lane.name == "tor":
            self._tor_patience(lane, eng_name, target, result)
        if target.role == "search" and result.status == 429:
            from .engines import cool_down_engine
            hours = self.rng.uniform(2, 8)
            host = cool_down_engine(target.url, hours * 3600)
            if host:
                self._emit("warn", lane.name, f"{host} showed its “are you a robot?” check. Using other search "
                           f"engines for about {hours:.0f} h, the way a person would switch.")
        if target.role == "search" and not result.ok and any(
                k in (result.error or "") for k in ("ERR_HTTP2_PROTOCOL_ERROR", "ERR_CONNECTION_RESET",
                                                   "ERR_EMPTY_RESPONSE", "ERR_QUIC_PROTOCOL_ERROR")):
            from .engines import cool_down_engine       # the engine is cutting the connection: use others for a while
            minutes = self.rng.uniform(30, 120)
            host = cool_down_engine(target.url, minutes * 60)
            if host:
                self._emit("warn", lane.name, f"{host} cut the connection ({result.error[:60]}). Using other search "
                           f"engines for about {minutes:.0f} minutes.")
        if target.kind == "html":
            import urllib.parse as _up
            self._host_last[_up.urlparse(target.url).hostname or ""] = self.clock()
        self.bytes_today += int(getattr(result, "bytes", 0) or len(result.html or ""))
        budget = lane.budgets[eng_name]
        if result.ok:
            budget.record_hit(self.clock())
            if eng_name == "onion":
                self._onion_seen_alive(target.url)
            lane.hits_by_identity += 1
            lane.hits_total += 1
            lane.consecutive_failures = 0
            lane.last_hit_ts = time.time()
            lane.last_error = None
            if getattr(lane.transport, "dimmed", False):
                lane.transport.dimmed = False
            self._settle(lane, eng_name, target, result)
            self._maybe_linger(lane, eng_name, target)
        else:
            budget.record_failure(self.clock())
            lane.failures_total += 1
            lane.last_error = result.error or f"HTTP {result.status}"
            lane.consecutive_failures += 1
            pacer.on_failure(max(1, budget.failures))
            # Rotate identity & request new circuit if failing repeatedly
            if lane.consecutive_failures >= 3:
                lane.identity = None
                lane.hits_by_identity = 0
                lane.consecutive_failures = 0
            if eng_name == "onion":          # a dead onion is normal; restart the walk
                lane.onion_next, lane.onion_depth = None, 0
        lane.last_latency_ms = getattr(result, "latency_ms", None)
        # Onion services are routinely offline: they don't count toward the clearnet failure cap
        # (they get their own, more generous one).
        if not result.ok:
            if eng_name == "onion":
                self.day_onion_failures += 1
            else:
                self.day_failures += 1
        total_failures, onion_failures = self.day_failures, self.day_onion_failures
        self._record_hit(lane, eng_name, identity, target, result)
        if self._data_capped():
            raise MaxFailuresExceeded("daily data cap reached")
        if total_failures > self.profile.daily_max_failures or \
                onion_failures > self.profile.daily_max_failures * 3:
            raise MaxFailuresExceeded("daily_max_failures exceeded — stopping run")
        if result.dim_transport and hasattr(lane.transport, "dimmed"):
            lane.transport.dimmed = True
        if wait:
            if any(ln.follow_next is not None for ln in self.lanes):       # about to click a result: a few seconds
                pacer.sleep_fn(self.rng.uniform(4, 18) * self.profile.realtime_scale)
            elif self.rate is None or pacer.backoff_pending():
                pacer.wait(hour)                       # CLI/tests, or honouring a failure backoff
            else:
                # app mode: irregular sittings whose hourly total still fits the hour
                hits_left = sum(b.remaining for ln in self.lanes for e, b in ln.budgets.items()
                                if e not in self.side_streams)
                seconds_left = max(60.0, self._hour_end - self.clock())
                gap = self._sessions.next_gap(hits_left, seconds_left, self.profile.realtime_scale)
                pacer.sleep_fn(gap)
        return True

    def _record_hit(self, lane: Lane, eng_name: str, identity: Identity,
                    target: Target, result: HitResult) -> None:
        self._hit_seq += 1
        status = f"HTTP {result.status}" if result.status else (result.error or "ERROR")
        shown = (target.url.split("/", 3)[-1] if target.kind == "dns"                # dns: just the name
                 else target.note if target.kind == "pkg" else target.url)              # pkg: "pip install numpy"
        rec = {
            "seq": self._hit_seq, "ts": time.time(), "lane": lane.name, "engine": eng_name,
            "url": shown, "status": result.status, "ok": result.ok,
            "error": result.error, "latency_ms": getattr(result, "latency_ms", None),
            "identity": getattr(identity, "id", None),
            "note": target.note, "role": target.role, "detail": getattr(result, "detail", None),
            "on_page_s": round(getattr(result, "on_page_s", 0) or 0, 1),
        }
        if eng_name == "onion" and target.kind == "html":
            from .onion import builtin_site_name
            rec["site"] = builtin_site_name(target.url) or "a site from your own list"
        self.hit_log.append(rec)
        short = shown if len(shown) <= 90 else shown[:87] + "…"
        if rec.get("site"):
            short = f"{rec['site']} · {short}"
        tag = f" [{target.note}]" if target.note else (" [click]" if target.role == "result" else "")
        self._emit("info" if result.ok or getattr(result, "offline", False) else "warn", lane.name,
                   f"{eng_name:6s} {short}{tag} → {status}"
                   + (f" ({rec['latency_ms']:.0f} ms)" if rec["latency_ms"] else ""), **{"hit": rec["seq"]})
        if self.verbose:
            print(f"[{time.strftime('%H:%M:%S')}] [{lane.name}] {eng_name:6s} -> {target.url[:65]} ({status})")
        if not result.ok and lane.name == "tor" and self.verbose:
            print(f"  [tor notice] {result.error or 'Hit failed'}.", file=sys.stderr)

    def _settle(self, lane: Lane, eng_name: str, target: Target, result: HitResult) -> None:
        """Post-hit bookkeeping: advance the crawl random-walk from fetched HTML."""
        if eng_name == "onion":
            nxt = lane.onion_factory.next_from(result.html, target.url) \
                if lane.onion_factory is not None and result.html else None
            max_depth = self.profile.engines["onion"].max_depth
            if nxt is not None and lane.onion_depth < max_depth:
                lane.onion_next, lane.onion_depth = nxt, lane.onion_depth + 1
            else:
                lane.onion_next, lane.onion_depth = None, 0
            return
        if eng_name == "search":
            lane.follow_next = None
            if target.role == "result" and self.domains is not None and hasattr(self.domains, "remember"):
                import urllib.parse as _u
                self.domains.remember(_u.urlparse(target.url).hostname or "")
            if result.html:
                if target.role == "search" and lane.pending_visit is not None:
                    pv, lane.pending_visit = lane.pending_visit, None
                    pick = lane.search_factory.result_target(result.html, target.url, prefer_host=pv.host) \
                        if lane.search_factory is not None else None
                    if pick is None or pv.host.removeprefix("www.") not in pick.url:
                        pick = Target(url=pv.url, referer=target.url, role="result")   # the site we were after
                    pick.note = "found by searching"
                    lane.follow_next = pick
                elif target.role == "search" and self.rng.random() < self.click_prob \
                        and lane.search_factory is not None:
                    lane.follow_next = lane.search_factory.result_target(result.html, target.url)
                elif target.role == "result" and self.rng.random() < 0.25:
                    from .engines import CrawlTargetFactory
                    lane.follow_next = CrawlTargetFactory(rng=self.rng, seeds=[]).next_from(
                        result.html, target.url)
            return
        if eng_name != "crawl" or not result.html:
            return
        nxt = lane.crawl_factory.next_from(result.html, target.url) \
            if lane.crawl_factory is not None else None
        max_depth = self.profile.engines["crawl"].max_depth
        if nxt is not None and lane.crawl_depth < max_depth:
            lane.crawl_next = nxt
            lane.crawl_depth += 1
        else:
            lane.crawl_next = None
            lane.crawl_depth = 0

    def _make_target(self, lane: Lane, eng_name: str, identity: Identity) -> Target:
        from .engines import CrawlTargetFactory, DnsNoise, SearchTargetFactory
        words = self.wordlist
        if eng_name == "onion":
            from .onion import OnionTargetFactory
            retry = lane.__dict__.get("onion_retry")
            if retry and self.clock() >= retry[1]:      # the page that failed a minute ago: try once more
                lane.__dict__["onion_retry"] = None
                if not self._onion_is_dead(retry[0]):
                    from .transports import Target as _T
                    return _T(url=retry[0], timeout=60.0, note="retry")
            if lane.onion_next is not None:
                return lane.onion_next
            tor_cfg = self.profile.transports.get("tor")
            if lane.onion_factory is None:
                lane.onion_factory = OnionTargetFactory(
                    rng=self.rng, seeds=list(tor_cfg.onion_seeds) if tor_cfg and tor_cfg.onion_seeds else [],
                    max_depth=self.profile.engines["onion"].max_depth,
                    follow_offsite=bool(tor_cfg.onion_follow_offsite) if tor_cfg else True)
            for _ in range(8):                       # skip sites that were offline recently
                t = lane.onion_factory.make(identity)
                if not self._onion_is_dead(t.url):
                    return t
            return t
        if eng_name == "search":
            if lane.follow_next is not None:
                nxt, lane.follow_next = lane.follow_next, None
                return nxt
            if lane.search_factory is None:
                lane.search_factory = SearchTargetFactory(
                    rng=self.rng, words=words, queries=self.queries,
                    html_mode=not getattr(lane.transport, "is_browser", False))
            return lane.search_factory.make(identity)
        if eng_name == "crawl":
            if lane.crawl_next is not None:
                return lane.crawl_next
            cfg = self.profile.engines["crawl"]
            lane.crawl_factory = CrawlTargetFactory(rng=self.rng, seeds=cfg.seeds,
                                                    max_depth=cfg.max_depth,
                                                    same_site_only=cfg.same_site_only,
                                                    domains=self.domains)
            visit = lane.crawl_factory.make(identity)
            led = self._search_led(lane, visit)
            return led or visit
        if eng_name == "dns":
            fac = DnsNoise(rng=self.rng, words=words, domains=self.domains, plan=self.dns_plan)
            _packet, domain, server = fac.make_query()
            via = "your normal DNS" if server == "system" else self._dns_label(server)
            return Target(url=f"dns://{server}/{domain}", kind="dns", timeout=4.0, note=f"via {via}")
        if eng_name == "packages":
            pk = self._packages(lane)
            action, pkg = pk.choose()
            label = pk.label(action, pkg)
            return Target(url=f"pkg://{action}/{pkg}", kind="pkg", timeout=600.0, note=label)
        raise ValueError(f"unknown engine '{eng_name}'")

    def run(self) -> dict[str, dict[str, int]]:
        """Drain budgets across lanes (respects max_iterations safety net)."""
        iterations = 0
        while iterations < self.max_iterations and not self._stopped():
            if all(lane.budgets[e].exhausted
                   for lane in self.lanes for e in lane.engines):
                break
            if not self.run_once():
                self.sleep_fn(1.0)       # lanes gated (e.g. Tor still bootstrapping)
            iterations += 1
        return {lane.name: {eng: lane.budgets[eng].spent for eng in lane.engines}
                for lane in self.lanes}

    # ── search-led visits: look the topic up first, then click through to the site ──────────────────
    def _search_led(self, lane: Lane, visit: Target) -> Target | None:
        """Most visits to a site from the persona begin with a search that would lead there."""
        if self.rate is None or "search" not in lane.engines or lane.budgets["search"].exhausted \
                or self.rng.random() > 0.65:
            return None
        from .interests import query_for_site
        host = urllib.parse.urlparse(visit.url).netloc + urllib.parse.urlparse(visit.url).path
        query = query_for_site(self.rng, host)
        if not query:
            return None
        from .engines import SearchTargetFactory
        if lane.search_factory is None:
            lane.search_factory = SearchTargetFactory(
                rng=self.rng, words=self.wordlist, queries=self.queries,
                html_mode=not getattr(lane.transport, "is_browser", False))
        lane.pending_visit = visit
        return lane.search_factory.for_query(query, note=f"looking for {urllib.parse.urlparse(visit.url).netloc}")

    def _follow_due(self, options):
        """A search was just done: its click-through comes next, right away, not whenever the dice allow."""
        for lane in self.lanes:
            nxt = lane.follow_next
            if nxt is not None and lane.open and not self._lane_away(lane):
                lane.follow_next = None
                return lane, "search", nxt
        return None

    # ── long sessions: one page for a long time, or away for hours and back to it ──────────────
    def _lane_away(self, lane: Lane) -> bool:
        lg = lane.linger
        now = self.clock()
        return bool(lg and lg["mode"] == "away" and now < lg["until"] and now < lg.get("other_at", math.inf))

    # For the default persona, a share of the long sessions (both kinds) are a chat on duck.ai.
    DUCK_AI_URL = "https://duck.ai/"
    DUCK_AI_CHANCE = 0.2

    def _away_detour_gap(self) -> float:
        """While stepped away, the odd thing still happens (a mail check, a quick lookup), about every 10-40 min."""
        return self.rng.uniform(600, 2400) * self.profile.realtime_scale

    # While a long session is on, the same kind of visit elsewhere is rare: about a 15% chance in any 10 minutes
    # (once an hour or so), so most of the time is spent on the page that matters to "you".
    OTHER_SITE_CHANCE_10MIN = 0.15

    def _other_site_gap(self) -> float:
        mean_s = -600.0 / math.log(1.0 - self.OTHER_SITE_CHANCE_10MIN)            # about 61 minutes
        return self.rng.expovariate(1.0 / mean_s) * self.profile.realtime_scale

    def _staying_on_page(self, lane: Lane, eng_name: str) -> bool:
        lg = lane.linger
        return bool(lg and lg["mode"] == "work" and lg["engine"] == eng_name and self.clock() < lg.get("other_at", 0.0))

    def _linger_due(self, options) -> tuple | None:
        """The page a long session goes back to now, if one is due: (lane, engine, target)."""
        now = self.clock()
        for lane in self.lanes:
            lg = lane.linger
            if not lg or not lane.open:
                continue
            if lg["mode"] == "work" and now >= lg["until"]:
                lane.linger = None                         # finished with it
                continue
            due = now >= (lg["until"] if lg["mode"] == "away" else lg["next_at"])
            if not due or lane.budgets[lg["engine"]].exhausted:
                continue
            scale = self.profile.realtime_scale
            if lg["mode"] == "away":                       # back at the computer: carry on with the same page
                note = "back after being away, same page"
                lane.linger = {**lg, "mode": "work", "until": now + self.rng.uniform(600, 2400) * scale,
                               "next_at": now + self.rng.uniform(120, 600) * scale,
                               "other_at": now + self._other_site_gap()}
            else:
                note = "still working on the same page"
                lg["next_at"] = now + self.rng.uniform(120, 600) * scale
            return lane, lg["engine"], Target(url=lg["url"], timeout=60.0 if lg["engine"] == "onion" else 25.0,
                                              note=note, role="linger", dwell=self.rng.uniform(60, 300) * scale)
        return None

    def _maybe_linger(self, lane: Lane, eng_name: str, target: Target) -> None:
        """Now and then a page becomes something you work on for a long time, or leave open for hours."""
        ex = getattr(self.profile, "extras", None)
        if (self.rate is None or ex is None or not getattr(ex, "long_sessions", False) or lane.linger
                or target.kind != "html" or target.role in ("search", "linger") or eng_name not in ("crawl", "onion")):
            return
        r, now, scale = self.rng.random(), self.clock(), self.profile.realtime_scale
        if r < 0.11 and eng_name == "crawl" and getattr(ex, "persona", "") == "Ason" \
                and self.rng.random() < self.DUCK_AI_CHANCE:
            target = Target(url=self.DUCK_AI_URL, role="linger", note="duck.ai chat")   # the page to come back to
        if r < 0.008:                                  # rare, and shorter than before: mostly continued use
            hours = self.rng.uniform(0.5, 2.0)
            lane.linger = {"mode": "away", "url": target.url, "engine": eng_name,
                           "until": now + hours * 3600 * scale, "next_at": 0.0,
                           "other_at": now + self._away_detour_gap()}
            self._emit("info", lane.name, f"Long session: left a page open and stepped away for about {hours:.1f} h "
                                          "(a little other activity continues meanwhile).")
        elif r < 0.11:
            minutes = min(180.0, max(15.0, self.rng.lognormvariate(3.7, 0.6)))    # typically ~40 minutes
            lane.linger = {"mode": "work", "url": target.url, "engine": eng_name,
                           "until": now + minutes * 60 * scale, "next_at": now + self.rng.uniform(120, 600) * scale,
                           "other_at": now + self._other_site_gap()}
            self._emit("info", lane.name, f"Long session: keeps coming back to the same page for about "
                                          f"{minutes:.0f} minutes.")

    def _side_loop(self, eng_name: str) -> None:
        """One kind of noise on its own schedule, at the same time as everything else."""
        while not self._stopped():
            if self.paused or self.hour is None:
                self.sleep_fn(1.0)
                continue
            lanes = [ln for ln in self.lanes
                     if eng_name in ln.engines and ln.open and not ln.budgets[eng_name].exhausted]
            if not lanes:
                self.sleep_fn(5.0)
                continue
            lane = lanes[0]
            budget = lane.budgets[eng_name]
            # spread what's left of this hour's allowance over what's left of the hour, irregularly
            seconds_left = max(30.0, self._hour_end - self.clock())
            gap = seconds_left / max(1, budget.remaining) * self.rng.uniform(0.4, 1.6)
            self.sleep_fn(min(gap, seconds_left) * self.profile.realtime_scale)
            if self._stopped() or self.paused:
                continue
            target = self._make_target(lane, eng_name, lane.identity)
            try:
                result = self._probe(lane, lane.identity, target)
            except Exception as exc:                       # a side stream must never take the app down
                result = HitResult(None, error=f"{type(exc).__name__}: {exc}")
            with self._rec_lock:
                self.bytes_today += int(getattr(result, "bytes", 0) or 0)
                if result.ok:
                    budget.record_hit(self.clock())
                    lane.hits_total += 1
                    lane.last_hit_ts = time.time()
                else:
                    budget.record_failure(self.clock())
                    lane.failures_total += 1
                    lane.last_error = result.error or f"HTTP {result.status}"
                    self.day_failures += 1
                self._record_hit(lane, eng_name, lane.identity, target, result)
                if self._data_capped():
                    self.paused = "failures"

    def _start_side_streams(self) -> None:
        for eng in self.side_streams:
            th = threading.Thread(target=self._side_loop, args=(eng,), daemon=True, name=f"side-{eng}")
            th.start()
            self._side_threads.append(th)

    def run_forever(self) -> None:
        """Long-running mode for the app: honours stop/pause, resets budgets daily."""
        self._emit("info", "scheduler", "Noise generation started.")
        self._start_side_streams()
        while not self._stopped():
            now = time.localtime()
            if now.tm_yday != self.day:
                self.day = now.tm_yday
                self.reset_budgets()
                self.paused = False if self.paused == "failures" else self.paused
            if self.rate is not None and now.tm_hour != self.hour:
                first = self.hour is None
                total = self.plan_hour(now.tm_hour)
                # first plan after Start: begin within seconds. Later hours: a short, random offset,
                # never a burst exactly on the hour mark.
                wait = self.rng.uniform(3, 20) if first else self.rng.uniform(0, min(120.0, 3600.0 / max(total, 0.25)))
                if first:
                    self._emit("info", "scheduler", f"First action in about {wait:.0f} seconds.")
                self.sleep_fn(wait * self.profile.realtime_scale)
                continue
            if self.paused:
                self.sleep_fn(1.0)
                continue
            if self._activity_says_wait():
                continue
            try:
                worked = self.run_once()
            except MaxFailuresExceeded as exc:
                self._emit("warn" if "data cap" in str(exc) else "error", "scheduler",
                           f"{str(exc)[0].upper()}{str(exc)[1:]}. Pausing until tomorrow.")
                self.paused = "failures"           # auto-resumes at the next day reset
                continue
            if not worked:
                self.sleep_fn(2.0)       # all budgets spent or lanes gated: idle politely
        self.close()
        self._emit("info", "scheduler", "Noise generation stopped.")

    def close(self) -> None:
        """Release transport resources (real browsers) from the thread that used them."""
        for lane in self.lanes:
            fn = getattr(lane.transport, "close", None)
            if fn:
                try:
                    fn()
                except Exception:
                    pass
