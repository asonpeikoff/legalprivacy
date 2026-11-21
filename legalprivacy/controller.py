"""Application controller: one object the UI (and CLI) drives.

Owns the profile, the Tor manager, the scheduler thread and the event log, and
exposes simple start/stop/configure operations plus a JSON-friendly state()
snapshot for the dashboard.
"""
from __future__ import annotations

import copy
import hashlib
import json
import platform
import re
import random
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

import yaml

from . import __version__
from .config import (ConfigError, Profile, apply_overrides, profile_to_dict)
from .engines import ENGINE_NAMES, SEARCH_WEIGHTS, load_wordlist
from .dnsplan import DnsPlan
from .domains import DomainPool
from .rate import RatePlanner, describe as describe_rate
from .events import EventLog
from .feeds import FeedStore
from .queries import QueryConfig, QuerySource
from .onion import BUILTIN_ONION_SEEDS, clean_seed_list
from .paths import app_dir, config_path, resolve_resource, write_private
from .scheduler import MaxFailuresExceeded, Runner, build_lanes
from .tormanager import TorManager, find_tor_binary, port_open

PRESETS = {   # budgets per day: search / crawl / dns / onion
    "light":  {"search": 50,  "crawl": 20,  "dns": 80,  "onion": 15},
    "normal": {"search": 120, "crawl": 40,  "dns": 200, "onion": 40},
    "heavy":  {"search": 300, "crawl": 100, "dns": 500, "onion": 100},
}
def wipe_old_log_files() -> None:
    """Delete any cricket.log left by an older version. The app keeps no log files."""
    for name in ("cricket.log", "cricket.log.1"):
        try:
            (app_dir() / name).unlink()
        except OSError:
            pass


APP_DEFAULTS = {"observe": True, "autostart": False, "open_browser": True, "port": 8765, "intensity": "normal",
                "auto_refresh_sources": False,   # off: use the snapshot shipped with the app (no lookups)
                "ml_auto": False, "ml_history": [],
                "clear_logs_on_restart": True}


class Controller:
    def __init__(self, profile_path: str | None = None):
        wipe_old_log_files()                      # older versions wrote cricket.log to disk
        self.log = EventLog()                     # live log is memory-only (never written to disk)
        self._save_lock = threading.RLock()       # autosave: concurrent saves are serialised
        self.profile_path = profile_path or str(config_path())
        self.first_run = not Path(self.profile_path).exists()
        self.app: dict[str, Any] = dict(APP_DEFAULTS)
        self.profile: Profile = Profile(name="default")
        self._load()
        self.tor: TorManager | None = None
        self.feeds = FeedStore(self.log)
        from .observe import TrafficObserver
        self.observer = TrafficObserver(
            noise_on=lambda: self.running and not (self.runner and self.runner.paused),
            noise_requests=self._requests_in_minute,
            tor_pid=lambda: (self.tor.pid if self.tor else None),
            path=app_dir() / "observe.json")
        from .har import HarStore
        self.har = HarStore(app_dir() / "har.json")      # derived counts from an imported browser recording
        self._hist_cache: tuple | None = None            # (read at, [(time, site)]) for the baseline fallback
        self._hist_thread: threading.Thread | None = None
        self.observer.baseline_fn = self._baseline
        self._feed_timer_started = False
        from .relayrun import RelayManager
        self.relay = RelayManager(self.log)        # optional relay: its own Tor process, practice mode unless set up
        from .accounts import AccountsManager
        self.accounts = AccountsManager(          # optional signed-in accounts; clearnet only, never Tor
            self.log, config=lambda: self.profile.accounts,
            running=lambda: self.running and not (self.runner and self.runner.paused),
            proxy=lambda: self.profile.transports["clearnet"].proxy,
            tor_addrs=lambda: tuple(filter(None, (getattr(self.tor, "socks_addr", None),
                                                  self.profile.transports["tor"].socks))))
        from .av import AvManager
        self.av = AvManager(self.log)             # optional ClamAV manager; runs nothing until you press a button
        self.runner: Runner | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self.log.info("app", f"legalPrivacy {__version__} on {platform.system()} {platform.release()} "
                             f"(Python {platform.python_version()})")
        self.log.info("app", f"Config: {self.profile_path}")
        threading.Thread(target=self._ml_auto_loop, daemon=True, name="ml-auto").start()   # needs self.app, so last

    # ── config ──────────────────────────────────────────────────────────────
    def _load(self) -> None:
        p = Path(self.profile_path)
        if not p.exists():
            return
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            self.profile = apply_overrides(Profile(name="default"), raw)
            self.app |= {k: v for k, v in (raw.get("app") or {}).items() if k in APP_DEFAULTS}
        except Exception as exc:
            self.log.error("app", f"Could not read config ({exc}); using defaults.")

    def _save(self) -> None:
        # Settings save themselves, so two saves can arrive together: serialise them, and give
        # each its own temporary file so one can never move the other's away.
        with self._save_lock:
            data = profile_to_dict(self.profile)
            data["app"] = self.app
            path = Path(self.profile_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            write_private(path, yaml.safe_dump(data, sort_keys=False))     # holds bridges and passwords
            self.first_run = False

    def wizard(self, answers: dict[str, Any]) -> dict:
        """Apply the 2–3 first-run answers and save.

        intensity: light|normal|heavy       tor: off|onion
        autostart: bool
        """
        raw: dict[str, Any] = {"rate": {"mode": answers.get("rate_mode", "random"),
                                        "level": float(answers.get("level", 5))},
                               "transports": {"tor": {"enabled": answers.get("tor", "off") != "off",
                                                      "onion": True}}}
        self.apply_config(raw, save=False)
        self.app["autostart"] = bool(answers.get("autostart", False))
        self._save()
        self.log.info("app", f"Setup saved: {self.profile.rate.mode} noise at level {self.profile.rate.level:g}, "
                             f"tor={answers.get('tor', 'off')}.")
        return self.state()

    def apply_config(self, raw: dict[str, Any], save: bool = True) -> dict:
        """Validate+apply a partial profile dict. Takes effect on next (re)start."""
        with self._save_lock:
            return self._apply_config(raw, save)

    def _apply_config(self, raw: dict[str, Any], save: bool = True) -> dict:
        new = copy.deepcopy(self.profile)
        tor_raw = (raw.get("transports") or {}).get("tor") or {}
        if "onion_seeds" in tor_raw:
            seeds = tor_raw["onion_seeds"]
            if isinstance(seeds, str):
                seeds = seeds.splitlines()
            good, bad = clean_seed_list(list(seeds))
            if bad:
                raise ConfigError("invalid onion address(es): " + ", ".join(bad[:3]))
            tor_raw["onion_seeds"] = good
        if "bridges" in tor_raw and isinstance(tor_raw["bridges"], str):
            tor_raw["bridges"] = [ln.strip() for ln in tor_raw["bridges"].splitlines() if ln.strip()]
        apply_overrides(new, raw)
        self.profile = new
        if save:
            self._save()
        self.log.info("app", "Settings saved." + (" Restart noise to apply." if self.running else ""))
        return self.state()

    def update_app(self, raw: dict[str, Any]) -> None:
        for k in ("autostart", "open_browser", "auto_refresh_sources", "ml_auto", "observe", "clear_logs_on_restart"):
            if k in raw:
                self.app[k] = bool(raw[k])
        if "observe" in raw:
            (self.observer.start if self.app["observe"] else self.observer.stop)()
        self._save()
        self._start_feed_timer()

    # ── Tor ─────────────────────────────────────────────────────────────────
    def _tor_cfg(self):
        return self.profile.transports["tor"]

    def tor_manager(self) -> TorManager:
        cfg = self._tor_cfg()
        mode = "managed" if cfg.manage else "external"
        if self.tor is None or self.tor.mode != mode or self.tor.ext_socks != cfg.socks \
                or self.tor.bridges != [b.strip() for b in cfg.bridges if b.strip()] \
                or self.tor.configured_bridge_mode != cfg.bridge_mode or self.tor.bridge_auto != cfg.bridge_auto \
                or (self.tor.dns_port_cfg, self.tor.dns_lan, self.tor.dns_lan_addr) != (
                    cfg.dns_port, cfg.dns_lan, cfg.dns_lan_addr):
            if self.tor and self.tor.state not in ("stopped",):
                self.tor.stop()
            self.tor = TorManager(self.log, mode=mode, socks=cfg.socks, control=cfg.control,
                                  control_password=cfg.control_password,
                                  bridges=cfg.bridges, auto_install=cfg.auto_install,
                                  bridge_mode=cfg.bridge_mode, bridge_auto=cfg.bridge_auto,
                                  dns_port=cfg.dns_port, dns_lan=cfg.dns_lan, dns_lan_addr=cfg.dns_lan_addr)
        return self.tor

    # ── DNS resolver table: health + verification ──────────────────────────
    def _requests_in_minute(self, t: int) -> int:
        r = self.runner
        if not r:
            return 0
        return sum(1 for h in list(r.hit_log) if t <= h["ts"] < t + 60)

    # ── imported browser recording (HAR): counts and site names only ───────
    def har_state(self) -> dict:
        from .har import summary
        return summary(self.har.load())

    def har_import(self, body: dict) -> dict:
        from .har import HarError, parse_har
        src = body if isinstance(body.get("log"), dict) else body.get("text")
        if src is None:
            raise ConfigError("Choose a HAR file to import.")
        try:
            data = parse_har(src, denylist=self.feeds.denylist())
        except HarError as exc:
            raise ConfigError(str(exc)) from None
        finally:
            src = body = None                              # the file's contents are not kept
        self.har.save(data)
        self.log.info("har", f"Imported a browser recording: {data['entries']} requests "
                             f"({data['skipped']} skipped). Only times and site names were kept.")
        return self.har_state()

    def har_forget(self, what: str = "all") -> dict:
        self.har.forget("hosts" if what == "hosts" else "all")
        self.log.info("har", "Removed the imported browser recording's " + ("site list." if what == "hosts" else "data."))
        return self.har_state()

    def _history_events(self) -> list | None:
        """Browser history as a last-resort baseline: read in the background (it can take seconds), kept in
        memory for 10 minutes, never saved. None until the first read finishes."""
        c, now = self._hist_cache, time.time()
        if (c is None or now - c[0] > 600) and not (self._hist_thread and self._hist_thread.is_alive()):
            def go():
                try:
                    from .history import visit_events
                    ev = sorted(visit_events(time.time() - 14 * 86400, time.time())["events"])
                except Exception:
                    ev = []
                self._hist_cache = (time.time(), ev)
            self._hist_thread = threading.Thread(target=go, daemon=True, name="history-baseline")
            self._hist_thread.start()
        return c[1] if c else None

    def _baseline(self) -> dict:
        """Your baseline: imported HAR, else noise-off minutes, else browser history; see baseline.py."""
        from .baseline import select
        har, obs = self.har.load(), self.observer.rows()
        sel = select(har, obs, None)
        if sel["source"] == "none":                          # only touch browser history when nothing else will do
            ev = self._history_events()
            sel = select(har, obs, ev, history_pending=ev is None)
        return sel

    def baseline_status(self) -> dict:
        from .baseline import public
        return public(self._baseline())

    def activity_state(self) -> dict:
        """Data for the Proof tab's activity graphs: intended pattern, this session, baseline vs noise."""
        from .activity import baseline_vs_noise, intended, session
        ex = self.profile.extras
        plan = intended(self.profile.rate, self._search_share(), ex.active_hours, ex.active_from, ex.active_to, ex.persona)
        return {"intended": plan, "session": session(self.observer.timeline(6), plan, self.running),
                "baseline": baseline_vs_noise(self._baseline(), self.observer.rows()), "har": self.har_state(),
                "now": time.time()}

    def observe_state(self) -> dict:
        st = self.observer.state()
        st["enabled"] = bool(self.app.get("observe", True))
        st["running"] = self.running
        return st

    def _fresh_dns_plan(self) -> DnsPlan:
        """One shared plan (keeps health results); re-checks resolvers when they'll be used."""
        plan = getattr(self, "dns_plan", None)
        if plan is None:
            plan = self.dns_plan = DnsPlan(random.Random(), self.profile.dns, self.feeds.items("opennic"))
        plan.cfg = self.profile.dns
        if self.profile.dns.mode != "system":
            plan.check_async()
            with self._lock:
                first = not getattr(self, "_dns_timer", False)
                self._dns_timer = True
            if first:
                def loop():
                    while True:
                        time.sleep(600)
                        if self.running and self.profile.dns.mode != "system":
                            plan.check_async()
                threading.Thread(target=loop, daemon=True, name="dns-recheck").start()
        return plan

    def check_dns(self) -> None:
        plan = getattr(self, "dns_plan", None) or self._fresh_dns_plan()
        plan.cfg = self.profile.dns
        plan.check_async()

    def dns_report(self) -> dict:
        plan = getattr(self, "dns_plan", None)
        if plan is None:
            plan = self.dns_plan = DnsPlan(random.Random(), self.profile.dns, self.feeds.items("opennic"))
        plan.cfg = self.profile.dns
        return plan.report()

    def get_bridges(self, country: str = "") -> dict:
        """Ask the Tor Project's bridge service for bridges that work in a country; save them."""
        from .tormanager import fetch_bridges_for_country
        sets = fetch_bridges_for_country(country)
        lines = [ln for s in sets for ln in s["lines"]]
        if not lines:
            return {"ok": False, "message": "The Tor Project says no bridges are needed for that country "
                                            "(or has none to suggest). Try the built-in ones, or request your own."}
        self.apply_config({"transports": {"tor": {"bridges": lines, "bridge_mode": "custom"}}})
        self.log.info("tor", f"Got {len(lines)} bridge(s) from bridges.torproject.org "
                             f"({', '.join(sorted({s['type'] for s in sets}))}); saved as your bridges.")
        return {"ok": True, "count": len(lines), "types": sorted({s["type"] for s in sets})}

    def tor_selftest(self) -> None:
        """User-initiated check: does traffic leave through Tor, and does an onion site load?"""
        tm = self.tor_manager()
        self.tor_test = {"running": True, "ts": time.time()}

        def go():
            import requests
            from .onion import BUILTIN_ONION_SEEDS
            from .transports import explain_tor_error
            res = {"running": False, "ts": time.time()}
            if not tm.ready:
                res["summary"] = "Tor isn't ready yet — start it and wait for 100%."
                self.tor_test = res
                return
            proxies = {"http": f"socks5h://test:test@{tm.socks_addr}", "https": f"socks5h://test:test@{tm.socks_addr}"}
            try:
                t0 = time.time()
                j = requests.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=60).json()
                res["exit"] = {"ok": bool(j.get("IsTor")), "ip": j.get("IP"), "ms": round((time.time() - t0) * 1000)}
            except Exception as exc:
                res["exit"] = {"ok": False, "error": explain_tor_error(str(exc), tm.socks_addr)}
            url = next(u for n, u in BUILTIN_ONION_SEEDS if n == "Tor Project")
            try:
                t0 = time.time()
                r = requests.get(url, proxies=proxies, timeout=90)
                res["onion"] = {"ok": r.status_code < 400, "status": r.status_code, "ms": round((time.time() - t0) * 1000)}
            except Exception as exc:
                res["onion"] = {"ok": False, "error": explain_tor_error(str(exc), tm.socks_addr)}
            ok = res["exit"]["ok"] and res["onion"]["ok"]
            res["summary"] = ("Tor works: traffic leaves through the Tor network and onion sites load."
                              if ok else "Tor test found a problem — see details.")
            self.log.add("info" if ok else "warn", "tor", "Self-test: " + res["summary"])
            self.tor_test = res
        threading.Thread(target=go, daemon=True, name="tor-selftest").start()

    # ── Tools tab: network checks (user-initiated, clearnet only) ───────────
    def resolvers_check(self) -> dict:
        from . import nettools
        dns = self.profile.dns
        secure = [r["ip"] for r in DnsPlan(random.Random(), dns, self.feeds.items("opennic")).configured()]
        return nettools.dns_leak_check(secure)

    def speed_start(self) -> dict:
        from . import nettools
        st = getattr(self, "_speed", None)
        if st and st.get("state") == "running":
            return st
        self._speed = {"state": "running", "progress": "Starting…", "result": None}
        proxy = self.profile.transports["clearnet"].proxy

        def work():
            res = nettools.speed_test(proxy, progress=lambda s: self._speed.update(progress=s))
            self._speed.update(state="done", progress="", result=res)
            self.log.info("tools", f"Speed test: down {res['down_mbps']} Mbit/s, up {res['up_mbps']} Mbit/s"
                          + (f" ({'; '.join(res['errors'])})" if res["errors"] else ""))
        threading.Thread(target=work, daemon=True).start()
        return self._speed

    # ── My List ──────────────────────────────────────────────────────────────
    def _domain_pool(self, _r):
        ml = self.profile.mylist
        pool = DomainPool(_r.Random(), self.feeds, my_sites=ml.sites if ml.enabled else None,
                          random_share=ml.random_share, my_weights=ml.weights)
        pool.interests, pool.interest_share = self._interests(), self._interest_share()
        pool.site_list = self.profile.extras.site_list
        return pool

    def interests_state(self) -> dict:
        from .interests import CATEGORIES
        it = self._interests()
        ex = self.profile.extras
        hh = []
        if ex.household and ex.interest_salt:
            from .household import Household
            from .useragents import sample_entry
            hh = Household(ex.household_size, ex.interest_salt, sample_entry=sample_entry,
                           mobile_share=self.profile.traffic.mobile_share, device=self.profile.traffic.device).describe()
        from .interests import PERSONAS
        return {"themes": list(CATEGORIES), "active": it.active() if it else [], "household": hh,
                "personas": {k: v for k, v in PERSONAS.items()}, "persona": ex.persona}

    def estimate(self) -> dict:
        """Rough data use before running (idea from NoisyCompany): per day and per month."""
        from .rate import searches_per_hour
        prof, ex, tc = self.profile, self.profile.extras, self.profile.traffic
        eng = {n: (c.budget_per_day if c.enabled else 0) for n, c in prof.engines.items()}
        if not self._tor_cfg().enabled:
            eng["onion"] = 0
        tot = sum(eng.values()) or 1
        actions_h = searches_per_hour(prof.rate.level) / max(eng.get("search", 0) / tot, 0.05)
        hours = 15.0
        if ex.active_hours:
            a, b = ex.active_from, ex.active_to
            hours = float((b - a) % 24 or 24)
        page_mb = 0.4 if ex.low_data else 2.5            # a real-browser page with images vs without
        b_share = (tc.browser / ((tc.browser + tc.plain) or 1)) if self.browser_info()["active"] else 0.0
        per_page = b_share * page_mb + (1 - b_share) * 0.15
        per = {"search": per_page, "crawl": per_page, "dns": 0.0003, "onion": 0.4}
        mb_h = actions_h * sum(eng[n] / tot * per.get(n, 0.2) for n in eng)
        day = mb_h * hours
        if ex.daily_data_mb:
            day = min(day, ex.daily_data_mb)
        return {"mb_per_day": round(day, 1), "gb_per_month": round(day * 30 / 1000, 2),
                "actions_per_hour": round(actions_h), "hours_per_day": hours,
                "real_browser": b_share > 0, "low_data": ex.low_data, "cap_mb": ex.daily_data_mb}

    def selftest(self, days: float = 14) -> dict:
        """How easily the noise could be told apart from your real browsing (local only)."""
        import random as _r
        from .history import visit_events
        from .selftest import evaluate, simulate_noise
        days = max(2.0, min(60.0, float(days)))
        now = time.time()
        since = now - days * 86400
        from .baseline import HOWTO, har_events, human_span
        har = self.har.load()
        real_note, until, from_har = "", now, False
        if har and har.get("top_hosts") and har["entries"] >= 50 and (har["last"] - har["first"]) >= 2 * 3600:
            real = {"events": har_events(har), "errors": []}          # your imported recording comes first
            since, until, from_har = har["first"], har["last"], True  # compare only over the hours it covers
            real_note = ("Your baseline is the browser recording you imported. Site names for each moment were "
                         "re-drawn from its top-sites list, so revisit habits are approximate, and noise was "
                         "compared only over the hours the recording covers.")
        else:
            real = visit_events(since, now)
        hits = [h for h in (self.runner.hit_log if self.runner else []) if h["lane"] != "tor"]
        session_span = (hits[-1]["ts"] - hits[0]["ts"]) if len(hits) > 1 else 0
        if len(hits) >= 200 and session_span >= 86400 and not from_har:
            import urllib.parse as up
            noise = [(h["ts"], (up.urlparse(h["url"]).hostname if "://" in h["url"] else h["url"]) or "")
                     for h in hits]
            source = "this session's noise"
        else:
            noise = simulate_noise(self.profile, self._domain_pool(_r), since, until)
            source = "noise simulated from your current settings"
        ranks = {d: i for i, d in enumerate(self.feeds.items("tranco"))}
        res = evaluate(real["events"], [(t, s.removeprefix("www.")) for t, s in noise if s], ranks)
        n_real = len(real["events"])
        if from_har:
            res["baseline"] = {"source": "har", "status": f"Your baseline: {human_span(until - since)} from your HAR file "
                                                          f"(approximate: see the note below)."}
        elif n_real >= 50:
            res["baseline"] = {"source": "history", "status": f"Your baseline: {n_real:,} visits from your browser "
                                                              f"history over the last {days:g} days."}
        else:
            res["baseline"] = {"source": "none", "status": "Not enough data yet to say how you browse, so no score is "
                                                           "shown. " + HOWTO}
        if "error" in res and n_real < 50:
            res["error"] = ("Not enough data to compare. " + ("Your browser history is empty, erased or too short. "
                            if not n_real else f"Only {n_real} of your visits were found (at least 50 are needed). ") + HOWTO)
        if real_note:
            res.setdefault("warnings", []).append(real_note)
        res.update({"real_visits": len(real["events"]), "noise_events": len(noise), "noise_source": source,
                    "days": days, "errors": real["errors"], "ran_at": time.time()})
        model = res.pop("_model", None)
        if model is not None:
            self._ml_model, self._ml_ranks = model, ranks
            hist = list(self.app.get("ml_history") or [])[-29:] + [[round(time.time()), res["score"]]]
            self.app["ml_history"] = hist             # scores only: no browsing data is kept
            self._save()
        self._ml_last = res
        self.log.info("tools", f"Self-test: {res.get('score', '—')}% ({res.get('verdict', res.get('error', ''))}).")
        return res

    def ml_state(self) -> dict:
        return {"last": getattr(self, "_ml_last", None), "history": self.app.get("ml_history") or [],
                "baseline": self.baseline_status(),
                "auto": bool(self.app.get("ml_auto")), "can_predict": getattr(self, "_ml_model", None) is not None}

    def ml_predict(self, site: str, hour: int, weekday: int) -> dict:
        from .history import site_of
        from .selftest import predict
        if getattr(self, "_ml_model", None) is None:
            raise ConfigError("Run the test once first: predictions use its model.")
        host = site_of(site if "://" in site else "https://" + site) or ""
        if not host:
            raise ConfigError("Enter a site like example.com")
        return {"site": host, "hour": hour, "weekday": weekday,
                "noise_probability": predict(self._ml_model, host, int(hour) % 24, int(weekday) % 7, self._ml_ranks)}

    def _ml_auto_loop(self) -> None:
        """Settings → ML → run automatically: once a day, in the background."""
        while True:
            time.sleep(600)
            try:
                hist = self.app.get("ml_history") or []
                if self.app.get("ml_auto") and (not hist or time.time() - hist[-1][0] > 86400):
                    self.selftest(14)
            except Exception as exc:  # keep the loop alive; report
                self.log.warn("tools", f"Automatic self-test failed: {exc}")

    def privacy_check(self) -> list[dict]:
        from .nettools import privacy_check
        return privacy_check(self)

    def mylist_state(self) -> dict:
        from .history import history_files
        ml = self.profile.mylist
        now = time.time()
        ends = ml.watch_started + ml.watch_hours * 3600 if ml.watch_started else 0
        return {"enabled": ml.enabled, "sites": ml.sites, "weights": ml.weights, "random_share": ml.random_share,
                "watch_hours": ml.watch_hours, "watch_started": ml.watch_started, "watch_ends": ends,
                "watch_done": bool(ml.watch_started) and now >= ends, "now": now,
                "browsers": sorted({f"{f['browser']} ({f['profile']})" for f in history_files()}),
                "running": self.running}

    def mylist_scan(self, days: float) -> dict:
        from .history import top_sites
        try:
            days = max(1.0, min(365.0, float(days)))
        except (TypeError, ValueError):
            raise ConfigError("days must be a number") from None
        res = top_sites(time.time() - days * 86400, denylist=self.feeds.denylist())
        self.log.info("mylist", f"Scanned browser history (last {days:g} days): {len(res['sites'])} sites found.")
        return res

    def mylist_watch(self, action: str, hours: float | None = None) -> dict:
        from .history import top_sites
        ml = self.profile.mylist
        if action == "start":
            try:
                length = float(hours or ml.watch_hours)
            except (TypeError, ValueError):
                raise ConfigError("hours must be a number") from None
            self.apply_config({"mylist": {"watch_started": time.time(), "watch_hours": length}})
            self.log.info("mylist", f"Recording your sites for {self.profile.mylist.watch_hours:g} hours.")
            return self.mylist_state()
        if action == "cancel":
            self.apply_config({"mylist": {"watch_started": 0}})
            return self.mylist_state()
        if action == "collect":
            if not ml.watch_started:
                raise ConfigError("Not recording.")
            end = min(time.time(), ml.watch_started + ml.watch_hours * 3600)    # cut off at the window end
            res = top_sites(ml.watch_started, end, denylist=self.feeds.denylist())
            self.apply_config({"mylist": {"watch_started": 0}})
            self.log.info("mylist", f"Recording collected: {len(res['sites'])} sites.")
            return res
        raise ConfigError(f"unknown action {action}")

    def mylist_bookmarks(self, urls: list | None = None) -> dict:
        """Bookmarks from your browsers, or the links from a bookmarks export file (the page
        extracts just the links and sends those, never titles)."""
        from .history import bookmark_sites, sites_from_urls
        if urls is not None:
            if not isinstance(urls, list):
                raise ConfigError("urls must be a list of addresses")
            res = sites_from_urls([str(u) for u in urls[:50_000]], self.feeds.denylist())
        else:
            res = bookmark_sites(self.feeds.denylist())
        self.log.info("mylist", f"Imported addresses: {len(res['sites'])} sites found.")
        return res

    def mylist_save(self, body: dict) -> dict:
        keep = {k: body[k] for k in ("enabled", "sites", "weights", "random_share") if k in body}
        self.apply_config({"mylist": keep})
        return self.mylist_state()

    # ── user agents (Settings) ─────────────────────────────────────────────
    def ua_state(self) -> dict:
        from .useragents import library
        ident = self.profile.identity
        rows = [{"id": e["id"], "ua": e["ua"], "group": e["group"], "platform": e["platform"],
                 "release": e["release"], "share": e["share"]} for e in library()]
        return {"mode": ident.ua_mode, "rotate_every": ident.rotate_every, "pin": ident.ua_pin,
                "own_ua": ident.own_ua, "library": rows, "running": self.running,
                "applies_to": "Plain-HTTP lane. The real-browser lane always sends its own browser's "
                              "user agent, and the onion lane always uses Tor Browser's fixed one."}

    def ua_save(self, body: dict) -> dict:
        allowed = {k: str(body[k]) for k in ("ua_mode", "rotate_every", "ua_pin", "own_ua") if k in body}
        cur = self.profile.identity
        mode = allowed.get("ua_mode", cur.ua_mode)
        pin = allowed.get("ua_pin", cur.ua_pin)
        own = allowed.get("own_ua", cur.own_ua).strip()
        if mode == "pin" and not pin:
            raise ConfigError("Choose what to pin to first.")
        if mode == "pin" and pin == "own" and not own:
            raise ConfigError("Paste or detect your browser's user agent first.")
        self.apply_config({"identity": allowed})
        return self.ua_state()

    def _learn_own_ua(self) -> None:
        """Default is your own browser's user agent. If it isn't known yet, read it once from the
        installed browser; if that isn't possible, say so (noise rotates until it's pasted)."""
        ident = self.profile.identity
        if ident.ua_mode != "pin" or ident.ua_pin != "own" or ident.own_ua.strip():
            return
        res = self.ua_detect() if self.browser_info()["available"] else {"error": "no browser to read it from"}
        if res.get("ua"):
            self.apply_config({"identity": {"own_ua": res["ua"]}})
            self.log.info("app", "Learned your browser's user agent; noise now looks like your browser.")
        else:
            self.log.warn("app", "Couldn't read your browser's user agent (" + res.get("error", "?") + "). "
                                 "Noise rotates browsers until you paste it in Settings → User agent.")

    def ua_detect(self) -> dict:
        from .useragents import detect_own_ua
        return detect_own_ua()

    def speed_status(self) -> dict:
        return getattr(self, "_speed", None) or {"state": "idle"}

    def tor_action(self, action: str) -> dict:
        tm = self.tor_manager()
        if action == "start":
            tm.start()
        elif action == "stop":
            tm.stop()
        elif action == "restart":
            tm.restart()
        elif action == "newnym":
            tm.new_identity()
        elif action == "install":
            tm.install()
        else:
            raise ConfigError(f"unknown tor action '{action}'")
        return self.tor_state()

    def tor_state(self) -> dict:
        tm = self.tor_manager()
        d = tm.snapshot()
        d["enabled"] = self._tor_cfg().enabled
        d["circuits"] = tm.circuits()
        d["selftest"] = getattr(self, "tor_test", None)
        d["dns_test"] = getattr(self, "_dns_test", None)
        return d

    # ── Tor DNS (optional) ──────────────────────────────────────────────────
    def tor_dns_addresses(self) -> dict:
        """This computer's private addresses, for the 'share on my network' picker (nothing is sent)."""
        from . import tordns
        return {"addresses": tordns.local_private_addresses()}

    def tor_dns_test(self) -> dict:
        """User-initiated: one real A query through Tor's DNSPort for a neutral name."""
        from . import tordns
        info = self.tor_manager().dns_info()
        if not info["on"]:
            res = {"ok": False, "error": "Tor DNS is off. Switch it on and restart Tor first."}
        elif not info["managed"]:
            res = {"ok": False, "error": "Tor DNS works only with the Tor that legalPrivacy manages."}
        elif not info["ready"]:
            res = {"ok": False, "error": "Tor isn't ready yet. Start Tor and wait for 100%, then try again."}
        else:
            res = tordns.probe(info["address"], info["port"])
        res["ts"] = time.time()
        self._dns_test = res
        self.log.add("info" if res["ok"] else "warn", "tor",
                     "Tor DNS test: " + (f"{res['name']} -> {', '.join(res['answers'])} in {res['ms']} ms"
                                         if res["ok"] else res["error"]))
        return res

    # ── Relay (a separate Tor process; starts with the app in practice mode by default) ──
    RELAY_CHECKLIST = ("address", "always_on", "bandwidth", "not_exit", "public_ip")

    @staticmethod
    def _mb_from_rate(rate: str) -> float | None:
        m = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?) ?MBytes", rate or "")
        return float(m.group(1)) if m else None

    def relay_preview(self, body: dict) -> dict:
        """The torrc these (unsaved) settings would produce, or the plain reason they are not valid. Saves nothing."""
        from .config import RelayConfig
        from .relay import generate_torrc
        cur = self.profile.relay
        try:
            mb = float(body.get("bandwidth_mb", self._mb_from_rate(cur.bandwidth_rate) or 1.0))
            if not (0.1 <= mb <= 1000):
                raise ConfigError("bandwidth cap must be between 0.1 and 1000 MBytes per second")
            rc = RelayConfig(mode=str(body.get("mode", cur.mode)), nickname=str(body.get("nickname", cur.nickname)),
                             contact=str(body.get("contact") or "").strip() or None,
                             bandwidth_rate=f"{mb:g} MBytes", or_port=int(body.get("or_port", cur.or_port)),
                             dir_port=0, practice=body.get("practice", cur.practice) is True)
            rc.validate()
            return {"torrc": generate_torrc(rc.spec(), data_dir="(the relay's own data folder)"), "error": None}
        except (ConfigError, TypeError, ValueError) as exc:
            return {"torrc": "", "error": str(exc)}

    def relay_state(self) -> dict:
        from .relayrun import monthly_estimate
        rc = self.profile.relay
        mb = self._mb_from_rate(rc.bandwidth_rate)
        if mb is None:                               # a rate saved by an older version, e.g. 5Mbit
            mb = 1.0
        spec = rc.spec()
        spec.dir_port = 0
        from .relay import generate_torrc
        torrc = self.relay.torrc if self.relay.running else generate_torrc(spec, data_dir="(the relay's own data folder)")
        return {
            "settings": {"mode": rc.mode, "nickname": rc.nickname, "contact": rc.contact or "",
                         "bandwidth_mb": mb, "or_port": rc.or_port, "practice": rc.practice,
                         "autostart": rc.autostart, "acknowledged": rc.acknowledged},
            "status": self.relay.snapshot(), "torrc": torrc,
            "tor_found": bool(find_tor_binary()), "estimate": monthly_estimate(mb),
            "checklist": list(self.RELAY_CHECKLIST), "platform": sys.platform,
        }

    def relay_start(self, body: dict) -> dict:
        """Save the relay settings and start the relay. A public relay needs every checklist item ticked."""
        from .relay import RelayConfigError
        cur = self.profile.relay
        try:
            mb = float(body.get("bandwidth_mb", self._mb_from_rate(cur.bandwidth_rate) or 1.0))
            or_port = int(body.get("or_port", cur.or_port))
        except (TypeError, ValueError):
            raise ConfigError("bandwidth and port must be numbers") from None
        if not (0.1 <= mb <= 1000):
            raise ConfigError("bandwidth cap must be between 0.1 and 1000 MBytes per second")
        practice = body.get("practice", cur.practice) is True
        ticked = {str(k) for k, v in (body.get("checklist") or {}).items() if v is True} \
            if isinstance(body.get("checklist"), dict) else set()
        if not practice and not set(self.RELAY_CHECKLIST) <= ticked:
            raise ConfigError("Tick every item on the checklist before starting a public relay, "
                              "or use practice mode.")
        raw = {"mode": str(body.get("mode", cur.mode)), "nickname": str(body.get("nickname", cur.nickname)),
               "contact": str(body.get("contact") or "").strip() or None,
               "bandwidth_rate": f"{mb:g} MBytes", "or_port": or_port, "dir_port": 0, "practice": practice,
               "acknowledged": cur.acknowledged or not practice}
        if "autostart" in body:
            raw["autostart"] = body["autostart"] is True
        self.apply_config({"contribute": {"relay": raw}})      # validates with relay.RelaySpec; saved on success
        try:
            self.relay.start(self.profile.relay.spec())
        except RelayConfigError as exc:
            raise ConfigError(str(exc)) from exc
        return self.relay_state()

    def relay_stop(self) -> dict:
        self.relay.stop()
        return self.relay_state()

    def relay_autostart(self) -> None:
        """Called once when the app opens. Starts the relay if 'start with the app' is on (the default). Out of the
        box that is practice mode: loopback only, nothing published. A public relay starts only after its
        checklist was completed once."""
        rc = self.profile.relay
        if rc.autostart and (rc.practice or rc.acknowledged):
            if not self.relay._find_binary():            # default-on: stay quiet until Tor has been installed once
                self.log.info("relay", "Relay not started: Tor is not installed yet (it installs the first time you start Tor).")
                return
            try:
                self.relay.start(rc.spec())
            except Exception as exc:
                self.log.warn("relay", f"The relay did not start with the app: {exc}")

    # ── realism helpers ─────────────────────────────────────────────────────
    def browser_info(self) -> dict:
        from .browser import browser_support
        cfg = self.profile.transports["clearnet"]
        ok, detail = browser_support()
        active = cfg.browser == "on" or (cfg.browser == "auto" and ok)
        return {"setting": cfg.browser, "available": ok, "detail": detail,
                "active": bool(active and ok), "visible": cfg.browser_visible}

    def _clearnet_transport(self, stop: threading.Event):
        info = self.browser_info()
        cfg = self.profile.transports["clearnet"]
        if not info["active"]:
            if cfg.browser == "on":
                self.log.warn("browser", f"Real-browser mode is on but unavailable: {info['detail']}. "
                                         "Using plain HTTP instead.")
            return None
        from .browser import BrowserTransport
        engine = self._browser_engine()
        import os as _os
        wayland = bool(_os.environ.get("WAYLAND_DISPLAY")) or _os.environ.get("XDG_SESSION_TYPE") == "wayland"
        has_display = sys.platform in ("win32", "darwin") or bool(_os.environ.get("DISPLAY"))
        offscreen = cfg.browser_window == "offscreen" and has_display and not wayland
        if cfg.browser_window == "offscreen" and not offscreen:     # Wayland won't let a window sit off-screen
            self.log.info("browser", "An off-screen window isn't possible on this system, so the noise browser "
                                     "runs hidden instead.")
        return BrowserTransport(proxy=cfg.proxy, headless=not (cfg.browser_visible or offscreen),
                                engine=engine, cookie_hours=cfg.cookie_hours, cookie_vary=cfg.cookie_vary,
                                offscreen=offscreen and not cfg.browser_visible, executable=info["detail"],
                                low_data=self.profile.extras.low_data,
                                stop_event=stop, scale=lambda: self.profile.realtime_scale,
                                on_event=lambda lvl, msg: self.log.add(lvl, "browser", msg))

    def _interest_share(self) -> float:
        ex = self.profile.extras
        return ex.persona_share if ex.persona else ex.interest_share

    def _interests(self):
        ex = self.profile.extras
        if ex.persona:                            # a persona takes priority over rotating interests
            import random as _r
            from .interests import Persona
            return Persona(_r.Random(), ex.persona)
        if not ex.interests:
            return None
        import random as _r
        from .interests import Interests
        return Interests(_r.Random(), ex.interest_list, ex.interest_active, ex.interest_rotate_days, ex.interest_salt)

    def _browser_engine(self) -> str:
        """auto = match your own browser: Firefox if your user agent is Firefox and Playwright's
        Firefox is installed; otherwise Chromium."""
        from .browser import find_playwright_firefox
        want = self.profile.transports["clearnet"].browser_engine
        if want == "auto":
            want = "firefox" if "Firefox/" in self.profile.identity.own_ua else "chromium"
        if want == "firefox" and not find_playwright_firefox():
            self.log.warn("browser", "Firefox engine wanted, but Playwright's Firefox isn't installed "
                                     "(run: python -m playwright install firefox). Using Chromium.")
            return "chromium"
        return want

    def _query_source(self, words):
        import random as _r
        q = self.profile.queries
        qs = QuerySource(_r.Random(), self.feeds, QueryConfig(q.live, q.dataset, q.builtin, q.words), words)
        qs.interests, qs.interest_share = self._interests(), self._interest_share()
        return qs

    def _start_feed_timer(self) -> None:
        """Only if the user opted in: re-fetch sources when they are ~3 months old."""
        with self._lock:
            if self._feed_timer_started or not self.app.get("auto_refresh_sources"):
                return
            self._feed_timer_started = True

        def loop():
            while self.app.get("auto_refresh_sources"):     # switching it off in Settings ends the timer
                self.feeds.refresh_async()
                time.sleep(1800)
            self._feed_timer_started = False
        threading.Thread(target=loop, daemon=True, name="feed-timer").start()

    def refresh_feeds(self) -> None:
        self.feeds.refresh_async(force=True)

    # ── run control ─────────────────────────────────────────────────────────
    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self, reason: str = "you pressed Start") -> None:
        with self._lock:
            old = self._thread
            if old is not None and old.is_alive() and self._stop.is_set():
                old.join(timeout=15)             # a run that is still shutting down: let it finish first
                if old.is_alive():
                    raise ConfigError("The previous run is still shutting down; try again in a moment.")
            if self.running:
                return
            self._stop = threading.Event()
            prof = self.profile
            active = next((e.wordlist for e in prof.engines.values() if e.enabled and e.wordlist), None)
            words = load_wordlist(active)
            tor_cfg = self._tor_cfg()
            gate = None
            if tor_cfg.enabled:
                tm = self.tor_manager()
                tm.start()

                def gate() -> bool:    # lane opens only once Tor is bootstrapped
                    if tm.ready:
                        lane = next((l for l in (self.runner.lanes if self.runner else []) if l.name == "tor"), None)
                        if lane is not None and (lane.transport.socks_port != tm.socks_port or
                                                 lane.transport.control != tm.control_addr):
                            lane.transport.set_endpoint(tm.socks_addr, tm.control_addr, tm.cookie_path)
                        return True
                    return False
            self._start_feed_timer()
            self._learn_own_ua()
            browser_tr = self._clearnet_transport(self._stop)
            plain_tr = None
            if browser_tr is not None and prof.traffic.plain > 0:      # both kinds of clearnet noise
                from .transports import ClearnetTransport
                plain_tr = ClearnetTransport(proxy=prof.transports["clearnet"].proxy)
            lanes = build_lanes(prof, words, tor_gate=gate, clearnet_transport=browser_tr,
                                plain_transport=plain_tr)
            if not lanes:
                raise ConfigError("Nothing to run: enable clearnet noise or Tor/onion noise in Settings.")
            import random as _r
            prev = self.runner
            if self.app.get("clear_logs_on_restart", True):      # Settings → General (on by default)
                self.log.clear()
                self.log_epoch = getattr(self, "log_epoch", 0) + 1
            self.runner = Runner(profile=prof, lanes=lanes, wordlist=words, log=self.log,
                                 stop_event=self._stop, sleep_fn=lambda s: self._stop.wait(s),
                                 queries=self._query_source(words), domains=self._domain_pool(_r),
                                 rate=RatePlanner(_r.Random(), prof.rate),
                                 dns_plan=self._fresh_dns_plan(),
                                 mix=True)
            if prev is not None:                  # request numbers keep counting across restarts
                self.runner._hit_seq = prev._hit_seq
                if not self.app.get("clear_logs_on_restart", True):
                    self.runner.hit_log.extend(prev.hit_log)
            self._thread = threading.Thread(target=self._run_loop, daemon=True, name="legalprivacy-runner")
            self._thread.start()
            self.accounts.start()                 # idle unless an account is signed in AND switched on
            self._note_start(reason)
            self._running_dict = profile_to_dict(prof)
            self._applied_at = time.time()
            self.log.info("app", f"Started ({reason}): lanes = " + ", ".join(
                f"{l.name}[{'/'.join(l.engines)}]" for l in lanes))

    # ── is what runs what you saved? ───────────────────────────────────────
    @staticmethod
    def _fingerprint(prof) -> str:
        flat = {k: v for k, v in Controller._flat(profile_to_dict(prof)).items()
                if not k.endswith(".own_ua")}          # learned from your browser at start, not a setting you chose
        return hashlib.sha256(json.dumps(flat, sort_keys=True, default=str).encode()).hexdigest()[:8]

    @staticmethod
    def _flat(d, pre="") -> dict:
        out = {}
        for k, v in (d or {}).items():
            key = f"{pre}{k}"
            if isinstance(v, dict):
                out.update(Controller._flat(v, key + "."))
            else:
                out[key] = v
        return out

    _PRIVATE = ("password", "bridge", "token", "seed", "sites", "weights", "account", "custom", "pin")

    def _settings_diff(self, old: dict | None, new: dict) -> list[str]:
        a, b = self._flat(old or {}), self._flat(new)
        out = []
        for k in sorted(set(a) | set(b)):
            if k.endswith(".own_ua"):
                continue
            if a.get(k) != b.get(k):
                if any(w in k.lower() for w in self._PRIVATE):
                    out.append(f"{k} changed")
                else:
                    out.append(f"{k}: {a.get(k)} → {b.get(k)}")
        return out

    def settings_status(self) -> dict:
        """Whether the running noise uses exactly the settings that are saved."""
        r = self.runner
        run_fp = self._fingerprint(r.profile) if r is not None and self.running else None
        saved_fp = self._fingerprint(self.profile)
        return {"running": bool(run_fp), "in_effect": run_fp == saved_fp if run_fp else None,
                "saved": saved_fp, "running_fp": run_fp, "applied_at": getattr(self, "_applied_at", None)}

    def _note_start(self, reason: str) -> None:
        """Keep the last minute of starts; say so in the log when noise keeps being (re)started."""
        now = time.time()
        recent = [(t, r) for t, r in getattr(self, "_starts", []) if now - t < 60] + [(now, reason)]
        self._starts = recent
        if len(recent) >= 5:
            why = ", ".join(sorted({r for _, r in recent}))
            self.log.warn("app", f"Noise was started {len(recent)} times in the last minute (reasons: {why}). "
                                 "If you did not expect this, note which reason it is.")

    def reapply(self) -> None:
        """Make the running noise pick up settings that were just saved: rebuild it in place.
        Tor stays connected, the log is kept, and a paused noise stays paused."""
        lock = self.__dict__.setdefault("_apply_lock", threading.Lock())
        with lock:
            if not self.running:
                return
            paused = bool(self.runner and self.runner.paused)
            before = getattr(self, "_running_dict", None)
            keep = self.app.get("clear_logs_on_restart", True)
            self.app["clear_logs_on_restart"] = False
            try:
                self.stop()
                self.start(reason="settings applied")
                if paused:
                    self.pause(True)
            finally:
                self.app["clear_logs_on_restart"] = keep
            changes = self._settings_diff(before, getattr(self, "_running_dict", {}))
            st = self.settings_status()
            if st["in_effect"]:
                shown = "; ".join(changes[:8]) + (f"; and {len(changes) - 8} more" if len(changes) > 8 else "")
                self.log.info("app", f"Applied live and verified (settings fingerprint {st['saved']}): "
                                     f"{shown or 'no setting had changed'}.")
            else:
                self.log.warn("app", "Applied, but the running settings do not match the saved ones "
                                     f"(running {st['running_fp']}, saved {st['saved']}). Press Stop, then Start.")

    # ── Panic: stop now, and (optionally) leave nothing behind ───────────────
    def panic(self, level: str = "soft") -> dict:
        """soft: stop the noise. medium: + clear the log and noise-browser cookies.
        hard: + stop Tor and delete everything legalPrivacy recorded (Proof data, cookies, logs).
        Your settings (profile) are never deleted."""
        import shutil
        from .paths import app_dir
        if level not in ("soft", "medium", "hard"):
            raise ConfigError("panic level must be soft, medium or hard")
        done = []
        if self.running:
            self.stop()
            done.append("noise stopped")
        else:
            done.append("noise was already stopped")
        if self.relay.running:
            self.relay.stop()
            done.append("relay stopped")
        if level in ("medium", "hard"):
            self.log.clear()
            done.append("log cleared")
            shutil.rmtree(app_dir() / "browser", ignore_errors=True)
            done.append("noise-browser cookies deleted")
            self.accounts.forget_all()
            done.append("signed-in account sessions deleted (you will need to sign in again)")
        if level == "hard":
            if self.tor and self.tor.state not in ("stopped",):
                self.tor.stop()
                done.append("Tor stopped")
            try:
                self.observer.stop()
            except Exception:
                pass
            try:
                gone = self.av.wipe()
                if gone:
                    done.append("antivirus results and quarantine deleted (signature files and your own files stay)")
            except Exception:
                pass
            for name in ("observe.json", "har.json"):
                try:
                    (app_dir() / name).unlink()
                except OSError:
                    pass
            try:
                wipe_old_log_files()
            except Exception:
                pass
            done.append("Proof data and log files deleted")
            if self.relay.wipe_data():            # only after the relay is stopped (above)
                done.append("relay data deleted (a new relay would get a new identity)")
            else:
                done.append("relay data kept because the relay would not stop")
        self.log.info("app", f"Panic ({level}): " + ", ".join(done) + ".")
        return {"level": level, "done": done}

    # ── optional signed-in accounts ─────────────────────────────────────────
    def accounts_action(self, action: str, provider: str) -> dict:
        from .accounts import AccountError
        try:
            if action == "signin":
                return self.accounts.begin_signin(provider)
            if action == "forget":
                self.accounts.forget(provider)
            elif action == "resume":
                self.accounts.resume(provider)
            else:
                raise ConfigError("unknown accounts action")
        except AccountError as exc:
            raise ConfigError(str(exc)) from exc
        return {"ok": True}

    # ── optional antivirus (ClamAV), offline-first: see av.py ────────────────
    def av_state(self, redetect: bool = False) -> dict:
        return self.av.state(redetect)

    def av_action(self, action: str, body: dict) -> dict:
        from .av import AvError
        av = self.av
        try:
            if action == "scan":
                av.start_scan(body.get("paths"))
            elif action == "stop":
                av.stop()
            elif action == "update":
                av.start_update(confirmed=body.get("confirmed") is True)
            elif action == "import":
                av.start_import(body.get("paths"))
            elif action == "selftest":
                av.start_selftest()
            elif action == "quarantine":
                av.quarantine(str(body.get("path", "")))
            elif action == "restore":
                av.restore(str(body.get("id", "")))
            elif action == "delete":
                av.delete_quarantined(str(body.get("id", "")))
            elif action == "detect":
                pass
            elif action == "probe":
                from .av import get_isolation
                get_isolation(force=True)
            else:
                raise ConfigError("unknown antivirus action")
        except AvError as exc:
            raise ConfigError(str(exc)) from exc
        return av.state(redetect=action in ("detect", "probe"))

    def leak_runner(self):
        from .leakcheck import LeakRunner
        if not hasattr(self, "_leak"):
            self._leak = LeakRunner(self)
        return self._leak

    def _run_loop(self) -> None:
        try:
            self.runner.run_forever()
        except Exception as exc:
            self.log.error("scheduler", f"Runner crashed: {exc!r}")
            try:
                self.runner.close()              # don't leave browsers behind after a crash
            except Exception:
                pass

    def stop(self, stop_tor: bool = False) -> None:
        self.accounts.stop()
        with self._lock:
            self._stop.set()
            t = self._thread
        if t:
            t.join(timeout=8)
            if t.is_alive():
                self.log.warn("app", "The noise is taking a while to wind down; it will stop on its own.")
        self.log.info("app", "Stopped.")
        if stop_tor and self.tor:
            self.tor.stop()
        if stop_tor:
            self.relay.stop()                     # quitting the app also stops the relay
        wipe_old_log_files()                      # the log itself lives in memory and ends with the app

    def pause(self, paused: bool) -> None:
        if self.runner:
            self.runner.paused = paused
            self.log.info("app", "Paused." if paused else "Resumed.")

    def test_once(self) -> None:
        """One immediate round (no pacing delay), for the 'Send one test hit' button."""
        def _go():
            if self.running and self.runner:
                self.runner.run_once(wait=False)
                return
            prof = self.profile
            words = load_wordlist(next((e.wordlist for e in prof.engines.values() if e.enabled and e.wordlist), None))
            lanes = [l for l in build_lanes(prof, words) if l.name == "clearnet"] or build_lanes(prof, words)
            import random as _r
            r = Runner(profile=prof, lanes=lanes, wordlist=words, log=self.log, sleep_fn=lambda s: None,
                       local_hour_fn=lambda: 12.0, queries=self._query_source(words),
                       domains=self._domain_pool(_r),
                       dns_plan=self._fresh_dns_plan())
            try:
                r.run_once(wait=False)
            except MaxFailuresExceeded as exc:
                self.log.error("scheduler", str(exc))
            finally:
                r.close()
        threading.Thread(target=_go, daemon=True, name="legalprivacy-once").start()

    # ── state / diagnostics ─────────────────────────────────────────────────
    def state(self) -> dict:
        r = self.runner
        stats = r.stats() if r else {"lanes": [], "paused": False, "uptime": 0}
        if not self.running:
            stats["paused"] = False
        return {
            "version": __version__, "first_run": self.first_run, "running": self.running,
            "paused": stats.get("paused", False), "uptime": stats.get("uptime", 0) if self.running else 0,
            "current": stats.get("current") if self.running else None,
            "log_epoch": getattr(self, "log_epoch", 0),
            "lanes": stats["lanes"], "app": self.app,
            "bytes_today": stats.get("bytes_today", 0) if self.running else 0,
            "data_cap_mb": self.profile.extras.daily_data_mb,
            "engine_names": ENGINE_NAMES, "engine_defaults": dict(zip(ENGINE_NAMES, SEARCH_WEIGHTS)),
            "profile": profile_to_dict(self.profile)["profile"],
            "tor": self.tor_state(), "log_last_id": self.log.last_id(),
            "builtin_onion_seeds": [{"name": n, "url": u} for n, u in BUILTIN_ONION_SEEDS],
            "config_path": self.profile_path,
            "presets": PRESETS, "browser": self.browser_info(), "feeds": self.feeds.status(),
            "feeds_refreshing": self.feeds.refreshing,
            "rate_info": [describe_rate(lv, self._search_share()) for lv in range(1, 11)],
            "hour_target": round(self.runner.hour_target) if self.runner and self.running else None,
            "opennic": [x.split("|") for x in self.feeds.items("opennic")],
            "dns": self.dns_report(),
            "settings": self.settings_status(),
            "accounts": self.accounts.status(),
        }

    def _search_share(self) -> float:
        e = self.profile.engines
        on = {n: c.budget_per_day for n, c in e.items() if c.enabled and (n != "onion" or self._tor_cfg().enabled)}
        return (on.get("search", 0) / sum(on.values())) if sum(on.values()) else 0.3

    def hits(self, after: int = 0) -> list[dict]:
        if not self.runner:
            return []
        return [h for h in self.runner.hit_log if h["seq"] > after]

    def browser_trace(self) -> dict:
        """Every address the noise browser's tabs showed recently, and what made each one change."""
        bt = next((l.transport for l in (self.runner.lanes if self.runner else [])
                   if getattr(l.transport, "is_browser", False)), None)
        if bt is None:
            return {"running": False, "blocked": 0, "items": []}
        items = list(getattr(bt, "nav_log", []))[-200:]
        return {"running": True, "blocked": getattr(bt, "blocked_navs", 0), "items": items[::-1]}

    def doctor(self) -> list[dict]:
        """Self-checks with plain-language results: status ∈ ok | warn | fail | info."""
        checks: list[dict] = []

        def add(name, status, detail):
            checks.append({"name": name, "status": status, "detail": detail})

        for lib in ("requests", "yaml", "socks"):
            try:
                __import__(lib)
                add(f"Python library: {lib}", "ok", "installed")
            except ImportError:
                add(f"Python library: {lib}", "fail", "missing — reinstall legalPrivacy")
        wl = next((e.wordlist for e in self.profile.engines.values() if e.enabled and e.wordlist), None)
        if wl:
            path = resolve_resource(wl)
            if Path(path).exists():
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    n = sum(1 for ln in fh if ln.strip())
                add("Word list", "ok", f"{path} ({n:,} words)")
            else:
                add("Word list", "warn", f"{wl} not found — built-in topics will be used")
        try:
            socket.create_connection(("1.1.1.1", 443), timeout=4).close()
            add("Internet (clearnet)", "ok", "reachable")
        except OSError as exc:
            add("Internet (clearnet)", "warn", f"cannot reach 1.1.1.1:443 ({exc})")
        cfg = self._tor_cfg()
        if not cfg.enabled:
            add("Tor", "info", "Tor is turned off (optional). Enable it in Settings or on the Tor tab.")
        else:
            binp = find_tor_binary()
            add("Tor program", "ok" if binp else "warn",
                binp or "not installed — it will be downloaded automatically on start")
            tm = self.tor_manager()
            add("Tor status", "ok" if tm.ready else "warn",
                f"{tm.state} ({tm.bootstrap_pct}%)" + (f" — {tm.error}" if tm.error else ""))
            seeds_ok, bad = clean_seed_list(cfg.onion_seeds or [u for _, u in BUILTIN_ONION_SEEDS])
            add("Onion seeds", "ok" if not bad else "fail",
                f"{len(seeds_ok)} valid v3 addresses" + (f"; {len(bad)} invalid" if bad else ""))
            if port_open("127.0.0.1", 9150) or port_open("127.0.0.1", 9050):
                add("Other Tor on this PC", "info",
                    "A system Tor/Tor Browser is running. legalPrivacy's own Tor uses different ports and won't touch it.")
        bi = self.browser_info()
        add("Real browser", "ok" if bi["active"] else ("warn" if bi["setting"] != "off" else "info"),
            (f"in use: {bi['detail']}" if bi["active"] else
             "turned off in Settings" if bi["setting"] == "off" else
             f"not available — {bi['detail']}. Plain HTTP is used, which looks far less human."))
        for f in self.feeds.status():
            st = "ok" if f["count"] and not f["stale"] else ("warn" if f["error"] or not f["count"] else "info")
            add(f"Source: {f['name']}", st, f"{f['count']:,} items" + (" (stale)" if f["stale"] and f["count"] else "")
                + (f" — {f['error']}" if f["error"] else ""))
        if self.profile.relay.enabled:
            add("Relay contribution", "info", f"{self.profile.relay.mode} relay '{self.profile.relay.nickname}' (never an exit)")
        try:
            import psutil  # noqa: F401
            add("Connection watching (Proof tab)", "ok", "available")
        except ImportError:
            add("Connection watching (Proof tab)", "warn",
                "the psutil package is missing, so the Proof tab's map and timeline stay empty. "
                "Close legalPrivacy and start it again with the start script (it now installs what's "
                "missing), or run: pip install psutil")
        from pathlib import Path as _P
        nm = _P(__file__).parent / "web" / "netmap.js"
        add("Network map", "ok" if nm.exists() else "warn",
            "ready" if nm.exists() else "the map's file (netmap.js) is missing from this install; reinstall legalPrivacy")
        add("Data folder", "ok", str(app_dir()))
        return checks
