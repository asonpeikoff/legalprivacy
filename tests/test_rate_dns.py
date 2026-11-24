"""Hourly rate planning and DNS resolver choice (offline)."""
import os
import random
import statistics
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

from legalprivacy.config import ConfigError, DnsConfig, Profile, apply_overrides  # noqa: E402
from legalprivacy.dnsplan import DnsPlan  # noqa: E402
from legalprivacy.rate import RateConfig, RatePlanner, describe, searches_per_hour  # noqa: E402
from legalprivacy.scheduler import Runner, build_lanes  # noqa: E402
from legalprivacy.transports import HitResult  # noqa: E402


def test_slider_is_monotonic_and_labelled_with_benchmarks():
    vals = [searches_per_hour(lv) for lv in range(1, 11)]
    assert vals == sorted(vals) and vals[0] < 1 and vals[-1] >= 20
    d = describe(5, 0.3)
    assert d["searches_per_hour"] == 4 and d["vs_average_person"] > 1


def test_random_mode_varies_hour_to_hour_and_has_quiet_hours():
    rp = RatePlanner(random.Random(1), RateConfig(mode="random", level=5))
    xs = [rp.actions_for_hour(h % 24, 0.3) for h in range(24 * 30)]
    assert statistics.pstdev(xs) > 0.3 * statistics.mean(xs)
    assert sum(x < 2 for x in xs) > 24 * 30 * 0.05            # some near-empty "away" hours
    night = [rp.actions_for_hour(4, 0.3) for _ in range(400)]
    evening = [rp.actions_for_hour(20, 0.3) for _ in range(400)]
    assert statistics.mean(evening) > statistics.mean(night)


def test_steady_mode_is_constant():
    rp = RatePlanner(random.Random(1), RateConfig(mode="steady", level=5))
    assert len({round(rp.actions_for_hour(h, 0.3), 6) for h in range(24)}) == 1


def test_plan_hour_sets_budgets_and_spreads_pacing():
    p = Profile(name="t")
    apply_overrides(p, {"rate": {"mode": "steady", "level": 6}})
    lanes = build_lanes(p, ["w"])
    r = Runner(profile=p, lanes=lanes, wordlist=["w"], sleep_fn=lambda s: None,
               probe_fn=lambda *a: HitResult(200, ""), rate=RatePlanner(random.Random(2), p.rate))
    total = r.plan_hour(14)
    budgeted = sum(b.per_day for l in r.lanes for b in l.budgets.values())
    assert abs(budgeted - total) <= len(lanes[0].budgets) + 1
    lo, hi = r._pace
    assert lo < 3600 / total < hi                                  # spread across the hour, not a burst


def test_dns_defaults_to_mix_with_only_opennic_on():
    cfg = Profile(name="t").dns
    assert cfg.mode == "mix" and cfg.opennic is False and cfg.quad9 is False and cfg.custom == []
    assert [r["ip"] for r in cfg.resolvers] == ["80.152.203.134", "193.31.24.55", "80.153.146.105", "9.9.9.9"]
    assert [r["role"] for r in cfg.resolvers] == ["primary"] * 3 + ["fallback"]


def test_recommended_resolvers_primaries_then_fallback():
    cfg = DnsConfig(mode="secure")
    assert [r["ip"] for r in cfg.resolvers if r["role"] == "primary"] == \
        ["80.152.203.134", "193.31.24.55", "80.153.146.105"]
    plan = DnsPlan(random.Random(3), cfg)
    assert {plan.pick()[0] for _ in range(100)} == {"80.152.203.134", "193.31.24.55", "80.153.146.105"}
    for ip in ("80.152.203.134", "193.31.24.55"):
        plan.health[ip] = {"ip": ip, "ok": True, "rtt_ms": 900, "egress": None}      # answering, but slow
    plan.health["80.153.146.105"] = {"ip": "80.153.146.105", "ok": False, "rtt_ms": None, "egress": None}
    plan.health["9.9.9.9"] = {"ip": "9.9.9.9", "ok": True, "rtt_ms": 20, "egress": None}
    assert {plan.pick()[0] for _ in range(50)} == {"9.9.9.9"}                 # fallback only now
    plan.health["9.9.9.9"]["ok"] = False
    assert {plan.pick()[0] for _ in range(50)} <= {"80.152.203.134", "193.31.24.55"}   # slow beats nothing


def test_interception_is_detected():
    plan = DnsPlan(random.Random(1), DnsConfig(mode="secure"))
    plan.system_egress = "192.0.2.7"
    for r in plan.cfg.resolvers:
        plan.health[r["ip"]] = {"ip": r["ip"], "ok": True, "rtt_ms": 1, "egress": "192.0.2.7"}
    assert plan.report()["intercepted"]
    plan.health["193.31.24.55"]["egress"] = "193.31.24.55"
    assert plan.verdict("193.31.24.55") == "ok"


def test_user_can_override_and_reset_resolvers():
    p = Profile(name="t")
    apply_overrides(p, {"dns": {"resolvers": [{"ip": "10.0.0.53", "name": "mine", "role": "primary"}]}})
    assert [r["ip"] for r in p.dns.resolvers] == ["10.0.0.53"]
    apply_overrides(p, {"dns": {"reset_resolvers": True}})
    assert len(p.dns.resolvers) == 4


def test_mix_mode_switches_in_blocks_with_the_right_share():
    t = [0.0]
    plan = DnsPlan(random.Random(4), DnsConfig(mode="mix", system_share=0.7),
                   [], clock=lambda: t[0])
    modes, runs, last = [], 0, None
    for _ in range(20000):                 # one minute steps over ~2 weeks
        m = plan.current_mode()
        runs += m != last
        last = m
        modes.append(m)
        t[0] += 60
    share = modes.count("system") / len(modes)
    assert 0.6 < share < 0.8
    assert runs < len(modes) / 8                            # blocks, not per-lookup flapping


def test_bad_dns_settings_rejected():
    for bad in ({"dns": {"mode": "weird"}}, {"dns": {"resolvers": [{"ip": "not-an-ip"}]}}, {"rate": {"level": 11}}):
        try:
            apply_overrides(Profile(name="t"), bad)
            raise AssertionError(f"accepted {bad}")
        except ConfigError:
            pass


def test_hourly_level_glides_instead_of_jumping():
    rp = RatePlanner(random.Random(3), RateConfig(mode="random", level=5))
    xs = [rp.actions_for_hour(h % 24, 0.3) for h in range(24 * 60)]
    same_day = [(a, b) for i, (a, b) in enumerate(zip(xs, xs[1:])) if (i + 1) % 24 != 0]
    assert max(abs(a - b) / max(a, b) for a, b in same_day) < 0.95  # no hour-to-hour cliffs
    assert any(x < 2 for x in xs)                                   # but away spells still happen


def test_partial_randomness_scales_between_steady_and_random():
    import statistics
    def spread(r):
        rp = RatePlanner(random.Random(5), RateConfig(mode="random", level=5, randomness=r))
        xs = [rp.actions_for_hour(h % 24, 0.3) for h in range(24 * 40)]
        return statistics.pstdev(xs) / statistics.mean(xs)
    assert spread(0.0) < 1e-9 < spread(0.3) < spread(1.0)


def test_top_level_stays_gentle_and_no_engine_exceeds_its_hourly_cap():
    from legalprivacy.engines import MAX_SEARCHES_PER_ENGINE_PER_HOUR, _ENGINE_HITS, pick_search_endpoint
    from legalprivacy.rate import searches_per_hour
    assert searches_per_hour(10) <= 20
    _ENGINE_HITS.clear()
    rng, t0 = random.Random(1), 1_000_000.0
    picks = [pick_search_endpoint(rng, now=t0 + i) for i in range(40)]
    assert max(picks.count(p) for p in set(picks)) <= MAX_SEARCHES_PER_ENGINE_PER_HOUR
    _ENGINE_HITS.clear()


def test_opennic_filter_keeps_only_passing_encrypted_no_or_anonymized_log_servers():
    from legalprivacy.feeds import parse_opennic_servers
    row = ("<p><span> {feats}</span><span class='host' title=\"(Paris, FR)\"><a id='{h}.dns.opennic.glue' href='x'>{h}</a></span>"
           "<span class='mono ipv4'>{ip}</span><span class='stat' title='{st}'>x</span></p>")
    f = lambda *t: "".join(f"<i style='color:#000;' title='{x}'>i</i>" for x in t)   # noqa: E731
    html = "<div name='ccg[FR]' style=''>" + "".join([
        row.format(feats=f("No logs kept", "DNS over TLS"), h="ns1.fr", ip="1.1.1.10", st="Passing"),
        row.format(feats=f("Logs are anonymized", "DNScrypt"), h="ns2.fr", ip="1.1.1.11", st="Passing"),
        row.format(feats=f("No logs kept"), h="ns3.fr", ip="1.1.1.12", st="Passing"),              # no encryption
        row.format(feats=f("No logs kept", "DNS over HTTP"), h="ns4.fr", ip="1.1.1.13", st="Extended failure"),
        row.format(feats=f("DNS over HTTP"), h="ns5.fr", ip="1.1.1.14", st="Passing"),             # logs unknown
    ]) + "</div>"
    got = parse_opennic_servers(html)
    assert got == ["1.1.1.10|ns1.fr|Paris, FR|none|DoT", "1.1.1.11|ns2.fr|Paris, FR|anonymized|DNSCrypt"]


def test_no_log_opennic_servers_are_preferred():
    cfg = DnsConfig(mode="secure", opennic=True)
    plan = DnsPlan(random.Random(2), cfg, ["1.0.0.1|a|X|none|DoT", "1.0.0.2|b|X|anonymized|DoH"])
    picks = [plan.pick()[0] for _ in range(2000)]
    assert 2.4 < picks.count("1.0.0.1") / picks.count("1.0.0.2") < 3.8


def test_side_streams_run_alongside_instead_of_taking_a_share():
    def planned(side):
        p = Profile(name="t")
        apply_overrides(p, {"rate": {"mode": "steady", "level": 6}, "extras": {"persona": "Developer"}})
        r = Runner(profile=p, lanes=build_lanes(p, ["w"]), wordlist=["w"], sleep_fn=lambda s: None,
                   probe_fn=lambda *a: HitResult(200, ""), rate=RatePlanner(random.Random(2), p.rate),
                   side_streams=side)
        r.plan_hour(14)
        out = {}
        for ln in r.lanes:
            for e, b in ln.budgets.items():
                out[e] = out.get(e, 0) + b.per_day
        return out, r
    together, _ = planned(())
    alongside, r = planned(("dns", "packages"))
    assert alongside["search"] >= together["search"]            # searching no longer shares its hour with them
    assert alongside["dns"] > 0
    # the main stream never picks a side-stream kind
    seen = set()
    for _ in range(60):
        r.run_once(wait=False)
        seen |= {h["engine"] for h in r.hit_log}
    assert seen and not seen & {"dns", "packages"}


def test_side_stream_records_its_own_hits_at_the_same_time():
    import threading
    p = Profile(name="t")
    apply_overrides(p, {"rate": {"mode": "steady", "level": 6}})
    stop = threading.Event()
    r = Runner(profile=p, lanes=build_lanes(p, ["w"]), wordlist=["w"], sleep_fn=lambda s: stop.wait(0.001),
               probe_fn=lambda *a: HitResult(200, ""), rate=RatePlanner(random.Random(2), p.rate),
               side_streams=("dns",), stop_event=stop)
    r.plan_hour(14)
    r.hour = 14
    th = threading.Thread(target=r._side_loop, args=("dns",), daemon=True)
    th.start()
    import time as _t
    deadline = _t.time() + 5
    while _t.time() < deadline and not [h for h in r.hit_log if h["engine"] == "dns"]:
        _t.sleep(0.02)
    stop.set()
    th.join(2)
    assert [h for h in r.hit_log if h["engine"] == "dns"]


def _app_runner(p, clock):
    return Runner(profile=p, lanes=build_lanes(p, ["w"]), wordlist=["w"], sleep_fn=lambda s: None, clock=clock,
                  probe_fn=lambda *a: HitResult(200, ""), rate=RatePlanner(random.Random(2), p.rate))


def test_long_session_keeps_returning_to_the_same_page():
    p = Profile(name="t")
    apply_overrides(p, {"rate": {"mode": "steady", "level": 10}})
    now = [1000.0]
    r = _app_runner(p, lambda: now[0])
    r.plan_hour(14)
    lane = next(ln for ln in r.lanes if "crawl" in ln.engines)
    for b in lane.budgets.values():
        b.per_day = 1000
    lane.linger = {"mode": "work", "url": "https://example.org/notes", "engine": "crawl",
                   "until": now[0] + 3600, "next_at": now[0]}
    r.run_once(wait=False)
    assert r.hit_log[-1]["url"] == "https://example.org/notes" and r.hit_log[-1]["role"] == "linger"
    now[0] += 4000                                           # the session is over
    r.profile.extras.long_sessions = False                   # (so the next visit cannot start a new one at random)
    r.run_once(wait=False)
    assert lane.linger is None


def test_stepping_away_keeps_the_route_quiet_then_resumes_the_same_page():
    p = Profile(name="t")
    apply_overrides(p, {"rate": {"mode": "steady", "level": 10}})
    now = [1000.0]
    r = _app_runner(p, lambda: now[0])
    r.plan_hour(14)
    for ln in r.lanes:
        for b in ln.budgets.values():
            b.per_day = 1000
        ln.linger = {"mode": "away", "url": "https://example.org/doc", "engine": "crawl",
                     "until": now[0] + 7200, "next_at": 0.0}
    assert r.run_once(wait=False) is False                     # away: nothing on these routes
    now[0] += 7300
    assert r.run_once(wait=False) is True
    assert r.hit_log[-1]["url"] == "https://example.org/doc" and "back after being away" in r.hit_log[-1]["note"]
    assert r.lanes[0].linger["mode"] == "work"                 # and carries on with it for a while


def test_stepped_away_still_has_the_odd_detour():
    p = Profile(name="t")
    apply_overrides(p, {"rate": {"mode": "steady", "level": 10}})
    now = [1000.0]
    r = _app_runner(p, lambda: now[0])
    r.plan_hour(14)
    for ln in r.lanes:
        for b in ln.budgets.values():
            b.per_day = 1000
        ln.linger = {"mode": "away", "url": "https://example.org/doc", "engine": "crawl",
                     "until": now[0] + 7200, "next_at": 0.0, "other_at": now[0] + 900}
    assert r.run_once(wait=False) is False                     # quiet at first
    now[0] += 1000
    assert r.run_once(wait=False) is True                      # then a detour while still away
    assert r.hit_log[-1]["role"] != "linger"
    assert any(ln.linger and ln.linger["mode"] == "away" and ln.linger["other_at"] > now[0] for ln in r.lanes)


def test_long_sessions_start_now_and_then_and_can_be_turned_off():
    from legalprivacy.transports import Target
    p = Profile(name="t")
    assert p.extras.long_sessions is True
    r = _app_runner(p, lambda: 0.0)
    lane = r.lanes[0]
    started = 0
    for _ in range(2000):
        lane.linger = None
        r._maybe_linger(lane, "crawl", Target(url="https://example.org/"))
        started += lane.linger is not None
    assert 120 < started < 330                                 # about 11% of page visits, few of them "away"
    r.profile.extras.long_sessions = False
    lane.linger = None
    for _ in range(500):
        r._maybe_linger(lane, "crawl", Target(url="https://example.org/"))
    assert lane.linger is None


def test_search_engine_that_cuts_the_connection_is_rested_for_a_while():
    from legalprivacy import engines as E
    from legalprivacy.transports import Target
    p = Profile(name="t")
    r = Runner(profile=p, lanes=build_lanes(p, ["w"]), wordlist=["w"], sleep_fn=lambda s: None,
               probe_fn=lambda *a: HitResult(None, error="net::ERR_HTTP2_PROTOCOL_ERROR at https://www.bing.com/search?q=x"))
    bing = next(e for e in E.SEARCH_ENDPOINTS if "bing.com" in e)
    E._ENGINE_COOLDOWN.pop(bing, None)
    r._make_target = lambda lane, eng, ident: Target(url="https://www.bing.com/search?q=x", role="search")
    lane = next(ln for ln in r.lanes if "search" in ln.engines)
    r.rng.seed(1)
    # run until the search lane is chosen
    for _ in range(50):
        r.run_once(wait=False)
        if E._ENGINE_COOLDOWN.get(bing, 0) > 0:
            break
    assert E._ENGINE_COOLDOWN.get(bing, 0) > 0
    E._ENGINE_COOLDOWN.pop(bing, None)
    assert lane


def test_a_visit_to_a_persona_site_starts_with_a_search_that_leads_there():
    from legalprivacy.interests import query_for_site
    from legalprivacy.transports import Target
    p = Profile(name="t")
    apply_overrides(p, {"rate": {"mode": "steady", "level": 10}})
    serp = '<html><body><a href="https://www.geeksforgeeks.org/pandas-groupby/">GfG</a><a href="https://other.example/x">o</a></body></html>'
    r = Runner(profile=p, lanes=build_lanes(p, ["w"]), wordlist=["w"], sleep_fn=lambda s: None,
               probe_fn=lambda lane, ident, t: HitResult(200, serp), rate=RatePlanner(random.Random(2), p.rate))
    r.rng.seed(4)
    lane = next(ln for ln in r.lanes if "search" in ln.engines and "crawl" in ln.engines)
    for b in lane.budgets.values():
        b.per_day, b.spent = 1000, 0
    visit = Target(url="https://www.geeksforgeeks.org/", note="popular site")
    led = None
    for _ in range(40):
        led = r._search_led(lane, visit)
        if led:
            break
    assert led and led.role == "search" and "geeksforgeeks" in led.note       # a topical search, not the site's name
    assert "geeksforgeeks" not in led.url.lower()
    assert lane.pending_visit is visit
    # when the search comes back, the click goes to that site and happens next
    r._settle(lane, "search", led, HitResult(200, serp))
    assert lane.follow_next is not None and "geeksforgeeks" in lane.follow_next.url and lane.follow_next.role == "result"
    forced = r._follow_due([])
    assert forced and forced[1] == "search" and forced[2].referer == led.url and lane.follow_next is None
    assert query_for_site(random.Random(1), "en.wikipedia.org/wiki/Aristotle") in (
        "Aristotle wikipedia", "Aristotle", "what is Aristotle", "Aristotle history")
    assert query_for_site(random.Random(1), "no-such-site.example") is None


def test_during_a_long_session_visits_to_other_sites_of_that_kind_are_rare():
    import math
    p = Profile(name="t")
    apply_overrides(p, {"rate": {"mode": "steady", "level": 10}})
    now = [1000.0]
    r = _app_runner(p, lambda: now[0])
    r.plan_hour(14)
    lane = next(ln for ln in r.lanes if "crawl" in ln.engines)
    lane.linger = {"mode": "work", "url": "https://example.org/a", "engine": "crawl", "until": now[0] + 7200,
                   "next_at": now[0] + 600, "other_at": now[0] + 1800}
    assert r._staying_on_page(lane, "crawl") and not r._staying_on_page(lane, "search")
    now[0] += 1801
    assert not r._staying_on_page(lane, "crawl")                          # the detour is allowed
    gaps = [r._other_site_gap() for _ in range(4000)]
    mean_min = sum(gaps) / len(gaps) / 60
    assert 50 < mean_min < 75                                              # about an hour
    share = sum(1 for g in gaps if g < 600) / len(gaps)
    assert abs(share - 0.15) < 0.03 and abs(-600 / math.log(1 - 0.15) / 60 - 61.6) < 0.5


def test_ason_long_sessions_sometimes_are_a_duck_ai_chat():
    from legalprivacy.transports import Target
    p = Profile(name="t")
    assert p.extras.persona == "Ason"
    r = _app_runner(p, lambda: 0.0)
    lane = r.lanes[0]
    modes = set()
    for _ in range(4000):
        lane.linger = None
        r._maybe_linger(lane, "crawl", Target(url="https://example.org/"))
        if lane.linger and lane.linger["url"] == "https://duck.ai/":
            modes.add(lane.linger["mode"])
    assert modes == {"work", "away"}
    r.profile.extras.persona = "Student"
    for _ in range(1500):
        lane.linger = None
        r._maybe_linger(lane, "crawl", Target(url="https://example.org/"))
        assert not lane.linger or lane.linger["url"] != "https://duck.ai/"


def test_default_persona_skips_celebrity_sites_in_the_popular_draw():
    import random
    from legalprivacy.domains import DomainPool, is_entertainment_news
    assert is_entertainment_news("www.people.com") and not is_entertainment_news("wikipedia.org")
    pool = DomainPool(random.Random(1))
    pool.avoid_entertainment = True
    assert not any(is_entertainment_news(d) for d in pool._ranked())


def test_a_dns_lookup_is_often_followed_by_the_burst_a_page_load_makes():
    import random as _r
    from legalprivacy.domains import DomainPool
    from legalprivacy.engines import PAGE_ASSET_HOSTS, DnsNoise, burst_hosts
    from legalprivacy.transports import Target
    pool = DomainPool(_r.Random(2), None)
    seen = []
    for seed in range(200):                                   # the burst: 2-14 names, real, no repeats, never the site
        b = burst_hosts(_r.Random(seed), pool, "example.com")
        assert 2 <= len(b) <= 14 and len(set(b)) == len(b) and "example.com" not in b
        seen.append(len(b))
    assert 2 <= sorted(seen)[100] <= 6                        # usually a handful
    assert {h for h, _ in PAGE_ASSET_HOSTS} & {h for s in range(50) for h in burst_hosts(_r.Random(s), None)}

    looked = []
    orig = DnsNoise.resolve_system
    DnsNoise.resolve_system = staticmethod(lambda domain, timeout=4.0: looked.append(domain) or True)
    try:
        p = Profile(name="t")
        r = _app_runner(p, lambda: 0.0)
        r.sleep_fn = lambda s: None
        sizes = []
        for _ in range(60):
            looked.clear()
            res = r._dns_probe(Target(url="dns://system/example.com", kind="dns"))
            assert res.status == 200 and looked[0] == "example.com"
            sizes.append(len(looked))
        assert 0.6 < sum(1 for n in sizes if n > 1) / 60 < 1.0 and max(sizes) > 3      # most, not all, lookups get a burst
        r.profile.extras.dns_bursts = False
        looked.clear()
        r._dns_probe(Target(url="dns://system/example.com", kind="dns"))
        assert looked == ["example.com"]                       # off: one lookup, as before
    finally:
        DnsNoise.resolve_system = orig
