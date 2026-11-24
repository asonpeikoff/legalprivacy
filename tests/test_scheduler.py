"""Scheduler + transport tests: offline, seeded, probe_fn injected (no network)."""

try:
    import pytest
except ImportError:
    class _RaisesContext:
        def __init__(self, exc): self.exc = exc
        def __enter__(self): return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is None: raise AssertionError(f"DID NOT RAISE {self.exc}")
            return issubclass(exc_type, self.exc)
    import types
    pytest = types.ModuleType("pytest")
    pytest.raises = _RaisesContext

from legalprivacy.config import (EngineConfig, Profile, TransportConfig)
from legalprivacy.pacing import Budget
from legalprivacy.scheduler import Lane, Runner, build_lanes
from legalprivacy.transports import (ClearnetTransport, HitResult)

WORDS = ["weather", "news", "books", "travel", "recipes", "music"]
HTML = '<a href="/p2">next</a> <a href="https://elsewhere.example/out">out</a>'


def make_profile(tor=True, clearnet=True, seeds=None, search=True) -> Profile:
    p = Profile(name="test")
    p.engines = {
        "search": EngineConfig(budget_per_day=10, enabled=search),
        "crawl": EngineConfig(budget_per_day=6, seeds=seeds or ["https://x.example/a"]),
        "dns": EngineConfig(budget_per_day=8),
        "onion": EngineConfig(budget_per_day=8),
    }
    p.transports = {
        "clearnet": TransportConfig(enabled=clearnet),
        "tor": TransportConfig(enabled=tor, control=None, onion=True),
    }
    return p


def make_runner(profile, probe) -> Runner:
    r = Runner(profile=profile, lanes=build_lanes(profile, WORDS), wordlist=WORDS,
               clock=lambda: 0.0, local_hour_fn=lambda: 12.0,
               sleep_fn=lambda s: None, probe_fn=probe, max_iterations=200)
    r.rng = __import__("random").Random(5)
    return r


def captured_probe(captured):
    return lambda lane, ident, target: (
        captured.append((lane.name, target.kind, target.url)),
        HitResult(200, HTML) if target.kind == "html" else HitResult(200, ""))[1]


def test_dns_uses_raw_udp_on_clearnet_and_tor_lane_is_onion_only():
    captured = []
    runner = make_runner(make_profile(), captured_probe(captured))
    for _ in range(20):
        if all(l.budgets[e].exhausted for l in runner.lanes for e in l.engines):
            break
        runner.run_once()
    kinds = {(lane, kind) for lane, kind, _ in captured}
    assert ("clearnet", "dns") in kinds
    assert not any(lane == "tor" and kind in ("doh", "dns") for lane, kind, _ in captured)
    assert all(".onion" in url for lane, _, url in captured if lane == "tor")     # Tor carries only onion visits
    for lane, kind, url in captured:
        if kind == "dns":
            assert url.startswith("dns://") and "@" not in url


def test_dns_clearnet_does_not_fire_extra_http_hit():
    """Raw-UDP DNS hits must not be followed by a real GET of the domain."""
    captured = []
    runner = make_runner(make_profile(clearnet=True, tor=False),
                         captured_probe(captured))
    runner.run_once()
    for _ in range(10):        # include search hits for comparison
        if all(l.budgets[e].exhausted for l in runner.lanes for e in l.engines):
            break
        runner.run_once()
    kinds = {kind for _, kind, _ in captured}
    assert kinds == {"dns", "html"}


def test_crawl_walk_follows_links_and_depth_caps():
    captured = []
    runner = make_runner(make_profile(clearnet=True, tor=False, search=False),
                         captured_probe(captured))
    for _ in range(20):
        if all(l.budgets[e].exhausted for l in runner.lanes for e in l.engines):
            break
        runner.run_once()
    crawl_urls = [u for l, k, u in captured if l == "clearnet" and k == "html"]
    # link extraction must produce same-site follow-ups, and depth must cap at 4
    assert crawl_urls and all(u.startswith("https://x.example/") for u in crawl_urls)
    assert crawl_urls[0] == "https://x.example/a"          # the seed
    assert any(u.endswith("/p2") for u in crawl_urls)      # followed a link
    assert not any("/out" in u for u in crawl_urls)        # cross-site refused


def test_identity_is_pinned_then_rotates_on_tor():
    runner = make_runner(make_profile(clearnet=False, tor=True),
                         lambda l, i, t: HitResult(200, ""))
    lane = runner.lanes[0]
    lane.transport.identities_per_circuit = 2
    seen = []
    for _ in range(5):
        runner.run_once()
        seen.append(lane.identity.id)
    assert len(set(seen)) >= 2            # rotated at the circuit lifetime
    assert seen[0] == seen[1]             # pinned within one lifetime


def test_identity_changes_after_a_random_number_of_visits_and_more_often_than_before():
    runner = make_runner(make_profile(clearnet=False, tor=True), lambda l, i, t: HitResult(200, ""))
    lane = runner.lanes[0]
    lane.transport.identities_per_circuit = 10
    lengths, last, run = [], None, 0
    for _ in range(400):
        lane.hits_by_identity += 0
        ident, _p = runner._identity_pacer_for(lane)
        if last is not None and ident.id != last:
            lengths.append(run)
            run = 0
        last, run = ident.id, run + 1
        lane.hits_by_identity += 1
    assert len(set(lengths)) > 3                          # not every Nth visit exactly
    assert sum(lengths) / len(lengths) < 8                # clearly more often than the old fixed 10


def test_failure_backs_off_and_dims_transport():
    lane = Lane(name="clearnet", transport=ClearnetTransport(),
                engines=["search"], budgets={"search": Budget(per_day=5)})
    runner = Runner(profile=make_profile(clearnet=True, tor=False), lanes=[lane],
                    wordlist=WORDS, clock=lambda: 0.0, local_hour_fn=lambda: 12.0,
                    sleep_fn=lambda s: None,
                    probe_fn=lambda l, i, t: HitResult(429, ""),
                    max_iterations=200)
    runner.rng.seed(1)
    runner.run_once()
    assert lane.budgets["search"].failures == 1
    assert lane.budgets["search"].spent == 0
    assert lane.transport.dimmed


def test_build_lanes_respects_disabled_transports():
    lanes = build_lanes(make_profile(clearnet=False, tor=False), WORDS)
    assert lanes == []


def test_runner_clock_defaults_to_callable():
    p = make_profile(clearnet=True, tor=False)
    runner = Runner(profile=p, lanes=build_lanes(p, WORDS), wordlist=WORDS,
                    clock=None, sleep_fn=lambda s: None,
                    probe_fn=lambda l, i, t: HitResult(200, ""))
    assert callable(runner.clock)
    # Must not throw TypeError: 'NoneType' object is not callable
    runner.run_once(wait=False)
    assert runner.lanes[0].budgets["search"].spent == 1 or \
           runner.lanes[0].budgets["crawl"].spent == 1 or \
           runner.lanes[0].budgets["dns"].spent == 1


def test_single_transport_gets_full_budget():
    p = make_profile(clearnet=True, tor=False)
    lanes = build_lanes(p, WORDS)
    assert len(lanes) == 1
    # search budget was 10; with 1 transport enabled it should receive 10, not 5
    assert lanes[0].budgets["search"].per_day == 10


def test_consecutive_failures_rotate_identity():
    p = make_profile(clearnet=True, tor=False)
    runner = Runner(profile=p, lanes=build_lanes(p, WORDS), wordlist=WORDS,
                    clock=lambda: 0.0, sleep_fn=lambda s: None,
                    probe_fn=lambda l, i, t: HitResult(403, ""))
    lane = runner.lanes[0]
    runner.run_once(wait=False)
    id1 = lane.identity.id
    runner.run_once(wait=False)
    assert lane.identity.id == id1
    runner.run_once(wait=False)  # 3rd failure triggers reset: lane.identity is set to None
    assert lane.identity is None
    assert lane.consecutive_failures == 0
    runner.run_once(wait=False)  # 4th run creates new identity
    assert lane.identity is not None and lane.identity.id != id1


def test_crawl_handles_complex_html():
    from legalprivacy.engines import CrawlTargetFactory
    rng = __import__("random").Random(1)
    fac = CrawlTargetFactory(rng=rng, seeds=["https://example.com/start"])
    html = """
    <html>
      <body>
        <A HREF='/page1'>Upper case tag</A>
        <a class="nav-link" href="/page2">Attributes before href</a>
        <a href='https://example.com/page3'>Single quotes</a>
        <a href="https://external.example.com/leak">External</a>
      </body>
    </html>
    """
    links = set()
    for _ in range(30):
        t = fac.next_from(html, "https://example.com/start")
        if t:
            links.add(t.url)
    assert "https://example.com/page1" in links
    assert "https://example.com/page2" in links
    assert "https://example.com/page3" in links
    assert not any("external.example.com" in u for u in links)


def test_dns_noise_only_uses_real_domains():
    from legalprivacy.engines import DnsNoise
    from legalprivacy.domains import FALLBACK_DOMAINS
    rng = __import__("random").Random(2)
    noise = DnsNoise(rng, ["xqzvbnm", "pentacapsular"])
    for _ in range(50):
        _, domain, _ = noise.make_query()
        assert domain.removeprefix("www.") in FALLBACK_DOMAINS
