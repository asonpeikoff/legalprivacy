"""Tor noise never stalls: a dead .onion never slows the Tor route; visits vary; sessions search or read on."""
import random
from types import SimpleNamespace

from legalprivacy.onion import OnionTargetFactory
from legalprivacy.scheduler import Runner
from legalprivacy.transports import HitResult, Target


def test_onion_visits_mix_quick_looks_and_long_reads():
    f = OnionTargetFactory(rng=random.Random(4))
    d = [f.make().dwell for _ in range(400)]
    assert min(d) < 30 and max(d) > 150 and sum(x < 30 for x in d) > 150 and sum(x > 150 for x in d) > 20


def test_a_failed_onion_visit_never_slows_the_tor_route():
    r = HitResult(None, error="site offline")
    assert r.dim_transport                         # it would have, before: then Tor showed "slowed down" and sat idle
    src = open(__import__("legalprivacy.scheduler", fromlist=["x"]).__file__).read()
    assert 'eng_name != "onion" and lane.name != "tor"' in src and 'lane.name != "tor":' in src


def _runner():
    r = Runner.__new__(Runner)
    r.rng = random.Random(1)
    r.queries = None
    r.profile = SimpleNamespace(realtime_scale=1.0)
    return r


def test_an_onion_session_on_a_search_site_types_searches_and_elsewhere_reads_on():
    r = _runner()
    ddg = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"
    t = r._onion_session_target({"url": ddg}, 1.0)
    assert "/html/?q=" in t.url and t.note.startswith("searching:") and t.role == "linger"
    other = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"
    lg = {"url": other, "next_page": other + "about/"}
    t = r._onion_session_target(lg, 1.0)
    assert t.url == other + "about/" and t.note == "reading on the same site" and isinstance(t, Target)


def test_onion_sessions_last_twenty_to_thirty_minutes():
    r = _runner()
    r.rate = object()
    r.clock = lambda: 1000.0
    r._emit = lambda *a: None
    r.profile = SimpleNamespace(realtime_scale=1.0, extras=SimpleNamespace(long_sessions=True, persona=""))
    lane = SimpleNamespace(linger=None, name="tor")
    for seed in range(200):
        r.rng = random.Random(seed)
        lane.linger = None
        r._maybe_linger(lane, "onion", Target(url="http://x.onion/"))
        if lane.linger:
            assert 20 * 60 <= lane.linger["until"] - 1000.0 <= 30 * 60 and lane.linger["mode"] == "work"
            return
    raise AssertionError("no onion session started in 200 tries")
