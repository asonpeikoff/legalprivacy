"""Unreachable onions: coin flip between another onion and a new identity; activity names the site; failing
seeds are remembered in a small file and not retried over and over."""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from legalprivacy.onion import BUILTIN_ONION_SEEDS, OnionHealth, onion_label  # noqa: E402
from legalprivacy.transports import HitResult  # noqa: E402

TOR = dict(BUILTIN_ONION_SEEDS)["Tor Project"]


class Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


def test_label_names_the_site():
    assert onion_label(TOR + "some/page") == "Tor Project"
    mine = "http://" + "b" * 56 + ".onion/"
    assert onion_label(mine, [mine]) == "your own onion seed"
    assert "found by following a link" in onion_label("http://" + "c" * 56 + ".onion/")


def test_three_misses_rest_a_site_and_it_backs_off_and_one_success_clears_it():
    clk = Clock()
    h = OnionHealth(clock=clk)
    assert not h.record(TOR, False) and not h.record(TOR, False)
    assert not h.is_resting(TOR)
    assert h.record(TOR, False) and h.is_resting(TOR)            # third miss: rest 6 h
    clk.t += 6 * 3600 + 1
    assert not h.is_resting(TOR)                                 # probed again after the rest...
    h.record(TOR, False)                                         # ...fails again: 12 h now
    clk.t += 6 * 3600 + 1
    assert h.is_resting(TOR)
    for _ in range(20):
        h.record(TOR, False)
    assert h.status(TOR)["resting_until"] - clk.t <= 7 * 86400 + 1            # capped at a week
    h.record(TOR, True)
    assert not h.is_resting(TOR) and h.status(TOR)["fails"] == 0


def test_history_file_persists_is_private_and_only_holds_seed_sites():
    d = Path(tempfile.mkdtemp())
    known = {"2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"}
    h = OnionHealth(path=d / "onion_health.json", known=lambda host: host in known)
    stranger = "http://" + "d" * 56 + ".onion/"
    for _ in range(3):
        h.record(TOR, False)
        h.record(stranger, False)                                # a random-walk site: never recorded
    again = OnionHealth(path=d / "onion_health.json", known=lambda host: host in known)
    assert again.is_resting(TOR) and not again.is_resting(stranger)
    data = json.loads((d / "onion_health.json").read_text())
    assert list(data) == list(known) and set(data[next(iter(data))]) <= {"fails", "until", "last_ok", "last_fail"}
    assert (d / "onion_health.json").stat().st_mode & 0o077 == 0


def test_a_corrupt_history_file_is_ignored():
    d = Path(tempfile.mkdtemp())
    (d / "onion_health.json").write_text("{not json")
    assert OnionHealth(path=d / "onion_health.json").data == {}


def _runner(seed):
    import random
    from legalprivacy.config import Profile, apply_overrides
    from legalprivacy.rate import RatePlanner
    from legalprivacy.scheduler import Runner, build_lanes
    p = Profile(name="t")
    apply_overrides(p, {"rate": {"mode": "steady", "level": 5}})
    r = Runner(profile=p, lanes=build_lanes(p, ["w"]), wordlist=["w"], sleep_fn=lambda s: None,
               probe_fn=lambda *a: HitResult(200, "x"), rate=RatePlanner(random.Random(1), p.rate), mix=True)
    r.rng = random.Random(seed)
    return r


class FakeTransport:
    def __init__(self):
        self.reconnects = 0

    def reconnect(self):
        self.reconnects += 1
        return True


def test_unreachable_onion_randomly_switches_identity_or_tries_another_onion():
    from legalprivacy.transports import Target
    switched = moved_on = 0
    for seed in range(200):
        r = _runner(seed)
        lane = next(ln for ln in r.lanes if ln.name == "tor") if any(ln.name == "tor" for ln in r.lanes) else r.lanes[0]
        lane.transport = FakeTransport()
        res = HitResult(None, error="SOCKS error: Host unreachable")
        res.offline = True
        r._tor_patience(lane, "onion", Target(url=TOR), res)
        assert lane.__dict__.get("onion_retry") is None              # never "reload the same page"
        if lane.transport.reconnects:
            switched += 1
        else:
            moved_on += 1
    assert 60 < switched < 140 and 60 < moved_on < 140               # roughly a coin flip each way


def test_activity_details_name_the_onion_site():
    from legalprivacy.transports import Target
    r = _runner(1)
    lane = r.lanes[0]
    ident = type("I", (), {"id": "x"})()
    r._record_hit(lane, "onion", ident, Target(url=TOR), HitResult(200, "x"))
    assert r.hit_log[-1]["detail"] == "Tor Project"
    r._record_hit(lane, "search", ident, Target(url="https://example.com/"), HitResult(200, "x"))
    assert r.hit_log[-1]["detail"] is None
