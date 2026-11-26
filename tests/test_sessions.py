"""Sessions and identities: nothing goes on longer than two hours, long sessions run alongside the others, and the Tor lane
also carries some file downloads."""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(__file__))
from test_extras import _runner  # noqa: E402

from legalprivacy.files import Pick  # noqa: E402
from legalprivacy.transports import Target  # noqa: E402

TWO_HOURS = 7200.0


def test_an_identity_never_lives_longer_than_two_hours_and_a_session_ends_with_it():
    r = _runner({})
    lane = r.lanes[0]
    now = [10_000.0]
    r.clock = lambda: now[0]
    first, _p = r._identity_pacer_for(lane)
    assert 35 * 60 <= lane.ident_expires - now[0] <= TWO_HOURS
    lane.linger = {"mode": "work", "url": "https://example.org/", "engine": "crawl", "until": now[0] + 99999}
    same, _p = r._identity_pacer_for(lane)
    assert same is first and lane.linger                      # still young: nothing changes
    now[0] = lane.ident_expires + 1
    new, _p = r._identity_pacer_for(lane)
    assert new is not first and lane.linger is None            # too old: a new identity, and the session is over


def test_long_sessions_are_never_over_two_hours_and_never_take_over():
    for seed in range(400):
        r = _runner({"long_sessions": True})
        r.rng = random.Random(seed)
        r.rate = object()
        lane = r.lanes[0]
        now = 1000.0
        r.clock = lambda: now
        for _ in range(300):
            r._maybe_linger(lane, "crawl", Target(url="https://example.org/a"))
            if lane.linger:
                break
        lg = lane.linger
        if lg:
            assert lg["exclusive"] is False
            assert (lg["until"] - now) <= TWO_HOURS + 1


def test_coming_back_after_being_away_still_ends_within_two_hours_of_the_start():
    r = _runner({"long_sessions": True})
    lane = r.lanes[0]
    t0 = 50_000.0
    now = [t0 + 6900]                                          # back after almost two hours away
    r.clock = lambda: now[0]
    lane.linger = {"mode": "away", "url": "https://example.org/a", "engine": "crawl", "exclusive": False, "chat": False,
                   "started": t0, "until": t0 + 6800, "next_at": 0.0, "other_at": 0.0}
    got = r._linger_due([])
    assert got is not None and lane.linger["mode"] == "work"
    assert lane.linger["until"] <= t0 + TWO_HOURS + 1


def test_a_finished_session_leads_to_a_new_identity():
    r = _runner({"long_sessions": True})
    lane = r.lanes[0]
    now = [1000.0]
    r.clock = lambda: now[0]
    r._identity_pacer_for(lane)
    lane.linger = {"mode": "work", "url": "https://example.org/a", "engine": "crawl", "exclusive": False, "chat": False,
                   "started": 900.0, "until": 1500.0, "next_at": 2000.0, "other_at": 0.0}
    now[0] = 1600.0
    r._linger_due([])
    assert lane.linger is None and lane.identity is None


class _Cat:
    def __init__(self, pick):
        self._p, self.cap = pick, None

    def pick(self, cap=0, kind=None):
        self.cap = cap
        return self._p


def test_the_tor_lane_downloads_files_too_but_never_uploads_and_keeps_them_smaller():
    r = _runner({})
    cat = _Cat(Pick("https://archive.org/download/x/a.jpg", "image", 400_000, "a.jpg"))
    r.__dict__["_catalog"] = cat
    for _ in range(50):
        t = r._files_target(over_tor=True)
        assert t.kind == "download" and "over Tor" in t.note
    assert cat.cap <= 12_000_000
    r.__dict__["_catalog"] = _Cat(None)                        # nothing found: look at the site instead, no upload
    t = r._files_target(over_tor=True)
    assert t.kind == "html" and "archive.org" in t.url
