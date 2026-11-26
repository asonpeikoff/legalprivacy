"""The noise must keep going: failures never pause it, a stuck or stopped run is woken, and a pause you asked for is left alone."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from test_extras import _runner  # noqa: E402

from legalprivacy.keepalive import KeepAlive  # noqa: E402
from legalprivacy.transports import HitResult  # noqa: E402


def test_failures_never_pause_or_stop_the_run():
    r = _runner({}, probe=lambda *a: HitResult(None, error="connection refused"))
    r.plan_hour(12)
    for _ in range(80):                       # far more than the old limit of 30 failures a day
        r.run_once(wait=False)                # must never raise
    assert r.day_failures + r.day_onion_failures >= 30 and not r.paused


def test_a_long_run_of_failed_onions_asks_tor_for_help_but_not_more_than_every_ten_minutes():
    r = _runner({})
    calls = []
    r.on_tor_trouble = calls.append
    now = [1000.0]
    r.clock = lambda: now[0]
    for _ in range(8):
        r._onion_trouble()
    assert calls == [1]                       # first: fresh circuits
    for _ in range(8):
        r._onion_trouble()
    assert calls == [1]                       # too soon after the last fix
    now[0] += 700
    for _ in range(8):
        r._onion_trouble()
    assert calls == [1, 2]                    # still failing: restart Tor


class _Log:
    def __init__(self):
        self.lines = []

    def warn(self, _a, m):
        self.lines.append(m)

    info = warn


class _Ctl:
    def __init__(self, runner, keep=True):
        self.runner, self.log, self.wanted_running = runner, _Log(), True
        self._alive, self.started, self.restarted = True, 0, 0

        class P:
            pass
        self.profile = P()
        self.profile.extras = P()
        self.profile.extras.keep_alive = keep

    @property
    def running(self):
        return self._alive

    def start(self, reason=""):
        self.started += 1
        self._alive = True

    def restart_for_keepalive(self):
        self.restarted += 1


def test_it_wakes_a_run_that_paused_itself_but_not_one_you_paused():
    r = _runner({})
    ka = KeepAlive(_Ctl(r))
    r.paused = "failures"
    assert ka.tick() == "woke" and r.paused is False
    r.paused = True                           # the person pressed Pause
    assert ka.tick() is None and r.paused is True


def test_your_own_daily_data_limit_is_respected():
    r = _runner({"daily_data_mb": 0.002})
    r.bytes_today = 10_000_000
    r.paused = "failures"
    assert KeepAlive(_Ctl(r)).tick() is None and r.paused == "failures"


def test_it_restarts_a_run_that_stopped_on_its_own_but_not_a_crash_loop():
    r = _runner({})
    ctl = _Ctl(r)
    ka = KeepAlive(ctl)
    for _ in range(10):
        ctl._alive = False
        ka.tick()
    assert ctl.started == 6                   # at most six an hour
    ctl.wanted_running = False                # you pressed Stop: it stays stopped
    ctl._alive, ctl.started = False, 0
    assert ka.tick() is None and ctl.started == 0


def test_a_stuck_loop_is_restarted_but_not_right_after_the_computer_wakes():
    r = _runner({})
    ctl = _Ctl(r)
    now = [5000.0]
    ka = KeepAlive(ctl, clock=lambda: now[0])
    r.last_beat = time.time() - 3600          # nothing has moved for an hour
    assert ka.tick() == "unstuck" and ctl.restarted == 1
    now[0] += 7200                            # the computer was asleep for two hours
    assert ka.tick() is None                  # a grace period before judging it
    now[0] += 100
    assert ka.tick() is None                  # still inside the grace period
    now[0] += 100
    assert ka.tick() == "unstuck"


def test_switching_it_off_leaves_everything_alone():
    r = _runner({})
    ctl = _Ctl(r, keep=False)
    ka = KeepAlive(ctl)
    r.paused = "failures"
    ctl._alive = False
    assert ka.tick() is None and r.paused == "failures" and ctl.started == 0
