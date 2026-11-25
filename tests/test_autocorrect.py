import random
import time

from legalprivacy.observe import TrafficObserver, ks_p
from legalprivacy.rate import RateConfig, RatePlanner


def test_the_p_value_is_small_for_different_samples_and_typical_for_the_same():
    ps, fars = [], []
    for seed in range(25):
        rng = random.Random(seed)
        a = [rng.gauss(0, 1) for _ in range(300)]
        ps.append(ks_p(a, [rng.gauss(0, 1) for _ in range(300)]))
        fars.append(ks_p(a, [rng.gauss(1.5, 1) for _ in range(300)]))
    assert sorted(ps)[12] > 0.2 and max(fars) < 0.001               # same: the median p is large; different: always tiny
    assert ks_p([1, 2], [1, 2, 3]) is None


def _observer(away_hour_you):
    obs = TrafficObserver(lambda: False, lambda t: 0, clock=lambda: 0.0)
    base = int(time.mktime((2026, 3, 3, 0, 0, 0, 0, 0, -1)))
    for h in range(24):
        for m in range(30):
            obs.minutes[base + h * 3600 + m * 60] = {"you": 0 if h in away_hour_you else 6, "noise": 0, "on": False}
    return obs


def test_hours_when_you_are_away_get_more_noise_and_busy_hours_get_less():
    obs = _observer(away_hour_you={2, 3, 4})
    g = obs.hour_gains()
    assert g[3] == 2.0 and g[14] == 1.0 and all(v <= 1.0 for h, v in g.items() if h not in {2, 3, 4})
    busy = _observer(away_hour_you=set())
    assert busy.hour_gains() == {h: 1.0 for h in range(24)}


def test_the_planner_applies_the_gain_only_when_auto_correct_is_on():
    def total(auto):
        cfg = RateConfig(mode="steady", level=5.0, randomness=0.0, auto_correct=auto)
        pl = RatePlanner(random.Random(1), cfg)
        pl.gain_fn = lambda h: 2.0 if h == 3 else 1.0
        return pl.actions_for_hour(3, 0.4), pl.actions_for_hour(14, 0.4)
    on, off = total(True), total(False)
    assert abs(on[0] - 2 * off[0]) < 1e-9 and on[1] == off[1]


def test_weekdays_and_weekends_get_their_own_gains():
    """Away every weekday night but at the computer all weekend: the weekend record must not borrow the weekday gains."""
    obs = TrafficObserver(lambda: False, lambda t: 0, clock=lambda: 0.0)
    mon = int(time.mktime((2026, 3, 2, 0, 0, 0, 0, 0, -1)))          # a Monday
    for day in range(7):
        for h in range(24):
            for m in range(30):
                away = day < 5 and h in {2, 3, 4}
                obs.minutes[mon + day * 86400 + h * 3600 + m * 60] = {"you": 0 if away else 6, "noise": 0, "on": False}
    assert obs.hour_gains(kind="weekday")[3] == 2.0
    assert obs.hour_gains(kind="weekend") == {h: 1.0 for h in range(24)}
    saturday = mon + 5 * 86400 + 12 * 3600
    obs.clock = lambda: saturday
    assert obs.hour_gain(3) == 1.0 and obs.correction()["basis"] == "weekend"
    obs._gain_cache = None
    obs.clock = lambda: mon + 12 * 3600
    assert obs.hour_gain(3) == 2.0 and obs.correction()["basis"] == "weekday"
