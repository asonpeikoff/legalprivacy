"""Activity graphs: intended pattern from the rate planner, session vs plan, baseline vs noise."""
import os
import random
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

from legalprivacy import activity as ac  # noqa: E402
from legalprivacy.rate import RateConfig  # noqa: E402

DAY = 1_700_000_000 // 86400 * 86400            # a UTC midnight; local hours are derived with time.localtime


def test_intended_random_has_band_and_day_night_shape():
    p = ac.intended(RateConfig("random", 5.0, 1.0), 0.3)
    assert all(lo <= mid <= hi for lo, mid, hi in zip(p["p10"], p["p50"], p["p90"]))
    assert p["p90"][20] > p["p10"][20]                       # a real spread in random mode
    assert p["p50"][21] > 2 * p["p50"][4]                    # evenings busier than 4 am
    assert p["per_day"] > 0 and p["verdict"].startswith("Reads as:") and "random" in p["verdict"]


def test_intended_steady_is_flat_and_active_hours_are_masked():
    p = ac.intended(RateConfig("steady", 5.0, 0.0), 0.3, active_hours=True, a=9, b=17, persona="Student")
    assert p["p10"] == p["p90"]
    assert all(p["p50"][h] == 0 for h in list(range(0, 9)) + list(range(17, 24)))
    assert len({p["p50"][h] for h in range(9, 17)}) == 1 and p["p50"][9] > 0
    assert "09:00–17:00" in p["verdict"] and "Student" in p["verdict"]
    wrap = ac.intended(RateConfig("steady", 5.0, 0.0), 0.3, active_hours=True, a=22, b=6)
    assert wrap["p50"][23] > 0 and wrap["p50"][3] > 0 and wrap["p50"][12] == 0


def _timeline(start, minutes, req_fn, on=True):
    return [{"t": start + i * 60, "on": on, "you": 2, "noise": 1, "tor": 0, "req": req_fn(i), "bytes": 0}
            for i in range(minutes)]


def _plan(level=5):
    return ac.intended(RateConfig("steady", level, 0.0), 0.3)


def test_session_on_plan_and_busier_than_planned():
    plan = _plan()
    per_hour = plan["p50"][0]
    start = DAY + 3600 * 5
    start -= start % 3600
    ok = ac.session(_timeline(start, 120, lambda i: per_hour / 60), plan, True)
    assert ok["state"] == "ok" and ok["verdict"].startswith("✓") and not ok["flags"]
    hot = ac.session(_timeline(start, 120, lambda i: per_hour / 60 * 8 + 1), plan, True)
    assert hot["state"] == "off" and "busier than planned" in hot["verdict"] and hot["verdict"].startswith("✗")
    assert all(f["dir"] == "busier" for f in hot["flags"])
    assert len(hot["buckets"]) == 12 and hot["buckets"][0]["hi"] > 0


def test_session_empty_and_early_states_explain_themselves():
    plan = _plan()
    off = ac.session(_timeline(DAY, 60, lambda i: 0, on=False), plan, False)
    assert off["state"] == "empty" and "off" in off["verdict"]
    early = ac.session(_timeline(DAY + 3600 * 3, 20, lambda i: 1), plan, True)
    assert early["state"] == "early" and "Too early" in early["verdict"]


def _sel(rows, enough=True):
    return {"enough": enough, "rows": rows, "status": "Your baseline: test.", "source": "har" if enough else "none"}


def _day_rows(hours, key="n", days=3, p=0.6, seed=1):
    rng = random.Random(seed)
    out = []
    for d in range(days):
        for i in range(1440):
            t = DAY + d * 86400 + i * 60
            h = time.localtime(t).tm_hour
            out.append({"t": t, key: rng.randint(1, 5) if (h in hours and rng.random() < p) else 0})
    return out


def _noise_rows(hours, **kw):
    rows = _day_rows(hours, key="req", **kw)
    return [{"t": r["t"], "on": True, "you": 0, "noise": r["req"], "req": r["req"], "tor": 0, "bytes": 0} for r in rows]


def test_baseline_vs_noise_close_and_different():
    day = set(range(8, 22))
    close = ac.baseline_vs_noise(_sel(_day_rows(day)), _noise_rows(day, seed=4))
    assert close["state"] == "ok" and close["similarity"] >= 0.9 and close["verdict"].startswith("✓")
    night = set(range(0, 5)) | day
    far = ac.baseline_vs_noise(_sel(_day_rows(day)), _noise_rows(night, seed=4))
    assert far["state"] == "off" and far["verdict"].startswith("✗") and "Noise active at 0" in far["verdict"]
    assert len(far["you"]) == 24 and abs(sum(far["noise"]) - 1) < 0.01
    assert far["bursts"]["you"] and len(far["gaps"]["noise"]) == len(far["labels"])


def test_baseline_vs_noise_short_baseline_and_empty_states():
    day = set(range(9, 11))
    short = ac.baseline_vs_noise(_sel(_day_rows(day, days=1)), _noise_rows(set(range(8, 22))))
    assert short["state"] == "short" and short["similarity"] is None and "can't be fairly compared" in short["verdict"]
    none = ac.baseline_vs_noise(_sel([], enough=False), _noise_rows({9}))
    assert none["state"] == "none" and none["similarity"] is None and none["you"] == [0.0] * 24
    early = ac.baseline_vs_noise(_sel(_day_rows(set(range(8, 22)))), [])
    assert early["state"] == "early"


def test_histogram_bins():
    assert ac.histogram([1, 2, 3, 4, 5, 9, 10, 25]) == [0.125, 0.125, 0.25, 0.25, 0.125, 0.125]
    assert ac.histogram([]) == [0.0] * 6


def test_activity_endpoint():
    import threading
    sys.path.insert(0, os.path.dirname(__file__))
    from test_controller import _call, _ctl
    from legalprivacy.webui import UIServer
    c = _ctl()
    srv = UIServer(c, port=0)
    threading.Thread(target=srv.httpd.serve_forever, daemon=True).start()
    try:
        code, d = _call(f"http://127.0.0.1:{srv.port}", srv.token, "/api/activity")
        assert code == 200 and len(d["intended"]["p50"]) == 24
        assert d["baseline"]["state"] in ("none", "early", "short") and d["session"]["state"] == "empty"
    finally:
        srv.httpd.shutdown()


def test_session_judges_whole_local_hours_in_half_hour_timezones():
    if not hasattr(time, "tzset"):
        return
    old = os.environ.get("TZ")
    os.environ["TZ"] = "Asia/Kolkata"        # UTC+5:30: UTC hour boundaries fall mid local hour
    time.tzset()
    try:
        plan = _plan()
        start = DAY + 3600 * 5 + 1800          # 05:30 UTC = 11:00 local
        res = ac.session(_timeline(start, 60, lambda i: plan["p50"][11] / 60), plan, True)   # one whole local hour
        assert res["state"] == "ok", res["verdict"]
    finally:
        if old is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old
        time.tzset()
