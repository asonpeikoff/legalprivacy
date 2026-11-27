"""The single-node load generator: capped, authorised-only, one machine, no spoofing, graphable series."""
import pytest

from legalprivacy import loadtest
from legalprivacy.loadtest import MAX_CONN, MAX_RPS, MAX_SECONDS, LoadTest, LoadTestError


def _mk(monkeypatch, **kw):
    monkeypatch.setattr(loadtest, "_check_target", lambda host: None)      # don't resolve in unit tests
    kw.setdefault("authorized", True)
    return LoadTest(**kw)


def test_it_will_not_start_without_authorisation(monkeypatch):
    monkeypatch.setattr(loadtest, "_check_target", lambda host: None)
    with pytest.raises(LoadTestError, match="authorised"):
        LoadTest(target="http://example.test/", authorized=False)


def test_rate_concurrency_and_duration_are_capped(monkeypatch):
    lt = _mk(monkeypatch, target="http://h.test/", rps=10 ** 9, concurrency=10 ** 9, duration=10 ** 9)
    assert lt.rps == MAX_RPS and lt.concurrency == MAX_CONN and lt.duration == MAX_SECONDS
    assert lt.status["capped"] == {"rps": True, "conn": True}


def test_targets_are_parsed_and_bad_ones_refused(monkeypatch):
    monkeypatch.setattr(loadtest, "_check_target", lambda host: None)
    http = _mk(monkeypatch, target="example.test/path")                    # scheme added
    assert http.host == "example.test" and http.port == 80 and http.url.startswith("http://")
    tcp = _mk(monkeypatch, target="10.0.0.5:8080", mode="tcp")
    assert tcp.host == "10.0.0.5" and tcp.port == 8080
    with pytest.raises(LoadTestError, match="host:port"):
        _mk(monkeypatch, target="not-a-port", mode="tcp")
    with pytest.raises(LoadTestError, match="GET, HEAD or POST"):
        _mk(monkeypatch, target="http://h.test/", method="DELETE")


def test_a_government_range_target_is_refused(monkeypatch):
    import socket
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [(2, 1, 6, "", ("6.1.2.3", 0))])

    class G:
        def reason(self, ip):
            return "a US Department of Defense range" if ip == "6.1.2.3" else None
    monkeypatch.setattr(loadtest.geoban if hasattr(loadtest, "geoban") else loadtest, "shared", lambda: G(), raising=False)
    import legalprivacy.geoban as gb
    monkeypatch.setattr(gb, "shared", lambda: G())
    with pytest.raises(LoadTestError, match="will not aim"):
        LoadTest(target="http://dod.test/", authorized=True)


def test_a_run_records_results_as_a_time_series_without_real_network(monkeypatch):
    lt = _mk(monkeypatch, target="h.test:80", mode="tcp", rps=3, concurrency=3, duration=2)
    calls = {"n": 0}

    def fake_tcp():
        calls["n"] += 1
        lt._record(calls["n"] % 4 != 0, 0, 0, None if calls["n"] % 4 else "Timeout", 0.01 * calls["n"])
    monkeypatch.setattr(lt, "_one_tcp", fake_tcp)
    st = lt.run()
    assert st["done"] and not st["running"] and st["sent"] > 0
    assert st["ok"] + st["failed"] == st["sent"]
    assert st["series"] and all({"t", "sent", "ok", "failed"} <= set(b) for b in st["series"])
    assert st["latency_ms"]["p50"] is not None


def test_stop_ends_the_run(monkeypatch):
    lt = _mk(monkeypatch, target="h.test:80", mode="tcp", rps=5, concurrency=2, duration=MAX_SECONDS)
    monkeypatch.setattr(lt, "_one_tcp", lambda: lt._record(True, 0, 0, None, 0.001))
    lt.stop.set()
    st = lt.run()
    assert st["done"] and st["elapsed"] < 5


def test_controller_refuses_a_second_run_and_requires_authorisation(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    monkeypatch.setattr(loadtest, "_check_target", lambda host: None)
    from legalprivacy.controller import ConfigError, Controller
    c = Controller(str(tmp_path / "config.yaml"))
    with pytest.raises(ConfigError, match="authorised"):
        c.loadtest_start({"target": "http://h.test/", "authorized": False})
    st = c.loadtest_state()
    assert st["job"] is None and st["caps"]["rps"] == MAX_RPS
