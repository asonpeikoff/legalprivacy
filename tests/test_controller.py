"""Controller + web UI API tests (offline; no Tor, no network)."""
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

from legalprivacy.config import ConfigError  # noqa: E402
from legalprivacy.controller import Controller  # noqa: E402
from legalprivacy.webui import UIServer  # noqa: E402

GOOD = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"


def _ctl():
    return Controller(os.path.join(tempfile.mkdtemp(), "config.yaml"))


def test_wizard_three_answers_persist_and_tor_defaults_off():
    c = _ctl()
    assert c.first_run
    st = c.wizard({"rate_mode": "random", "level": 3, "tor": "off", "autostart": True})
    assert not st["first_run"] and st["profile"]["rate"] == {"mode": "random", "level": 3.0, "randomness": 1.0}
    assert st["profile"]["transports"]["tor"]["enabled"] is False
    c2 = Controller(c.profile_path)                       # reload from disk
    assert c2.app["autostart"] is True and not c2.first_run


def test_wizard_onion_choice_never_enables_clearnet_over_tor():
    c = _ctl()
    st = c.wizard({"level": 5, "tor": "onion"})
    tor = st["profile"]["transports"]["tor"]
    assert tor["enabled"] and tor["onion"]


def test_apply_config_validates_onion_seeds_and_bridges():
    c = _ctl()
    try:
        c.apply_config({"transports": {"tor": {"onion_seeds": "http://bogus.onion"}}})
        raise AssertionError("expected ConfigError")
    except ConfigError:
        pass
    st = c.apply_config({"transports": {"tor": {"onion_seeds": GOOD, "bridges": "obfs4 1.1.1.1:1 AA\n\n"}}})
    assert st["profile"]["transports"]["tor"]["onion_seeds"] == [GOOD]
    assert st["profile"]["transports"]["tor"]["bridges"] == ["obfs4 1.1.1.1:1 AA"]


def test_start_stop_with_nothing_enabled_errors():
    c = _ctl()
    c.apply_config({"transports": {"clearnet": {"enabled": False}}})
    try:
        c.start()
        raise AssertionError("expected ConfigError")
    except ConfigError:
        pass


def _call(url, token, path, body=None, headers=None):
    req = urllib.request.Request(url + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"X-Token": token, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_web_api_requires_token_and_serves_state():
    import threading
    c = _ctl()
    srv = UIServer(c, port=0)
    threading.Thread(target=srv.httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.port}"
    try:
        assert _call(base, "wrong", "/api/state")[0] == 401
        code, st = _call(base, srv.token, "/api/state")
        assert code == 200 and st["first_run"] and st["tor"]["enabled"] is False
        assert _call(base, srv.token, "/api/doctor")[0] == 200
        assert _call(base, srv.token, "/api/config", {"daily_max_failures": 5})[1]["profile"]["daily_max_failures"] == 5
        assert _call(base, srv.token, "/api/tor/bogus", {})[0] == 400
        # cross-site POST rejected
        assert _call(base, srv.token, "/api/stop", {}, {"Origin": "http://evil.example"})[0] == 403
        # DNS-rebinding style Host header rejected
        assert _call(base, srv.token, "/api/state", None, {"Host": "evil.example"})[0] == 403
        # page itself needs the token in the URL
        try:
            urllib.request.urlopen(base + "/", timeout=5)
            raise AssertionError("index served without token")
        except urllib.error.HTTPError as e:
            assert e.code == 403
        with urllib.request.urlopen(base + "/?t=" + srv.token, timeout=5) as r:
            assert b"legalPrivacy" in r.read()
        for path, kind in (("/logo/egg/02-green-supine-skirt.webp", "image/webp"), ("/logo/egg/01-green-animated.mp4", "video/mp4"),
                           ("/logo/trad/07-terminal.webp", "image/webp")):
            with urllib.request.urlopen(base + path + "?t=" + srv.token, timeout=5) as r:
                assert r.headers["Content-Type"] == kind and len(r.read()) > 1000
        assert _call(base, srv.token, "/logo/egg/../../webui.py")[0] in (401, 404)      # only the logo files are served
        assert _call(base, "wrong", "/logo/egg/02-green-supine-skirt.webp")[0] == 401
    finally:
        srv.httpd.shutdown()


def test_live_log_is_memory_only_and_clearable():
    import tempfile
    from pathlib import Path
    from legalprivacy.events import EventLog
    d = Path(tempfile.mkdtemp())
    log = EventLog()                       # no file_path: nothing ever touches disk
    log.info("app", "hello")
    assert log.last_id() == 1 and not list(d.iterdir())
    log.clear()
    assert log.since(0) == [] and log.last_id() == 1


def test_network_tools_report_errors_without_crashing_and_leak_check_has_shape():
    from legalprivacy.nettools import dns_leak_check, speed_test
    res = speed_test(proxy="http://127.0.0.1:9", timeout=5)      # nothing listens there
    assert res["down_mbps"] is None and res["up_mbps"] is None and len(res["errors"]) == 2
    leak = dns_leak_check(["9.9.9.9"])
    assert {"resolvers", "sample_lookup", "external_test"} <= set(leak)

