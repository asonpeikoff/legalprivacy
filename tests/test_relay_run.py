"""Relay screen: torrc generation (practice mode, injection), the separate relay process (fake Tor), the
controller's checklist and state changes, and panic cleanup. Offline: no real Tor is started."""
import os
import stat
import sys
import time

import pytest

from legalprivacy.config import ConfigError, Profile, apply_overrides
from legalprivacy.relay import RelayConfigError, RelaySpec, generate_torrc, warn_if_exit_requested

ALL_TICKED = {k: True for k in ("address", "always_on", "bandwidth", "not_exit", "public_ip")}


# ── torrc generation ────────────────────────────────────────────────────────
def lines_of(t):
    return [ln.strip() for ln in t.splitlines()]


@pytest.mark.parametrize("mode", ["middle", "bridge"])
@pytest.mark.parametrize("practice", [False, True])
def test_never_an_exit_and_never_wildcard(mode, practice):
    t = generate_torrc(RelaySpec(mode=mode, practice=practice, contact="me@example.org"), data_dir="/tmp/x")
    assert "ExitPolicy accept" not in t and "ExitPolicy accept6" not in t
    assert "ExitRelay 0" in t and "ExitPolicy reject *:*" in t
    assert "0.0.0.0" not in t and "[::]" not in t
    assert t.endswith("ExitPolicy reject6 *:*\n")
    assert warn_if_exit_requested(t) == []
    assert "SocksPort 0" in t                                    # nobody can use it as a proxy


def test_practice_mode_flags():
    t = lines_of(generate_torrc(RelaySpec(mode="middle", practice=True, or_port=9443)))
    assert "ORPort 127.0.0.1:9443" in t
    assert "PublishServerDescriptor 0" in t
    assert "DirPort 0" in t
    assert "AssumeReachable 0" not in t
    b = lines_of(generate_torrc(RelaySpec(mode="bridge", practice=True)))
    assert "PublishServerDescriptor 0" in b and "PublishServerDescriptor bridge" not in b
    assert "ORPort 127.0.0.1:9001" in b


def test_public_mode_is_unchanged_by_the_practice_option():
    t = lines_of(generate_torrc(RelaySpec(mode="middle", practice=False)))
    assert "ORPort 9001" in t and "PublishServerDescriptor 0" not in t and "AssumeReachable 0" in t
    assert "PublishServerDescriptor bridge" in lines_of(generate_torrc(RelaySpec(mode="bridge")))


@pytest.mark.parametrize("field,value", [
    ("contact", "me@example.org\nExitPolicy accept *:*"),
    ("contact", "a\rExitRelay 1"),
    ("contact", "a\0b"),
    ("nickname", "nick\nExitRelay 1"),
    ("nickname", "nïck"),
    ("bandwidth_rate", "5Mbit\nExitRelay 1"),
    ("bandwidth_rate", "1 MBytes; ExitRelay 1"),
])
def test_injection_rejected(field, value):
    with pytest.raises(RelayConfigError):
        generate_torrc(RelaySpec(**{field: value}))


def test_data_dir_cannot_inject():
    for bad in ('/x"\nExitRelay 1', "/x\nExitRelay 1", '/x"'):
        with pytest.raises(RelayConfigError):
            generate_torrc(RelaySpec(), data_dir=bad)


def test_config_reuses_relay_validators():
    for bad in ({"nickname": "a\nb"}, {"contact": "x\ny"}, {"bandwidth_rate": "1 MBytes\nz"}, {"mode": "exit"},
                {"or_port": 80}):
        with pytest.raises(ConfigError):
            apply_overrides(Profile(name="x"), {"contribute": {"relay": bad}})


def test_relay_defaults_are_safe():
    r = Profile(name="x").relay
    assert r.enabled is False and r.autostart is True and r.practice is False and r.acknowledged is False


# ── a fake Tor ──────────────────────────────────────────────────────────────
FAKE = """#!{py}
import signal, sys, time
torrc = open(sys.argv[2]).read()
mode = {mode!r}
print("Nov 21 [notice] Opened OR listener on 127.0.0.1", flush=True)
if mode == "crash":
    print("[err] Could not bind to the ORPort", flush=True)
    sys.exit(1)
print("Nov 21 [notice] You are running a new relay. Thanks for helping the Tor network!", flush=True)
print("Nov 21 [notice] Your Tor server's identity key fingerprint is 'practice1 9239E26B0ED8850765F51573C40F6A6725CD2AB7'", flush=True)
print("Bootstrapped 10% (conn_done): Connected", flush=True)
if "PublishServerDescriptor 0" not in torrc:
    print("[notice] Self-testing indicates your ORPort is reachable from the outside. Excellent.", flush=True)
time.sleep(60)
"""


def make_fake(tmp_path, mode="ok"):
    p = tmp_path / ("faketor_" + mode)
    p.write_text(FAKE.format(py=sys.executable, mode=mode))
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def wait_for(cond, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture()
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(h))
    return h


@pytest.fixture()
def ctl(home, tmp_path):
    from legalprivacy.controller import Controller
    c = Controller(str(home / "config.yaml"))
    c.relay._find_binary = lambda: make_fake(tmp_path)
    yield c
    c.relay.stop()


# ── manager and controller state transitions ────────────────────────────────
def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_state_machine_practice(ctl, home):
    assert ctl.relay_state()["status"]["state"] == "stopped"
    port = free_port()
    st = ctl.relay_start({"practice": True, "or_port": port, "nickname": "practice1"})
    assert st["status"]["state"] in ("starting", "running")
    assert wait_for(lambda: ctl.relay_state()["status"]["state"] == "running")
    s = ctl.relay_state()["status"]
    assert s["practice"] is True and s["fingerprint"].startswith("9239E26B") and s["reachable"] is None
    assert any("running a new relay" in ln for ln in s["log"])
    # torrc on disk: practice flags, own data dir, owner-only permissions
    torrc = (home / "relay" / "torrc").read_text()
    assert f"ORPort 127.0.0.1:{port}" in torrc and "PublishServerDescriptor 0" in torrc
    assert f'DataDirectory "{(home / "relay" / "data").as_posix()}"' in torrc
    if os.name == "posix":
        assert stat.S_IMODE((home / "relay").stat().st_mode) == 0o700
        assert stat.S_IMODE((home / "relay" / "data").stat().st_mode) == 0o700
        assert stat.S_IMODE((home / "relay" / "torrc").stat().st_mode) == 0o600
    ctl.relay_stop()
    assert ctl.relay_state()["status"]["state"] == "stopped"
    assert ctl.relay.pid is None


def test_second_start_refused_while_running(ctl):
    ctl.relay_start({"practice": True, "or_port": free_port()})
    with pytest.raises(RuntimeError):
        ctl.relay_start({"practice": True, "or_port": free_port()})


def test_crash_becomes_error_with_plain_message(home, tmp_path):
    from legalprivacy.controller import Controller
    c = Controller(str(home / "config.yaml"))
    c.relay._find_binary = lambda: make_fake(tmp_path, "crash")
    c.relay_start({"practice": True, "or_port": free_port()})
    assert wait_for(lambda: c.relay_state()["status"]["state"] == "error")
    assert "stopped on its own" in c.relay_state()["status"]["error"]


def test_no_tor_installed_is_a_plain_error(ctl):
    ctl.relay._find_binary = lambda: None
    with pytest.raises(RuntimeError, match="not installed"):
        ctl.relay_start({"practice": True, "or_port": free_port()})
    assert ctl.relay_state()["status"]["state"] == "stopped"


def test_port_in_use_is_refused(ctl):
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        with pytest.raises(RuntimeError, match="already in use"):
            ctl.relay_start({"practice": True, "or_port": s.getsockname()[1]})


def test_public_relay_needs_every_checklist_item(ctl):
    port = free_port()
    with pytest.raises(ConfigError, match="checklist"):
        ctl.relay_start({"practice": False, "or_port": port})
    partial = dict(ALL_TICKED, public_ip=False)
    with pytest.raises(ConfigError, match="checklist"):
        ctl.relay_start({"practice": False, "or_port": port, "checklist": partial})
    with pytest.raises(ConfigError, match="checklist"):
        ctl.relay_start({"practice": False, "or_port": port, "checklist": dict(ALL_TICKED, not_exit="yes")})
    assert ctl.relay_state()["status"]["state"] == "stopped"


def test_public_relay_with_checklist(ctl, home):
    port = free_port()
    ctl.relay_start({"practice": False, "or_port": port, "checklist": ALL_TICKED, "bandwidth_mb": 2})
    assert wait_for(lambda: ctl.relay_state()["status"]["reachable"] is True)
    torrc = (home / "relay" / "torrc").read_text()
    assert f"ORPort {port}" in torrc and "RelayBandwidthRate 2 MBytes" in torrc
    assert "PublishServerDescriptor 0" not in torrc and "ExitPolicy accept" not in torrc
    assert ctl.profile.relay.acknowledged is True


def test_injection_through_the_controller(ctl):
    with pytest.raises(ConfigError):
        ctl.relay_start({"practice": True, "or_port": free_port(), "contact": "a@b.c\nExitRelay 1"})
    with pytest.raises(ConfigError):
        ctl.relay_start({"practice": True, "or_port": free_port(), "nickname": "x\nExitRelay 1"})
    with pytest.raises(ConfigError):
        ctl.relay_start({"practice": True, "or_port": free_port(), "bandwidth_mb": "9\nExitRelay 1"})
    assert ctl.relay_state()["status"]["state"] == "stopped"


def test_bandwidth_bounds(ctl):
    for bad in (0, -1, 5000):
        with pytest.raises(ConfigError):
            ctl.relay_start({"practice": True, "or_port": free_port(), "bandwidth_mb": bad})


def test_state_has_estimate_and_torrc_preview(ctl):
    st = ctl.relay_state()
    assert st["estimate"]["max_gb_per_direction"] == pytest.approx(1 * 86400 * 30 / 1000, abs=0.1)
    assert "ExitPolicy reject *:*" in st["torrc"] and "ExitRelay 0" in st["torrc"]       # never an exit
    assert st["settings"]["practice"] is False and st["settings"]["autostart"] is True


# ── never automatic, never remembered as "on" ───────────────────────────────
def test_nothing_is_published_silently_on_first_launch(home, tmp_path):
    """Autostart is on by default, but the checklist must have been completed once: a fresh install never
    starts (or publishes) a relay by itself."""
    from legalprivacy.controller import Controller
    c = Controller(str(home / "config.yaml"))
    c.relay._find_binary = lambda: make_fake(tmp_path)
    assert c.profile.relay.autostart is True and c.profile.relay.acknowledged is False
    c.relay_autostart()
    assert c.relay_state()["status"]["state"] == "stopped"


def test_the_first_start_needs_every_checklist_item(ctl):
    with pytest.raises(ConfigError, match="checklist"):
        ctl.relay_start({"or_port": free_port()})
    with pytest.raises(ConfigError, match="checklist"):
        ctl.relay_start({"or_port": free_port(), "checklist": {"address": True}})


def test_default_autostart_is_quiet_when_tor_is_not_installed(home):
    from legalprivacy.controller import Controller
    c = Controller(str(home / "config.yaml"))
    c.relay._find_binary = lambda: None
    c.relay_autostart()
    assert c.relay_state()["status"]["state"] == "stopped"


def test_running_is_not_saved_and_autostart_can_be_turned_off(ctl, home, tmp_path):
    from legalprivacy.controller import Controller
    ctl.relay_start({"practice": True, "or_port": free_port()})
    ctl.relay_stop()
    ctl.apply_config({"contribute": {"relay": {"autostart": False}}})
    c2 = Controller(str(home / "config.yaml"))                 # a new launch reads the saved settings
    c2.relay._find_binary = lambda: make_fake(tmp_path)
    c2.relay_autostart()
    assert c2.relay_state()["status"]["state"] == "stopped"     # the opt-out is respected
    assert c2.profile.relay.autostart is False and c2.profile.relay.enabled is False
    c2.apply_config({"contribute": {"relay": {"autostart": True, "or_port": free_port()}}})
    c2.relay_autostart()
    try:
        assert c2.relay_state()["status"]["state"] in ("starting", "running")
    finally:
        c2.relay.stop()


def test_autostart_of_public_relay_needs_the_checklist_done_once(home, tmp_path):
    from legalprivacy.controller import Controller
    c = Controller(str(home / "config.yaml"))
    c.relay._find_binary = lambda: make_fake(tmp_path)
    c.apply_config({"contribute": {"relay": {"autostart": True, "practice": False, "or_port": free_port()}}})
    c.relay_autostart()
    assert c.relay_state()["status"]["state"] == "stopped"


# ── stop on quit and on Panic ───────────────────────────────────────────────
def test_quit_stops_the_relay(ctl):
    ctl.relay_start({"practice": True, "or_port": free_port()})
    assert wait_for(lambda: ctl.relay.running)
    ctl.stop(stop_tor=True)
    assert not ctl.relay.running and ctl.relay_state()["status"]["state"] == "stopped"


def test_stop_without_tor_flag_leaves_the_relay_alone(ctl):
    ctl.relay_start({"practice": True, "or_port": free_port()})
    ctl.stop()                                                 # stops the noise only
    assert ctl.relay.running


@pytest.mark.parametrize("level", ["soft", "medium"])
def test_panic_stops_relay_but_keeps_data(ctl, home, level):
    ctl.relay_start({"practice": True, "or_port": free_port()})
    assert wait_for(lambda: ctl.relay_state()["status"]["state"] == "running")
    r = ctl.panic(level)
    assert "relay stopped" in r["done"] and not ctl.relay.running
    assert (home / "relay" / "torrc").exists()


def test_hard_panic_deletes_relay_data_only_after_stop(ctl, home):
    ctl.relay_start({"practice": True, "or_port": free_port()})
    assert wait_for(lambda: ctl.relay_state()["status"]["state"] == "running")
    (home / "relay" / "data").mkdir(exist_ok=True)
    (home / "relay" / "data" / "keys").write_text("secret")
    order = []
    real_stop, real_wipe = ctl.relay.stop, ctl.relay.wipe_data
    ctl.relay.stop = lambda: (order.append("stop"), real_stop())[1]
    ctl.relay.wipe_data = lambda: (order.append(("wipe", ctl.relay.running)), real_wipe())[1]
    r = ctl.panic("hard")
    assert order == ["stop", ("wipe", False)]
    assert not (home / "relay").exists()
    assert any("relay data deleted" in d for d in r["done"])


def test_wipe_refuses_while_running(ctl, home):
    ctl.relay_start({"practice": True, "or_port": free_port()})
    assert wait_for(lambda: ctl.relay.running)
    assert ctl.relay.wipe_data() is False
    assert (home / "relay").exists()


# ── the dashboard routes ────────────────────────────────────────────────────
def test_dashboard_routes(home, tmp_path):
    import http.client
    import json
    import threading
    from legalprivacy.controller import Controller
    from legalprivacy.webui import UIServer
    c = Controller(str(home / "config.yaml"))
    c.relay._find_binary = lambda: make_fake(tmp_path)
    srv = UIServer(c, port=0)
    threading.Thread(target=srv.httpd.serve_forever, daemon=True).start()
    try:
        def call(path, body=None):
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=15)
            conn.request("GET" if body is None else "POST", path,
                         body=None if body is None else json.dumps(body), headers={"X-Token": srv.token})
            r = conn.getresponse()
            out = (r.status, json.loads(r.read()))
            conn.close()
            return out
        code, st = call("/api/relay")
        assert code == 200 and st["status"]["state"] == "stopped"
        code, err = call("/api/relay/start", {"practice": False, "or_port": free_port()})
        assert code == 400 and "checklist" in err["error"]
        code, st = call("/api/relay/start", {"practice": True, "or_port": free_port()})
        assert code == 200 and st["status"]["state"] in ("starting", "running")
        code, st = call("/api/relay/stop", {})
        assert code == 200 and st["status"]["state"] == "stopped"
        code, a = call("/api/tor/dns/addresses")
        assert code == 200 and isinstance(a["addresses"], list)
        code, r = call("/api/tor/dns/test", {})
        assert code == 200 and r["ok"] is False and "off" in r["error"]
    finally:
        c.relay.stop()
        srv.httpd.shutdown()
