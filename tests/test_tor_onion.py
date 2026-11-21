"""Tor/onion tests — all offline (fake control server, injected probes)."""
import os
import random
import socket
import sys
import tempfile
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

from legalprivacy.config import (Profile, apply_overrides, load_profile,  # noqa: E402
                                 profile_to_dict, save_profile)
from legalprivacy.onion import (BUILTIN_ONION_SEEDS, OnionTargetFactory,  # noqa: E402
                                clean_seed_list, is_onion_url, is_valid_v3_onion)
from legalprivacy.scheduler import Runner, build_lanes  # noqa: E402
from legalprivacy.transports import HitResult, TOR_BROWSER_HEADERS  # noqa: E402
from legalprivacy.torcontrol import TorControl, TorControlError  # noqa: E402
from legalprivacy.config import ConfigError  # noqa: E402
from legalprivacy.events import EventLog  # noqa: E402
from legalprivacy.tormanager import TorManager  # noqa: E402
from pathlib import Path  # noqa: E402

WORDS = ["weather", "news", "books"]
GOOD = BUILTIN_ONION_SEEDS[0][1]


def test_builtin_seeds_all_valid_v3():
    assert BUILTIN_ONION_SEEDS
    assert all(is_onion_url(u) for _, u in BUILTIN_ONION_SEEDS)


def test_builtin_seeds_unique_and_lawful_only():
    urls = [u for _, u in BUILTIN_ONION_SEEDS]
    assert len(urls) == len(set(urls)) >= 15
    banned = ("market", "drug", "dread", "exploit", "porn", "pirate", "chan", "recon", "leak", "cia", "fbi", "police", "ncide", "gov")
    assert not any(b in n.lower() for n, _ in BUILTIN_ONION_SEEDS for b in banned)


def test_onion_checksum_rejects_typos_and_old_v2():
    host = GOOD.split("//")[1].rstrip("/")
    assert is_valid_v3_onion(host)
    flipped = host[:10] + ("a" if host[10] != "a" else "b") + host[11:]
    assert not is_valid_v3_onion(flipped)
    assert not is_valid_v3_onion("expyuzz4wqqyqhjn.onion")      # v2-length
    assert not is_valid_v3_onion("example.com")


def test_clean_seed_list_splits_good_and_bad():
    good, bad = clean_seed_list([GOOD, "http://nope.onion", "# c", "", "example.com"])
    assert good == [GOOD] and len(bad) == 2


def test_onion_walk_never_leaves_onion_space():
    import random
    f = OnionTargetFactory(rng=random.Random(1))
    html = f'<a href="https://evil.example/x">c</a><a href="{BUILTIN_ONION_SEEDS[1][1]}a">o</a>'
    for _ in range(20):
        nxt = f.next_from(html, GOOD)
        assert nxt is not None and is_onion_url(nxt.url)
    assert f.next_from('<a href="https://evil.example/">c</a>', GOOD) is None


def test_tor_is_off_by_default_and_clearnet_over_tor_off():
    p = Profile(name="d")
    tor = p.transports["tor"]
    assert tor.enabled is False and tor.onion is True
    assert p.active_engines("tor") == ["onion"]          # even when later enabled
    assert "onion" not in p.active_engines("clearnet")
    assert build_lanes(p, WORDS) and [l.name for l in build_lanes(p, WORDS)] == ["clearnet"]


def test_enabling_tor_adds_onion_lane_only():
    p = Profile(name="d")
    apply_overrides(p, {"transports": {"tor": {"enabled": True}}})
    lanes = {l.name: l for l in build_lanes(p, WORDS)}
    assert lanes["tor"].engines == ["onion"]
    assert lanes["clearnet"].budgets["search"].per_day == 120      # not halved: nothing shared


def test_tor_lane_runs_only_onion():
    p = Profile(name="d")
    apply_overrides(p, {"transports": {"tor": {"enabled": True}}})
    lanes = {l.name: l for l in build_lanes(p, WORDS)}
    assert set(lanes["tor"].engines) == {"onion"}
    assert lanes["clearnet"].budgets["search"].per_day == 120       # clearnet budgets are never shared with Tor


def test_profile_roundtrip(tmp_path=None):
    p = Profile(name="rt")
    apply_overrides(p, {"transports": {"tor": {"enabled": True, "bridges": ["obfs4 1.2.3.4:1 AA cert=x"]}}})
    path = os.path.join(tempfile.mkdtemp(), "c.yaml")
    save_profile(p, path)
    q = load_profile(path)
    assert q.transports["tor"].enabled and q.transports["tor"].bridges == ["obfs4 1.2.3.4:1 AA cert=x"]
    assert profile_to_dict(q) == profile_to_dict(p)


def _run_onion_runner(gate_open):
    p = Profile(name="t")
    apply_overrides(p, {"transports": {"clearnet": {"enabled": False}, "tor": {"enabled": True}}})
    seen = []

    def probe(lane, ident, target):
        seen.append((lane.name, target.url))
        return HitResult(200, '<a href="%s">x</a>' % BUILTIN_ONION_SEEDS[2][1])

    lanes = build_lanes(p, WORDS, tor_gate=lambda: gate_open[0])
    r = Runner(profile=p, lanes=lanes, wordlist=WORDS, clock=lambda: 0.0, local_hour_fn=lambda: 12.0,
               sleep_fn=lambda s: None, probe_fn=probe, max_iterations=50)
    return r, seen


def test_tor_lane_waits_for_gate_then_runs_onion_only():
    gate = [False]
    r, seen = _run_onion_runner(gate)
    assert r.run_once(wait=False) is False and not seen      # Tor not ready → idle, no leak
    gate[0] = True
    for _ in range(10):
        r.run_once(wait=False)
    assert seen and all(is_onion_url(u) for _, u in seen) and {l for l, _ in seen} == {"tor"}
    assert r.stats()["lanes"][0]["hits"] == len(seen)
    assert r.hit_log and r.hit_log[-1]["engine"] == "onion"


def test_onion_failures_dont_trip_clearnet_failure_cap():
    p = Profile(name="t")
    apply_overrides(p, {"daily_max_failures": 3, "transports": {"clearnet": {"enabled": False},
                                                                "tor": {"enabled": True}}})
    lanes = build_lanes(p, WORDS, tor_gate=lambda: True)
    r = Runner(profile=p, lanes=lanes, wordlist=WORDS, clock=lambda: 0.0, local_hour_fn=lambda: 12.0,
               sleep_fn=lambda s: None, probe_fn=lambda *a: HitResult(None, error="timeout"))
    for _ in range(8):          # 8 > 3 would have raised for a clearnet engine
        r.run_once(wait=False)


def test_tor_browser_headers_are_uniform():
    assert "Firefox" in TOR_BROWSER_HEADERS["User-Agent"] and "Chrome" not in TOR_BROWSER_HEADERS["User-Agent"]


# ── control port against a fake tor ─────────────────────────────────────────
def _fake_tor(handler_lines):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    received = []

    def serve():
        c, _ = srv.accept()
        f = c.makefile("rw", newline="\r\n")
        for line in iter(f.readline, ""):
            line = line.rstrip("\r\n")
            received.append(line)
            for out in handler_lines(line):
                f.write(out + "\r\n")
            f.flush()
            if line == "QUIT":
                break
        c.close()
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return port, received


def test_control_null_auth_getinfo_newnym_and_circuits():
    def h(line):
        if line.startswith("PROTOCOLINFO"):
            return ["250-PROTOCOLINFO 1", "250-AUTH METHODS=NULL", "250 OK"]
        if line == "AUTHENTICATE":
            return ["250 OK"]
        if line == "GETINFO version":
            return ["250-version=0.4.9.99", "250 OK"]
        if line == "GETINFO circuit-status":
            return ["250+circuit-status=", "5 BUILT $AAAA~guard,$BBBB~mid,$CCCC~exit BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL",
                    "7 BUILT $AAAA~guard,$BBBB~mid PURPOSE=HS_CLIENT_REND", ".", "250 OK"]
        if line == "SIGNAL NEWNYM":
            return ["250 OK"]
        return ["250 OK"]
    port, rec = _fake_tor(h)
    with TorControl("127.0.0.1", port) as c:
        assert c.getinfo("version") == "0.4.9.99"
        circ = c.circuits()
        assert circ[0]["path"] == ["guard", "mid", "exit"] and circ[1]["purpose"] == "HS_CLIENT_REND"
        c.newnym()
    assert "SIGNAL NEWNYM" in rec


def test_control_cookie_auth():
    cookie = tempfile.NamedTemporaryFile(delete=False)
    cookie.write(bytes(range(1, 33)))
    cookie.close()

    def h(line):
        if line.startswith("PROTOCOLINFO"):
            return ["250-PROTOCOLINFO 1", f'250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="{cookie.name}"', "250 OK"]
        if line.startswith("AUTHENTICATE "):
            return ["250 OK"] if line.split()[1] == bytes(range(1, 33)).hex() else ["515 bad"]
        return ["250 OK"]
    port, _ = _fake_tor(h)
    with TorControl("127.0.0.1", port):
        pass
    os.unlink(cookie.name)


def _patience_run(seed):
    p = Profile(name="t")
    apply_overrides(p, {"transports": {"clearnet": {"enabled": False}, "tor": {"enabled": True}}})
    clock = [1000.0]
    calls, seen = [], []
    lanes = build_lanes(p, WORDS, tor_gate=lambda: True)
    lanes[0].transport.reconnect = lambda: calls.append("newnym") or True
    lanes[0].transport.renew_circuits = lambda: calls.append("renew") or True

    def probe(l, ident, target):
        seen.append(target.url)
        return HitResult(None, error="0x01: General SOCKS server failure")

    r = Runner(profile=p, lanes=lanes, wordlist=WORDS, clock=lambda: clock[0], local_hour_fn=lambda: 12.0,
               sleep_fn=lambda s: None, probe_fn=probe)
    r.rng = random.Random(seed)
    for _ in range(6):
        r.run_once(wait=False)
        clock[0] += 200
    return r, seen, calls, clock, lanes


def test_tor_patience_varies_like_a_person_and_gets_new_identities():
    for seed in range(40):
        r, seen, calls, clock, lanes = _patience_run(seed)
        assert "newnym" in calls                          # a run of failures always ends in a new identity
        assert lanes[0].__dict__.get("onion_retry") is None    # an unreachable onion is never reloaded


def test_unreachable_onion_sometimes_switches_identity_first_and_sometimes_just_moves_on():
    early = later = 0
    for seed in range(40):
        p = Profile(name="t")
        apply_overrides(p, {"transports": {"clearnet": {"enabled": False}, "tor": {"enabled": True}}})
        calls = []
        lanes = build_lanes(p, WORDS, tor_gate=lambda: True)
        lanes[0].transport.reconnect = lambda calls=calls: calls.append("newnym") or True
        r = Runner(profile=p, lanes=lanes, wordlist=WORDS, clock=lambda: 1000.0, local_hour_fn=lambda: 12.0,
                   sleep_fn=lambda s: None,
                   probe_fn=lambda l, i, t: HitResult(None, error="0x04: Host unreachable"))
        r.rng = random.Random(seed)
        r.run_once(wait=False)                            # exactly one unreachable onion
        if calls:
            early += 1                                    # new identity before the next onion
        else:
            later += 1                                    # went straight to a different onion
    assert early > 5 and later > 5                        # a coin flip, not one fixed reaction


def test_tor_routine_new_circuits():
    r, seen, calls, clock, lanes = _patience_run(1)
    calls.clear()
    clock[0] += 3000
    r.probe_fn = lambda l, i, t: HitResult(200, "<html></html>")
    r.run_once(wait=False)
    assert "renew" in calls


def test_bridges_from_bundle_pt_config(tmp=None):
    import json
    from legalprivacy.events import EventLog
    from legalprivacy.tormanager import TorManager
    d = tempfile.mkdtemp()
    pt = os.path.join(d, "tor", "pluggable_transports")
    os.makedirs(pt)
    open(os.path.join(d, "tor", "tor"), "w").close()
    json.dump({"pluggableTransports": {"lyrebird": "ClientTransportPlugin meek_lite,obfs4 exec ${pt_path}lyrebird",
                                       "snowflake": "ClientTransportPlugin snowflake exec ${pt_path}lyrebird"},
               "bridges": {"obfs4": ["obfs4 1.2.3.4:443 AAAA cert=x iat-mode=0"],
                           "snowflake": ["snowflake 192.0.2.3:80 BBBB fingerprint=BBBB"]}},
              open(os.path.join(pt, "pt_config.json"), "w"))
    tm = TorManager(EventLog(), bridge_mode="snowflake", bridges=["obfs4 9.9.9.9:1 CCCC cert=y iat-mode=0"])
    tm.binary = os.path.join(d, "tor", "tor")
    assert tm.effective_bridges() == ["snowflake 192.0.2.3:80 BBBB fingerprint=BBBB"]
    real_pt = os.path.realpath(pt)          # Windows temp dirs resolve from 8.3 short names to long ones
    assert tm._pt_line("snowflake") == f"ClientTransportPlugin snowflake exec {real_pt}{os.sep}lyrebird"
    tm.bridge_mode = "custom"
    assert tm.effective_bridges() == ["obfs4 9.9.9.9:1 CCCC cert=y iat-mode=0"]
    tm.bridge_mode = "off"
    assert tm.effective_bridges() == []


def test_bridge_mode_validated():
    from legalprivacy.config import ConfigError
    try:
        apply_overrides(Profile(name="t"), {"transports": {"tor": {"bridge_mode": "weird"}}})
        raise AssertionError("accepted a bad bridge mode")
    except ConfigError:
        pass


def test_control_refuses_a_cookie_file_that_is_not_a_cookie():
    """A rogue 'tor' could name any file as its cookie; only a 32-byte cookie may ever be sent."""
    big = os.path.join(tempfile.mkdtemp(), "secret.txt")
    with open(big, "wb") as fh:
        fh.write(b"not a cookie " * 20)
    sent = []

    def h(line):
        sent.append(line)
        if line.startswith("PROTOCOLINFO"):
            return ["250-PROTOCOLINFO 1", f'250-AUTH METHODS=COOKIE COOKIEFILE="{big}"', "250 OK"]
        return ["250 OK"]
    port, _ = _fake_tor(h)
    try:
        TorControl("127.0.0.1", port).connect()
        raise AssertionError("expected TorControlError")
    except TorControlError as exc:
        assert "32 bytes" in str(exc)
    assert not any(ln.startswith("AUTHENTICATE") for ln in sent)


def test_control_password_cannot_smuggle_a_second_command():
    def h(line):
        if line.startswith("PROTOCOLINFO"):
            return ["250-PROTOCOLINFO 1", "250-AUTH METHODS=HASHEDPASSWORD", "250 OK"]
        return ["250 OK"]
    port, _ = _fake_tor(h)
    try:
        TorControl("127.0.0.1", port, password='x"\r\nSIGNAL SHUTDOWN').connect()
        raise AssertionError("expected TorControlError")
    except TorControlError as exc:
        assert "line breaks" in str(exc)


def test_bridge_lines_cannot_inject_torrc_settings():
    from legalprivacy.config import TransportConfig, valid_bridge_line
    good = ["obfs4 1.2.3.4:443 AAAA cert=x iat-mode=0", "1.2.3.4:9001 AAAA", "webtunnel [2001:db8::1]:443 AB url=https://e.example/p ver=0.0.3"]
    assert all(valid_bridge_line(b) for b in good)
    evil = ["obfs4 1.2.3.4:443 AA\nClientTransportPlugin obfs4 exec /bin/sh -c id",
            "ClientTransportPlugin obfs4 exec /bin/sh", "Bridge obfs4 1.2.3.4:443 AA", "../x 1.2.3.4:1", ""]
    assert not any(valid_bridge_line(b) for b in evil)
    try:
        TransportConfig(bridges=[evil[0]]).validate("tor")
        raise AssertionError("expected ConfigError")
    except ConfigError:
        pass
    TransportConfig(bridges=good).validate("tor")
    tm = TorManager(EventLog(), bridge_mode="custom", bridges=good + [evil[0]])
    tm.binary = "/nonexistent/tor/tor"
    tm.cookie_path = "/x"
    tm.socks_host, tm.socks_port, tm.control_host, tm.control_port = "127.0.0.1", 1, "127.0.0.1", 2
    text = tm._write_torrc(Path("/tmp/x")).read_text()
    assert "/bin/sh" not in text and text.count("\nBridge ") == len(good)
