"""Remote machines over SSH: connection strings, host keys, the runner, the manager (fake transport), the real
transport against a loopback SSH server, the web API and the native tab. No internet is used anywhere."""
import json
import os
import random
import subprocess
import sys
import tempfile
import threading
import time
import types
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

from legalprivacy import remoteagent as RA  # noqa: E402
from legalprivacy import remoterun as RR  # noqa: E402
from legalprivacy import sshconn as SC  # noqa: E402
from legalprivacy.events import EventLog  # noqa: E402
from legalprivacy.sshtarget import Target, TargetError, parse_target  # noqa: E402
from tests import sshfake as F  # noqa: E402

try:
    import paramiko
except ImportError:                                                # the loopback tests below need it; the rest do not
    paramiko = None
needs_paramiko = pytest.mark.skipif(paramiko is None, reason="the real-transport tests need paramiko")


# ── helpers ─────────────────────────────────────────────────────────────────
def pools(rng, os_name="Linux"):
    return {"domains": [f"site{i}.example.org" for i in range(400)], "queries": [f"query number {i}" for i in range(300)],
            "user_agents": [f"UA/{i}" for i in range(10)]}


def manager(tmp_path, **opts):
    F.FakeTransport.instances.clear()
    store = SC.HostKeyStore(tmp_path / "hostkeys.json")
    mgr = RR.RemoteManager(EventLog(), pools=pools, transport_factory=F.factory(**opts), path=tmp_path / "machines.json",
                           store=store, agent_source=lambda: b"# agent")
    return mgr, store


def add(mgr, target="pat@box.lan:2222", **kw):
    args = dict(target=target, auth="password", password="s3cret-pw", authorised=True)
    args.update(kw)
    return mgr.add(**args)


def wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def trust_it(mgr, mid):
    r = mgr.test(mid)
    assert r["status"] == "untrusted"
    mgr.trust(mid, r["fingerprint"])


# ── the connection string ───────────────────────────────────────────────────
@pytest.mark.parametrize("text,expect", [
    ("pat@box", ("pat", "box", 22)),
    ("pat@192.168.1.20:2200", ("pat", "192.168.1.20", 2200)),
    ("Pat@Box.Example.COM", ("Pat", "box.example.com", 22)),
    ("pat@[fe80::1]:2222", ("pat", "fe80::1", 2222)),
    ("pat@[::1]", ("pat", "::1", 22)),
    ("DOMAIN\\pat@win-pc:22", ("DOMAIN\\pat", "win-pc", 22)),
    ("me@mail.com@host:22", ("me@mail.com", "host", 22)),      # the LAST @ splits user from host
])
def test_parse_target_ok(text, expect):
    t = parse_target(text)
    assert (t.user, t.host, t.port) == expect


@pytest.mark.parametrize("text", ["", "box", "@box", "pat@", "pat@box:0", "pat@box:70000", "pat@box:x", "pat@bo x",
                                  "ssh://pat@box", "pat@[::1", "pat@[nope]", "pat@-bad", "pat@box:22:3"])
def test_parse_target_rejects(text):
    with pytest.raises(TargetError):
        parse_target(text)


def test_target_roundtrip_and_key():
    t = parse_target("pat@[::1]:2200")
    assert str(t) == "pat@[::1]:2200" and parse_target(str(t)) == t
    assert str(parse_target("pat@box:22")) == "pat@box" and t.key == "[::1]:2200"


# ── secrets and host keys ───────────────────────────────────────────────────
def test_credentials_never_show_secrets():
    c = SC.Credentials(password="hunter2", key_path="/k", passphrase="phrase!")
    text = repr(c) + str(c)
    assert "hunter2" not in text and "phrase!" not in text and "/k" in text
    assert SC._scrub("login with hunter2 failed", c.secrets()) == "login with *** failed"


def test_hostkey_store_tofu_and_change(tmp_path):
    st = SC.HostKeyStore(tmp_path / "h.json")
    tg = Target("pat", "box", 22)
    with pytest.raises(SC.HostKeyUnknown) as e:
        st.check(tg, "ssh-ed25519", "SHA256:aaa")
    assert e.value.fingerprint == "SHA256:aaa"
    st.trust(tg, "ssh-ed25519", "SHA256:aaa")
    st.check(tg, "ssh-ed25519", "SHA256:aaa")                       # the trusted key passes
    with pytest.raises(SC.HostKeyChanged):
        st.check(tg, "ssh-ed25519", "SHA256:bbb")                   # a different key is refused
    assert st.check is not None and st.get(tg)["fingerprint"] == "SHA256:aaa"      # ...and not replaced
    if os.name == "posix":
        assert (tmp_path / "h.json").stat().st_mode & 0o077 == 0     # private file
    assert st.forget(tg) and st.get(tg) is None and not st.forget(tg)


def test_missing_paramiko_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(SC, "paramiko_available", lambda: False)
    with pytest.raises(SC.MissingParamiko) as e:
        SC.make_transport(Target("a", "b"), SC.Credentials(password="x"), SC.HostKeyStore(Path(tempfile.mkdtemp()) / "h"))
    assert "pip install" in str(e.value) and "paramiko" in str(e.value)


# ── the runner (remoteagent.py): stdlib only, no network ────────────────────
def agent(**cfg):
    cfg.setdefault("dry_run", True)
    return RA.Agent(cfg, sleep=lambda s: None)


def test_agent_imports_only_the_standard_library():
    tree = Path(RA.__file__).read_text()
    for banned in ("import requests", "import yaml", "import paramiko", "from legalprivacy", "import legalprivacy"):
        assert banned not in tree


def test_agent_dry_run_emits_json_lines_and_counts(capsys):
    a = agent(actions_per_hour=60)
    a.run(max_steps=40)
    out = [json.loads(ln) for ln in capsys.readouterr().out.splitlines()]
    kinds = {r["kind"] for r in out}
    assert {"info", "stats"} <= kinds and kinds & {"visit", "dns", "search"}
    assert all({"t", "lvl", "kind", "msg"} <= r.keys() for r in out)
    assert sum(a.counts[k] for k in ("visit", "search", "dns", "download")) >= 20


def test_agent_two_machines_never_share_a_schedule():
    cfg = {"dry_run": True, "actions_per_hour": 30, "domains": [f"d{i}.org" for i in range(200)]}
    a, b = RA.Agent(dict(cfg)), RA.Agent(dict(cfg))
    def sig(x):
        return round(x.rate, 6), round(x.phase, 6), round(x.burst_mean, 6), tuple(x.lanes.items()), x.max_per_hour
    assert sig(a) != sig(b) and a.domains != b.domains          # own rhythm, own daily peak, own lane mix, own order


def test_agent_respects_hard_ceilings():
    a = agent(actions_per_hour=10**6, max_mb_per_day=10**6, max_download_mb=10**6)
    assert a.max_per_hour <= RA.MAX_ACTIONS_PER_HOUR and a.max_mb_day <= RA.MAX_MB_PER_DAY
    assert a.max_download <= RA.MAX_DOWNLOAD_MB * 1_000_000


def test_agent_hourly_budget_stops_actions():
    t = [1000.0]
    a = RA.Agent({"dry_run": True, "actions_per_hour": 5}, sleep=lambda s: None, now=lambda: t[0])
    n = 0
    while a.step() and n < 500:
        n += 1
        t[0] += 1                                                # only seconds pass: the hour window stays full
    assert 0 < n <= a.max_per_hour + 1
    assert a.step() is False
    t[0] += 3700                                                 # an hour later it may act again
    assert a.step() is True


def test_agent_daily_byte_budget():
    a = RA.Agent({"dry_run": True, "max_mb_per_day": 1, "actions_per_hour": 600}, sleep=lambda s: None)
    a.day_bytes = a.max_mb_day * 1_000_000 + 1
    assert a.step() is False


def test_agent_lanes_can_be_switched_off():
    a = agent(lanes={"visit": False, "search": False, "dns": True, "download": False})
    assert set(a.lanes) == {"dns"}
    a2 = agent(lanes={"visit": False, "search": False, "dns": False, "download": False})
    assert a2.lanes == {} and a2.step() is False


def test_agent_identity_rotates_after_a_few_visits():
    a = agent(user_agents=[f"UA/{i}" for i in range(20)])
    first = a.ident
    a.visits_left = 1
    a._after_visit()
    assert a.ident is not first and a.visits_left >= 15


@pytest.mark.parametrize("ip,ok", [("8.8.8.8", True), ("1.1.1.1", True), ("127.0.0.1", False), ("10.1.2.3", False),
                                   ("192.168.0.9", False), ("172.16.5.5", False), ("169.254.169.254", False),
                                   ("::1", False), ("fe80::1", False), ("0.0.0.0", False), ("224.0.0.1", False),
                                   ("::ffff:127.0.0.1", False), ("100.64.0.1", False), ("nonsense", False)])
def test_only_public_addresses(ip, ok):
    assert RA.is_public_address(ip) is ok


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "10.0.0.5", "printer.local", "router.lan", "[::1]", "",
                                  "metadata.internal"])
def test_host_is_safe_refuses_private_names(host):
    assert RA.host_is_safe(host) is False


def test_net_refuses_private_targets_and_redirects():
    n = RA.Net(lambda: "UA")
    with pytest.raises(urllib.error.URLError):
        n.fetch("http://127.0.0.1:1/", {"ua": "x", "lang": "en"})
    with pytest.raises(urllib.error.URLError):
        n.download("http://192.168.1.1/f.zip", {"ua": "x", "lang": "en"}, 1000)
    with pytest.raises(urllib.error.URLError):
        RA._SafeRedirect().redirect_request(types.SimpleNamespace(), None, 302, "Found", {}, "http://10.0.0.1/secret")
    with pytest.raises(urllib.error.URLError):
        RA._SafeRedirect().redirect_request(types.SimpleNamespace(), None, 302, "Found", {}, "file:///etc/passwd")


def test_parse_page_and_search_unwrapping():
    html = '<a href="/a">x</a><a href="https://o.org/b.pdf">y</a><script src="/s.js"></script><link rel="stylesheet" href="c.css"><a href="mailto:x@y">m</a>'
    links, assets = RA.parse_page(html, "https://s.example.com/p/")
    assert "https://s.example.com/a" in links and "https://o.org/b.pdf" in links and not any("mailto" in x for x in links)
    assert "https://s.example.com/s.js" in assets and "https://s.example.com/p/c.css" in assets
    assert RA.unwrap_result_link("/url?q=https://real.org/x&sa=U") == "https://real.org/x"
    assert RA.unwrap_result_link("//duckduckgo.com/l/?uddg=https://real.org/y") == "https://real.org/y"


def test_download_never_writes_to_disk_and_respects_the_cap(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    a = agent(download_urls=["https://files.example.org/big.zip"], max_download_mb=1)
    a.lanes = {"download": 1.0}
    before = set(tmp_path.iterdir())
    for _ in range(5):
        a.do_download()
    assert a.counts["download"] == 5 and set(tmp_path.iterdir()) == before
    _s, n, _d = a.net.download("https://x", a.ident, a.max_download)
    assert n <= a.max_download


def test_browser_commands_are_headless_with_a_throwaway_profile():
    c = RA.browser_command("/usr/bin/chromium", "https://a.org/", "/tmp/p", "/tmp/s.png")
    assert "--headless" in " ".join(c) and "--user-data-dir=/tmp/p" in c and "--no-sandbox" not in c and c[-1] == "https://a.org/"
    f = RA.browser_command("/usr/bin/firefox", "https://a.org/", "/tmp/p", "/tmp/s.png")
    assert "--headless" in f and "--screenshot" in f and "--profile" in f and "/tmp/p" in f


def test_browser_visit_cleans_up_and_reports_failure(monkeypatch):
    made = []
    real = tempfile.mkdtemp

    def mk(*a, **k):
        d = real(*a, **k)
        made.append(d)
        return d
    monkeypatch.setattr(RA.tempfile, "mkdtemp", mk)
    monkeypatch.setattr(RA.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=1, stderr=b"boom\n"))
    ok, why = RA.browser_visit("/bin/chromium", "https://a.org/")
    assert not ok and why == "boom" and made and not os.path.exists(made[0])
    monkeypatch.setattr(RA.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=0, stderr=b""))
    assert RA.browser_visit("/bin/chromium", "https://a.org/") == (True, "")


def test_headless_without_a_browser_uses_plain_http():
    a = RA.Agent({"dry_run": True}, browser=None, sleep=lambda s: None)
    assert a.browser is None and a.browser_share == 0.0
    a.do_visit()
    assert a.counts["visit"] >= 1


def test_probe_reports_machine(monkeypatch):
    monkeypatch.setattr(RA, "find_browser", lambda *a: None)
    p = RA.probe()
    assert p["kind"] == "probe" and p["python"] and "browser" in p


def _run_agent(args, stdin=None, cwd=None, timeout=30):
    return subprocess.run([sys.executable, RA.__file__, *args], input=stdin, capture_output=True, text=True,
                          timeout=timeout, cwd=cwd)


def test_agent_script_runs_stops_on_stdin_eof_and_removes_its_pid_file(tmp_path):
    (tmp_path / "settings.json").write_text(json.dumps({"dry_run": True, "time_scale": 5000, "actions_per_hour": 600}))
    p = subprocess.Popen([sys.executable, RA.__file__, "run", "settings.json"], cwd=tmp_path, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, text=True)
    first = json.loads(p.stdout.readline())
    assert first["msg"] == "runner started" and (tmp_path / "agent.pid").read_text() == str(p.pid)
    time.sleep(0.5)
    p.stdin.close()                                               # the SSH connection ended
    out = p.stdout.read()
    p.wait(timeout=20)
    assert p.returncode == 0 and "runner stopped" in out and not (tmp_path / "agent.pid").exists()
    assert sorted(x.name for x in tmp_path.iterdir()) == ["settings.json"]      # it wrote nothing else


def test_agent_script_stop_line_and_stop_command(tmp_path):
    (tmp_path / "settings.json").write_text(json.dumps({"dry_run": True, "time_scale": 5000}))
    p = subprocess.Popen([sys.executable, RA.__file__, "run", "settings.json"], cwd=tmp_path, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, text=True)
    p.stdout.readline()
    p.stdin.write("stop\n")
    p.stdin.flush()
    out, _ = p.communicate(timeout=20)
    assert "runner stopped" in out
    # `agent.py stop <folder>` sends SIGTERM to the pid in the file
    (tmp_path / "settings.json").write_text(json.dumps({"dry_run": True}))
    p = subprocess.Popen([sys.executable, RA.__file__, "run", "settings.json"], cwd=tmp_path, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, text=True)
    p.stdout.readline()
    r = _run_agent(["stop", str(tmp_path)])
    assert json.loads(r.stdout)["stopped"] is True
    p.communicate(timeout=20)
    assert p.returncode == 0
    assert json.loads(_run_agent(["stop", str(tmp_path)]).stdout)["stopped"] is False      # nothing recorded now


def test_agent_script_probe_and_usage():
    r = _run_agent(["probe"])
    assert json.loads(r.stdout)["kind"] == "probe"
    assert _run_agent(["bogus"]).returncode == 2


def test_agent_file_is_python37_compatible_syntax():
    import ast
    src = Path(RA.__file__).read_text()
    tree = ast.parse(src, feature_version=(3, 7))
    assert tree                                                    # no match statements, no 3.8+ only syntax in the file
    assert ":=" not in src


# ── settings ────────────────────────────────────────────────────────────────
def test_settings_validation():
    s = RR.RemoteSettings.from_dict({"intensity": "busy", "max_mb_per_day": 10**9, "download_urls": "https://a.org/x\n\nhttps://b.org/y"})
    assert s.intensity == "busy" and s.max_mb_per_day == RA.MAX_MB_PER_DAY and len(s.download_urls) == 2
    for bad in ({"intensity": "wild"}, {"browser": "x"}, {"download_urls": ["http://a.org/x"]}, {"max_mb_per_day": "lots"},
                {"visits": False, "searches": False, "dns": False, "downloads": False}):
        with pytest.raises(RR.RemoteConfigError):
            RR.RemoteSettings.from_dict(bad)


# ── the manager with a fake transport ───────────────────────────────────────
def test_add_requires_authorisation_and_valid_input(tmp_path):
    mgr, _ = manager(tmp_path)
    for kw, frag in [({"authorised": False}, "authorised"), ({"target": "nonsense"}, "user"),
                     ({"auth": "key", "key_path": ""}, "key"), ({"password": ""}, "password"), ({"auth": "token"}, "password or")]:
        with pytest.raises(RR.RemoteConfigError) as e:
            add(mgr, **kw)
        assert frag in str(e.value).lower()
    add(mgr)
    with pytest.raises(RR.RemoteConfigError):
        add(mgr)                                                    # the same machine twice
    assert len(mgr.machines) == 1


def test_secrets_are_never_saved_snapshotted_or_logged(tmp_path):
    mgr, _ = manager(tmp_path, stream_lines=['{"t":1,"lvl":"info","kind":"visit","msg":"leaks s3cret-pw here"}',
                                              "shell says s3cret-pw"])
    snap = add(mgr, passphrase="my-passphrase")
    mid = snap["id"]
    assert snap["has_secret"] is True
    text = (tmp_path / "machines.json").read_text()
    assert "s3cret-pw" not in text and "my-passphrase" not in text
    trust_it(mgr, mid)
    mgr.start(mid)
    m = mgr.get(mid)
    assert wait_for(lambda: m.state in ("error", "idle", "running") and len(m.log) >= 3)
    wait_for(lambda: m.thread is not None and not m.thread.is_alive())
    blob = json.dumps(mgr.snapshot()) + json.dumps(mgr.log.since(0))              # the app's Live Log too
    assert "s3cret-pw" not in blob and "my-passphrase" not in blob
    assert "s3cret-pw" not in "\n".join(m.log) and "***" in "\n".join(m.log)


def test_key_login_saves_the_path_not_the_key(tmp_path):
    mgr, _ = manager(tmp_path)
    add(mgr, auth="key", password=None, key_path="~/.ssh/id_ed25519", passphrase="pp")
    saved = json.loads((tmp_path / "machines.json").read_text())
    assert saved[0]["key_path"] == "~/.ssh/id_ed25519" and "pp" not in json.dumps(saved)
    mgr2 = RR.RemoteManager(EventLog(), pools=pools, transport_factory=F.factory(), path=tmp_path / "machines.json",
                            store=SC.HostKeyStore(tmp_path / "hostkeys.json"))
    m = next(iter(mgr2.machines.values()))                          # reloaded after a restart: list kept, secrets gone
    assert str(m.target) == "pat@box.lan:2222" and m.key_path == "~/.ssh/id_ed25519" and m.creds.passphrase is None
    snap = mgr2.snapshot()["machines"][0]
    assert snap["has_secret"] is True and snap["auth"] == "key"      # a key path alone can log in (no passphrase)


def test_password_machine_after_restart_asks_again(tmp_path):
    mgr, _ = manager(tmp_path)
    add(mgr)
    mgr2 = RR.RemoteManager(EventLog(), pools=pools, transport_factory=F.factory(), path=tmp_path / "machines.json",
                            store=SC.HostKeyStore(tmp_path / "hostkeys.json"))
    mid = next(iter(mgr2.machines))
    assert mgr2.snapshot()["machines"][0]["has_secret"] is False
    with pytest.raises(RR.RemoteConfigError) as e:
        mgr2.start(mid)
    assert "password again" in str(e.value)
    r = mgr2.test(mid)
    assert r["status"] == "error" and "password again" in r["message"]


def test_first_connection_needs_the_fingerprint_confirmed(tmp_path):
    mgr, store = manager(tmp_path)
    mid = add(mgr)["id"]
    r = mgr.test(mid)
    t = F.FakeTransport.instances[-1]
    assert r["status"] == "untrusted" and r["fingerprint"] == "SHA256:FAKEKEY1" and r["key_type"] == "ssh-ed25519"
    assert not t.commands and not t.files                           # nothing was run or sent
    pk = mgr.snapshot()["machines"][0]["pending_key"]
    assert pk["fingerprint"] == "SHA256:FAKEKEY1" and pk["check"].endswith("ssh_host_ed25519_key.pub")
    with pytest.raises(RR.RemoteConfigError):
        mgr.trust(mid, "SHA256:SOMETHINGELSE")                      # must match what the machine is offering
    assert store.get(parse_target("pat@box.lan:2222")) is None
    mgr.trust(mid, "SHA256:FAKEKEY1")
    ok = mgr.test(mid)
    assert ok["ok"] and ok["os"] == "Linux" and ok["python_path"] == "/usr/bin/python3" and ok["browser"] == "chromium"


@pytest.mark.parametrize("ktype,cmd", [("ssh-ed25519", "ssh_host_ed25519_key.pub"), ("ecdsa-sha2-nistp256", "ssh_host_ecdsa_key.pub"),
                                       ("ssh-rsa", "ssh_host_rsa_key.pub")])
def test_host_key_check_command_names_the_right_file(ktype, cmd):
    assert RR.host_key_check_command(ktype) == "ssh-keygen -lf /etc/ssh/" + cmd


def test_start_refuses_an_unconfirmed_host_without_sending_anything(tmp_path):
    mgr, _ = manager(tmp_path)
    mid = add(mgr)["id"]
    mgr.start(mid)
    m = mgr.get(mid)
    assert wait_for(lambda: m.thread is not None and not m.thread.is_alive())
    assert m.state == "needs_trust" and m.pending and not any(t.files or t.commands for t in F.FakeTransport.instances)


def test_changed_host_key_is_refused_and_never_silently_accepted(tmp_path):
    mgr, store = manager(tmp_path, key=("ssh-ed25519", "SHA256:EVIL"))
    mid = add(mgr)["id"]
    store.trust(parse_target("pat@box.lan:2222"), "ssh-ed25519", "SHA256:GOOD")
    r = mgr.test(mid)
    assert r["status"] == "changed" and "NOT the one you trusted" in r["message"]
    with pytest.raises(RR.RemoteConfigError):
        mgr.trust(mid, "SHA256:EVIL")                               # nothing pending: a changed key cannot be trusted
    mgr.start(mid)
    m = mgr.get(mid)
    assert wait_for(lambda: m.thread is not None and not m.thread.is_alive())
    assert m.state == "error" and "NOT the one you trusted" in m.error
    assert store.get(parse_target("pat@box.lan:2222"))["fingerprint"] == "SHA256:GOOD"
    assert not any(t.files or t.commands for t in F.FakeTransport.instances)
    mgr.forget_key(mid)                                              # only the person can do this, deliberately
    assert store.get(parse_target("pat@box.lan:2222")) is None


def test_auth_failure_message(tmp_path):
    mgr, _ = manager(tmp_path, fail_auth=True)
    mid = add(mgr)["id"]
    trust_it_manual(mgr, mid)
    r = mgr.test(mid)
    assert r["status"] == "error" and "refused the login" in r["message"] and "s3cret-pw" not in r["message"]


def trust_it_manual(mgr, mid):
    mgr.store.trust(mgr.get(mid).target, "ssh-ed25519", "SHA256:FAKEKEY1")


def test_missing_python_is_explained(tmp_path):
    mgr, _ = manager(tmp_path, probe=F.LINUX_NO_PYTHON)
    mid = add(mgr)["id"]
    trust_it_manual(mgr, mid)
    r = mgr.test(mid)
    assert r["status"] == "error" and "Python 3 is not installed" in r["message"]


def test_start_uploads_runner_and_private_settings_then_streams_the_log(tmp_path):
    lines = [json.dumps({"t": time.time(), "lvl": "info", "kind": "info", "msg": "runner started"}),
             json.dumps({"t": time.time(), "lvl": "info", "kind": "visit", "msg": "https://a.org/ -> 200 (12 KB)"}),
             json.dumps({"t": time.time(), "lvl": "warn", "kind": "search", "msg": "limited"}),
             json.dumps({"t": time.time(), "lvl": "info", "kind": "stats", "msg": "status",
                         "counts": {"visit": 4, "search": 2, "dns": 9, "download": 1, "error": 0}, "mb": 1.5})]
    mgr, _ = manager(tmp_path, stream_lines=lines, hold=True)
    mid = add(mgr)["id"]
    trust_it_manual(mgr, mid)
    mgr.start(mid)
    m = mgr.get(mid)
    assert wait_for(lambda: m.counts.get("visit") == 4)
    t = F.FakeTransport.instances[-1]
    assert m.state == "running"
    agent_path, settings_path = "/home/pat/.cache/legalprivacy/agent.py", "/home/pat/.cache/legalprivacy/settings.json"
    assert t.files[agent_path] == (b"# agent", 0o600) and t.files[settings_path][1] == 0o600
    cfg = json.loads(t.files[settings_path][0])
    assert "password" not in json.dumps(cfg).lower() and "s3cret" not in json.dumps(cfg)
    assert any("mkdir -p /home/pat/.cache/legalprivacy" in c and "chmod 700" in c and "umask 077" in c for c in t.commands)
    assert t.commands[-1] == "cd /home/pat/.cache/legalprivacy && exec /usr/bin/python3 agent.py run settings.json"
    snap = mgr.snapshot()["machines"][0]
    assert any("visit: https://a.org/ -> 200" in ln for ln in snap["log"]) and any("! " in ln and "limited" in ln for ln in snap["log"])
    assert RR.counts_text(snap) == "visits 4 · searches 2 · DNS 9 · downloads 1 · errors 0 · 1.5 MB"
    mgr.stop(mid)
    assert t.streams[0].written == ["stop\n"] and m.state == "idle" and t.closed


def test_runner_dying_on_its_own_shows_an_error(tmp_path):
    mgr, _ = manager(tmp_path, stream_lines=["python3: can't open file 'agent.py'"], hold=False)
    mid = add(mgr)["id"]
    trust_it_manual(mgr, mid)
    mgr.start(mid)
    m = mgr.get(mid)
    assert wait_for(lambda: m.state == "error")
    assert "stopped on its own" in m.error and any("can't open file" in ln for ln in m.log)


def test_stop_falls_back_to_asking_the_machine_to_stop_the_runner(tmp_path, monkeypatch):
    mgr, _ = manager(tmp_path, stream_lines=[], hold=True)
    mid = add(mgr)["id"]
    trust_it_manual(mgr, mid)
    mgr.start(mid)
    m = mgr.get(mid)
    assert wait_for(lambda: m.state == "running")
    stream = F.FakeTransport.instances[-1].streams[0]
    stream.write = lambda text: stream.written.append(text)        # deaf to "stop"
    real_join = m.thread.join
    monkeypatch.setattr(m.thread, "join", lambda timeout=None: real_join(timeout=0.2))
    mgr.stop(mid)
    t = F.FakeTransport.instances[-1]
    assert any(c.endswith("agent.py stop /home/pat/.cache/legalprivacy") for c in t.commands) and stream.closed


def test_remove_deletes_the_remote_folder_and_forgets_the_machine(tmp_path):
    mgr, store = manager(tmp_path)
    mid = add(mgr)["id"]
    trust_it_manual(mgr, mid)
    r = mgr.remove(mid)
    assert r["removed"] and r["wiped"] is True
    t = F.FakeTransport.instances[-1]
    wipe = [c for c in t.commands if "rm -rf" in c][0]
    assert "*/.cache/legalprivacy)" in wipe and "rm -rf -- /home/pat/.cache/legalprivacy" in wipe
    assert not mgr.machines and json.loads((tmp_path / "machines.json").read_text()) == []
    assert store.get(parse_target("pat@box.lan:2222")) is None


def test_remove_without_a_password_says_the_folder_was_not_deleted(tmp_path):
    mgr, _ = manager(tmp_path)
    add(mgr)
    mgr2 = RR.RemoteManager(EventLog(), pools=pools, transport_factory=F.factory(), path=tmp_path / "machines.json",
                            store=SC.HostKeyStore(tmp_path / "hostkeys.json"))
    r = mgr2.remove(next(iter(mgr2.machines)), wipe=True)
    assert r["wiped"] is False and "NOT deleted" in r["note"] and not mgr2.machines


def test_every_machine_gets_its_own_random_settings(tmp_path):
    mgr, _ = manager(tmp_path)
    a = mgr.get(add(mgr, "pat@a.lan")["id"])
    b = mgr.get(add(mgr, "pat@b.lan")["id"])
    cfgs = [mgr.build_settings(m) for m in (a, a, b, b)]
    assert len({json.dumps(c, sort_keys=True) for c in cfgs}) == 4           # even the same machine differs each start
    assert len({tuple(c["domains"][:5]) for c in cfgs}) == 4 and len({round(c["actions_per_hour"], 4) for c in cfgs}) == 4
    for c in cfgs:
        assert 120 <= len(c["domains"]) <= 260 and 60 <= len(c["queries"]) <= 140 and 2 <= len(c["user_agents"]) <= 4
        assert c["lanes"] == {"visit": True, "search": True, "dns": True, "download": True}


def test_configure_only_when_stopped_and_persists(tmp_path):
    mgr, _ = manager(tmp_path, hold=True)
    mid = add(mgr)["id"]
    snap = mgr.configure(mid, {"intensity": "light", "dns": False})
    assert snap["settings"]["intensity"] == "light" and snap["settings"]["dns"] is False
    assert json.loads((tmp_path / "machines.json").read_text())[0]["settings"]["intensity"] == "light"
    trust_it_manual(mgr, mid)
    mgr.start(mid)
    assert wait_for(lambda: mgr.get(mid).state == "running")
    with pytest.raises(RR.RemoteConfigError):
        mgr.configure(mid, {"intensity": "busy"})
    mgr.stop(mid)


def test_unknown_machine_and_double_start(tmp_path):
    mgr, _ = manager(tmp_path, hold=True)
    with pytest.raises(RR.RemoteConfigError):
        mgr.start("nope")
    mid = add(mgr)["id"]
    trust_it_manual(mgr, mid)
    mgr.start(mid)
    assert wait_for(lambda: mgr.get(mid).state == "running")
    with pytest.raises(RR.RemoteConfigError):
        mgr.start(mid)
    mgr.stop_all()
    assert mgr.get(mid).state == "idle"


def test_windows_machine_detection_and_commands():
    class T(F.FakeTransport):
        def run(self, command, timeout=30.0):
            self.commands.append(command)
            if "uname" in command:
                return 1, "", "'uname' is not recognized"
            return 0, "C:\\Users\\pat\\AppData\\Local\nC:\\Python312\\python.exe\nC:\\Program Files\\Google\\Chrome\\chrome.exe\n", ""
    t = T(Target("pat", "win"), SC.Credentials(password="x"), None)
    plat, info = RR.detect(t)
    assert isinstance(plat, RR.WindowsPlatform) and info["os"] == "Windows" and info["browser"] == "chrome.exe"
    assert plat.folder == "C:\\Users\\pat\\AppData\\Local\\legalprivacy"
    assert plat.sftp(plat.join(plat.folder, "agent.py")) == "/C:/Users/pat/AppData/Local/legalprivacy/agent.py"
    assert plat.start() == 'cd /d "C:\\Users\\pat\\AppData\\Local\\legalprivacy" && "C:\\Python312\\python.exe" agent.py run settings.json'
    assert "rmdir /s /q" in plat.wipe() and "legalprivacy" in plat.wipe()


def test_unknown_system_is_explained():
    class T(F.FakeTransport):
        def run(self, command, timeout=30.0):
            return 1, "weird", ""
    with pytest.raises(SC.SSHError) as e:
        RR.detect(T(Target("pat", "x"), SC.Credentials(), None))
    assert "not a system" in str(e.value)


def test_posix_commands_quote_odd_home_folders():
    p = RR.Platform("/home/o'brien dir", "/usr/bin/python3")
    cmd = p.start()
    assert "'/home/o'\"'\"'brien dir/.cache/legalprivacy'" in cmd
    assert "legalprivacy" in p.wipe() and "*/.cache/legalprivacy)" in p.wipe()


# ── the real transport against a real (loopback) SSH server ─────────────────
@pytest.fixture
def ssh_server():
    pytest.importorskip("paramiko")
    with F.LoopbackSSH() as srv:
        yield srv


def real_transport(srv, store, creds, trusted=None):
    return SC.ParamikoTransport(Target(srv.user, "127.0.0.1", srv.port), creds, store, trusted)


@needs_paramiko
def test_real_ssh_host_key_is_checked_before_any_password_is_sent(ssh_server, tmp_path):
    srv, store = ssh_server, SC.HostKeyStore(tmp_path / "h.json")
    t = real_transport(srv, store, SC.Credentials(password=srv.password))
    with pytest.raises(SC.HostKeyUnknown) as e:
        t.connect()
    assert e.value.fingerprint == srv.fingerprint()
    assert srv.logins == 0 and not srv.commands                    # unknown host: nothing was authenticated or run
    t2 = real_transport(srv, store, SC.Credentials(password=srv.password), trusted=srv.fingerprint())
    t2.connect()                                                   # the person confirmed exactly this fingerprint
    code, out, _ = t2.run("echo hello; echo $HOME")
    assert code == 0 and out.split() == ["hello", srv.home]
    t2.close()
    # a different server key on the same address is refused (and nothing is trusted)
    with F.LoopbackSSH(host_key=paramiko.ECDSAKey.generate()) as other:
        store.trust(Target(other.user, "127.0.0.1", other.port), "ecdsa-sha2-nistp256", "SHA256:old")
        t3 = real_transport(other, store, SC.Credentials(password=other.password))
        with pytest.raises(SC.HostKeyChanged):
            t3.connect()
        assert not other.commands


@needs_paramiko
def test_real_ssh_wrong_password_and_missing_key(ssh_server, tmp_path):
    srv, store = ssh_server, SC.HostKeyStore(tmp_path / "h.json")
    store.trust(Target(srv.user, "127.0.0.1", srv.port), "ecdsa-sha2-nistp256", srv.fingerprint())
    with pytest.raises(SC.AuthFailed) as e:
        real_transport(srv, store, SC.Credentials(password="wrong-pass-123")).connect()
    assert "wrong-pass-123" not in str(e.value)
    with pytest.raises(SC.AuthFailed):
        real_transport(srv, store, SC.Credentials(key_path=str(tmp_path / "nope"))).connect()


@needs_paramiko
def test_real_ssh_key_login_with_and_without_passphrase(ssh_server, tmp_path):
    srv, store = ssh_server, SC.HostKeyStore(tmp_path / "h.json")
    store.trust(Target(srv.user, "127.0.0.1", srv.port), "ecdsa-sha2-nistp256", srv.fingerprint())
    plain = srv.write_client_key()
    t = real_transport(srv, store, SC.Credentials(key_path=plain))
    t.connect()
    assert t.run("echo ok")[1].strip() == "ok"
    t.close()
    locked = srv.write_client_key("pass-123")
    with pytest.raises(SC.AuthFailed) as e:
        real_transport(srv, store, SC.Credentials(key_path=locked)).connect()
    assert "passphrase" in str(e.value)
    t = real_transport(srv, store, SC.Credentials(key_path=locked, passphrase="pass-123"))
    t.connect()
    t.close()


@needs_paramiko
def test_real_ssh_unreachable_host_message():
    s = __import__("socket").socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(SC.SSHError) as e:
        real_transport(types.SimpleNamespace(user="a", port=port), SC.HostKeyStore(Path(tempfile.mkdtemp()) / "h"),
                       SC.Credentials(password="x")).connect()
    assert "Could not connect" in str(e.value)


@needs_paramiko
def test_end_to_end_manager_runs_the_real_runner_over_real_ssh(ssh_server, tmp_path, monkeypatch):
    srv = ssh_server
    store = SC.HostKeyStore(tmp_path / "h.json")
    real = RR.RemoteManager(EventLog(), pools=pools, path=tmp_path / "m.json", store=store)
    monkeypatch.setattr(RR.RemoteManager, "build_settings", _fast)
    mid = real.add(f"{srv.user}@127.0.0.1:{srv.port}", auth="password", password=srv.password, authorised=True,
                   settings={"dry_run": True, "intensity": "busy"})["id"]
    r = real.test(mid)
    assert r["status"] == "untrusted" and r["fingerprint"] == srv.fingerprint()
    real.trust(mid, r["fingerprint"])
    r = real.test(mid)
    assert r["ok"] and r["os"] == "Linux" and r["python_path"]
    real.start(mid)
    m = real.get(mid)
    assert wait_for(lambda: m.state == "running" and any("runner started" in ln for ln in m.log), timeout=15)
    assert wait_for(lambda: any(": " in ln and ("dns" in ln or "visit" in ln or "search" in ln) for ln in m.log), timeout=15)
    folder = Path(srv.home) / ".cache" / "legalprivacy"
    assert (folder / "agent.py").read_bytes() == Path(RA.__file__).read_bytes()
    assert oct((folder / "agent.py").stat().st_mode & 0o777) == "0o600" and oct(folder.stat().st_mode & 0o777) == "0o700"
    assert (folder / "agent.pid").exists()
    assert "s3cret" not in json.dumps(real.snapshot()) and srv.password not in json.dumps(real.snapshot())
    real.stop(mid)
    assert m.state == "idle" and wait_for(lambda: not (folder / "agent.pid").exists())
    assert any("runner stopped" in ln for ln in m.log)
    res = real.remove(mid)
    assert res["wiped"] is True and not folder.exists()               # Remove deletes what it copied


def _fast(self, m, rng=None):
    cfg = _real_build(self, m, rng)
    cfg["time_scale"] = 3000
    return cfg


_real_build = RR.RemoteManager.build_settings


# ── the controller and the web API ──────────────────────────────────────────
@pytest.fixture
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    import http.client

    from legalprivacy.controller import Controller
    from legalprivacy.webui import UIServer
    ctl = Controller(str(tmp_path / "config.yaml"))
    ctl.remote = RR.RemoteManager(ctl.log, pools=pools, transport_factory=F.factory(hold=True), path=tmp_path / "rm.json",
                                  store=SC.HostKeyStore(tmp_path / "hk.json"), agent_source=lambda: b"# agent")
    srv = UIServer(ctl, port=0)
    threading.Thread(target=srv.httpd.serve_forever, daemon=True).start()

    def call(method, path, body=None, token=True):
        conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
        h = {"X-Token": srv.token} if token else {}
        if body is not None:
            h["Content-Type"] = "application/json"
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = conn.getresponse()
        raw = r.read()
        conn.close()
        return r.status, json.loads(raw or b"{}")
    yield ctl, call
    ctl.remote.stop_all()
    srv.httpd.shutdown()
    ctl.observer.stop()


def test_web_api_full_flow(web):
    ctl, call = web
    code, st = call("GET", "/api/remote")
    assert code == 200 and st["machines"] == [] and "authorised" in st["authorised_note"].lower()
    assert call("GET", "/api/remote", token=False)[0] == 401
    assert call("POST", "/api/remote/add", {"target": "pat@box:22", "password": "pw-1234"}, token=False)[0] == 401
    code, r = call("POST", "/api/remote/add", {"target": "pat@box:22", "password": "pw-1234"})
    assert code == 400 and "authorised" in r["error"]               # the ownership confirmation is required by the API too
    code, r = call("POST", "/api/remote/add", {"target": "pat@box:22", "password": "pw-1234", "authorised": True,
                                               "label": "Box", "settings": {"intensity": "light"}})
    assert code == 200 and r["target"] == "pat@box" and "pw-1234" not in json.dumps(r)
    mid = r["id"]
    code, r = call("POST", "/api/remote/test", {"id": mid})
    assert code == 200 and r["status"] == "untrusted"
    code, r2 = call("POST", "/api/remote/trust", {"id": mid, "fingerprint": "SHA256:wrong"})
    assert code == 400 and "not the one" in r2["error"]
    assert call("POST", "/api/remote/trust", {"id": mid, "fingerprint": r["fingerprint"]})[0] == 200
    code, r = call("POST", "/api/remote/test", {"id": mid})
    assert code == 200 and r["ok"] is True
    assert call("POST", "/api/remote/start", {"id": mid})[0] == 200
    assert wait_for(lambda: call("GET", "/api/remote")[1]["machines"][0]["state"] == "running")
    assert call("POST", "/api/remote/stop", {"id": mid})[0] == 200
    assert call("GET", "/api/remote")[1]["machines"][0]["state"] == "idle"
    assert call("POST", "/api/remote/configure", {"id": mid, "settings": {"intensity": "busy"}})[1]["settings"]["intensity"] == "busy"
    code, r = call("POST", "/api/remote/remove", {"id": mid, "wipe": True})
    assert code == 200 and r["removed"] and call("GET", "/api/remote")[1]["machines"] == []
    assert call("POST", "/api/remote/bogus", {})[0] == 404
    assert call("POST", "/api/remote/start", {"id": "gone"})[0] == 400


def test_panic_stops_remote_machines(web):
    ctl, call = web
    mid = call("POST", "/api/remote/add", {"target": "pat@box", "password": "pw", "authorised": True})[1]["id"]
    ctl.remote.store.trust(ctl.remote.get(mid).target, "ssh-ed25519", "SHA256:FAKEKEY1")
    call("POST", "/api/remote/start", {"id": mid})
    assert wait_for(lambda: ctl.remote.get(mid).state == "running")
    code, r = call("POST", "/api/panic", {"level": "soft"})
    assert code == 200 and ctl.remote.get(mid).state == "idle"


def test_controller_pools_give_different_slices_per_machine(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    from legalprivacy.controller import Controller
    ctl = Controller(str(tmp_path / "c.yaml"))
    try:
        a = ctl._remote_pools(random.Random(1), "Linux")
        b = ctl._remote_pools(random.Random(2), "Linux")
        assert a["domains"] and a["queries"] and a["user_agents"]
        assert all("X11; Linux" in u for u in a["user_agents"]) and a["domains"] != b["domains"]
        assert all("Windows" in u for u in ctl._remote_pools(random.Random(3), "Windows")["user_agents"])
    finally:
        ctl.observer.stop()


# ── web and native stay in step ─────────────────────────────────────────────
def test_web_and_native_ui_have_the_same_features():
    root = Path(__file__).parent.parent / "legalprivacy"
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    native = (root / "gui_remote.py").read_text(encoding="utf-8")
    for api in ("add", "test", "trust", "start", "stop", "remove", "forget_key"):
        assert f"/api/remote/{api}" in html or f"'{api}'" in html or f"remote_{api}" in html, api
        assert f"remote_{api}" in native or api in ("start", "stop", "forget_key"), api
    assert 'id="t-remote"' in html and 'data-t="remote"' in html and "RemoteTab" in (root / "gui.py").read_text()
    for needle in ("Test connection", "Start", "Stop", "Remove", "Forget host key", "Trust this fingerprint",
                   "Add machine", "authorised", "Private key", "Password", "Dry run", "memory only"):
        assert needle in html, ("web", needle)
        assert needle in native, ("native", needle)
    for st in RR.STATE_LABELS:
        label = RR.STATE_LABELS[st][0]
        assert label in html, label                                  # the web page words every state the same way
    assert "rm-" in html and "remote_state" in native


def test_dashboard_page_has_no_syntax_errors_in_remote_section():
    html = (Path(__file__).parent.parent / "legalprivacy" / "web" / "index.html").read_text(encoding="utf-8")
    assert html.count('id="remList"') == 1 and html.count("function renderRemote") == 1


# ── the native tab (needs Tk and a display; skipped otherwise) ──────────────
@pytest.fixture
def tk_app(tmp_path, monkeypatch):
    tk = pytest.importorskip("tkinter")
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    from legalprivacy import gui
    from legalprivacy.controller import Controller
    ctl = Controller(str(tmp_path / "p.yaml"))
    ctl.remote = RR.RemoteManager(ctl.log, pools=pools, transport_factory=F.factory(hold=True), path=tmp_path / "rm.json",
                                  store=SC.HostKeyStore(tmp_path / "hk.json"), agent_source=lambda: b"# agent")
    app = gui.build_app_class()(root, ctl, 0)

    def pump(seconds=1.0):
        end = time.time() + seconds
        while time.time() < end:
            root.update()
            time.sleep(0.02)
    app.pump_for = pump
    yield app
    try:
        app.closing = True
        ctl.remote.stop_all()
        ctl.observer.stop()
        ctl.relay.stop()
        root.destroy()
    except tk.TclError:
        pass


def test_native_remote_tab_add_test_trust_start_stop_remove(tk_app, monkeypatch):
    from tkinter import messagebox
    app = tk_app
    tab = next(t for t in app.tabs if t.title == "Remote")
    app.nb.select(app.tabs.index(tab))
    app.pump_for(0.3)
    tab.v_target.set("pat@box.lan:2222")
    tab.v_pass.set("pw-native")
    tab.add()                                                        # not ticked yet: refused with a message
    errors = []
    monkeypatch.setattr(app, "error", lambda what, exc: errors.append(str(exc)))
    app.pump_for(0.5)
    assert errors and "authorised" in errors[0]
    tab.v_own.set(True)
    tab.add()
    assert wait_for(lambda: (app.pump_for(0.1), len(tab._cards) == 1)[1], timeout=10)
    mid = next(iter(tab._cards))
    assert tab.v_pass.get() == "" and "pw-native" not in repr(tab._cards)
    tab.test(mid)
    assert wait_for(lambda: (app.pump_for(0.1), bool(tab._cards[mid].get("pending")))[1], timeout=10)
    assert "Check that its host key fingerprint is exactly SHA256:FAKEKEY1" in tab._cards[mid]["trust_lbl"].cget("text")
    tab.trust(mid)
    assert wait_for(lambda: (app.pump_for(0.1), tab._cards[mid].get("pending") is None)[1], timeout=10)
    tab.act("start", mid)
    assert wait_for(lambda: (app.pump_for(0.1), tab._cards[mid]["pill"].cget("text") == "Running")[1], timeout=10)
    tab.act("stop", mid)
    assert wait_for(lambda: (app.pump_for(0.1), tab._cards[mid]["pill"].cget("text") == "Stopped")[1], timeout=10)
    monkeypatch.setattr(messagebox, "askyesno", lambda *a, **k: True)
    tab.remove(mid)
    assert wait_for(lambda: (app.pump_for(0.1), not tab._cards)[1], timeout=10)
    assert not app.ctl.remote.machines
