"""Antivirus (ClamAV) manager: offline-first. Uses stub clamscan / freshclam / sigtool programs on PATH, a fake
psutil for the connection watcher, and checks that freshclam is NEVER run except by the explicit update."""
import json
import os
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from legalprivacy import av  # noqa: E402
from legalprivacy import leakcheck  # noqa: E402
from legalprivacy.config import ConfigError  # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="stub programs are POSIX scripts")
REPO = Path(__file__).resolve().parents[1]

NO_ISO = {"method": "none", "prefix": [], "isolated": False, "label": "Detection only (test)."}


def _stub(path: Path, body: str) -> None:
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


CLAMSCAN = '''
    import json, os, sys, time
    args = sys.argv[1:]
    log = os.environ.get("STUB_LOG")
    if log:
        open(log, "a").write(json.dumps({"tool": "clamscan", "args": args}) + "\\n")
    if "--version" in args:
        print("ClamAV 1.4.1/27000/Mon Jan  1 00:00:00 2024"); sys.exit(0)
    db = next((a.split("=", 1)[1] for a in args if a.startswith("--database=")), None)
    paths = [a for a in args if not a.startswith("--")]
    if not db or not os.path.exists(db):
        print("LibClamAV Error: cl_load(): No such file or directory"); sys.exit(2)
    files = [db] if os.path.isfile(db) else [os.path.join(db, f) for f in os.listdir(db)]
    if not files:
        print("ERROR: Can't open file or directory"); sys.exit(2)
    for f in files:
        if b"BAD" in open(f, "rb").read():
            print("LibClamAV Error: cl_load(): Malformed database"); sys.exit(2)
    time.sleep(float(os.environ.get("STUB_SLEEP", "0")))
    scanned = infected = 0
    todo = []
    for p in paths:
        if os.path.isdir(p):
            for r, _d, fs in os.walk(p):
                todo += [os.path.join(r, f) for f in fs]
        else:
            todo.append(p)
    for f in todo:
        if os.path.basename(f) == "unreadable":
            print(f + ": Permission denied. ERROR"); continue
        scanned += 1
        data = open(f, "rb").read()
        if b"EVIL" in data:
            print(f + ": Stub.Evil FOUND"); infected += 1
        elif (b"EICAR" + b"-STANDARD") in data:
            print(f + ": Eicar-Test-Signature FOUND"); infected += 1
    print("\\n----------- SCAN SUMMARY -----------")
    print("Known viruses: 5"); print("Engine version: 1.4.1"); print("Scanned directories: 1")
    print("Scanned files: %d" % scanned); print("Infected files: %d" % infected)
    print("Data scanned: 0.00 MB"); print("Time: 0.010 sec (0 m 0 s)")
    sys.exit(1 if infected else 0)
'''

FRESHCLAM = '''
    import json, os, sys
    args = sys.argv[1:]
    log = os.environ.get("STUB_LOG")
    if log:
        open(log, "a").write(json.dumps({"tool": "freshclam", "args": args}) + "\\n")
    if "--version" in args:
        print("ClamAV 1.4.1/27000/Mon Jan  1 00:00:00 2024"); sys.exit(0)
    d = next(a.split("=", 1)[1] for a in args if a.startswith("--datadir="))
    print("ClamAV update process started")
    print("daily.cvd updated (version: 27001)")
    open(os.path.join(d, "daily.cvd"), "wb").write(b"ClamAV-VDB:01 Jan 2024:27001:1:90:x:x:x:x:0" + b" " * 600)
'''

SIGTOOL = '''
    import json, os, sys
    args = sys.argv[1:]
    log = os.environ.get("STUB_LOG")
    if log:
        open(log, "a").write(json.dumps({"tool": "sigtool", "args": args}) + "\\n")
    if "--version" in args:
        print("ClamAV 1.4.1/27000/Mon Jan  1 00:00:00 2024"); sys.exit(0)
    f = next(a.split("=", 1)[1] for a in args if a.startswith("--info="))
    if b"BADSIG" in open(f, "rb").read():
        print("Verification: failed"); sys.exit(1)
    print("File: " + os.path.basename(f)); print("Version: 100"); print("Signatures: 5"); print("Verification OK.")
'''


def cvd(extra: bytes = b"") -> bytes:
    return b"ClamAV-VDB:01 Jan 2024:100:5:90:x:x:x:x:0" + b" " * 600 + extra


@pytest.fixture
def env(tmp_path, monkeypatch):
    home, binp = tmp_path / "home", tmp_path / "bin"
    home.mkdir()
    binp.mkdir()
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(home))
    monkeypatch.setenv("PATH", str(binp) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("STUB_LOG", str(tmp_path / "calls.jsonl"))
    monkeypatch.setattr(av, "EXTRA_DIRS", [])
    monkeypatch.setitem(av._DETECT, "val", None)
    monkeypatch.setitem(av._ISO, "val", dict(NO_ISO))
    av._INFO_CACHE.clear()
    for name, body in (("clamscan", CLAMSCAN), ("freshclam", FRESHCLAM), ("sigtool", SIGTOOL)):
        _stub(binp / name, body)

    class E:
        pass
    e = E()
    e.home, e.bin, e.calls, e.tmp = home, binp, tmp_path / "calls.jsonl", tmp_path

    def calls(tool=None):
        if not e.calls.exists():
            return []
        rows = [json.loads(x) for x in e.calls.read_text().splitlines()]
        return [r for r in rows if tool in (None, r["tool"])]
    e.log = calls

    def seed_db():
        (av.db_dir() / "daily.cvd").write_bytes(cvd())
    e.seed_db = seed_db
    return e


def scan_dir(env, name="scanme", evil=True):
    d = env.tmp / name
    d.mkdir()
    (d / "clean file.txt").write_text("hello")
    if evil:
        (d / "we ird: name.txt").write_text("EVIL payload")
    return d


# ── detection ──────────────────────────────────────────────────────────────
def test_detect_finds_tools_and_versions_and_reports_missing(env):
    d = av.detect(force=True)
    assert d["clamscan"]["path"].endswith("clamscan") and d["clamscan"]["version"].startswith("ClamAV 1.4.1")
    (env.bin / "sigtool").unlink()
    assert av.detect(force=True)["sigtool"]["path"] is None
    st = av.AvManager().state(redetect=True)
    assert st["found"] and st["install"] is None and st["can_update"] and not st["can_scan"]   # no signatures yet
    (env.bin / "clamscan").unlink()
    st = av.AvManager().state(redetect=True)
    assert not st["found"] and st["install"]["lines"] and "docs.clamav.net" in st["install"]["url"]


def test_install_hints_per_os():
    assert any("apt install clamav" in x for x in av.install_hint("linux")["lines"])
    assert any("dnf install clamav" in x for x in av.install_hint("linux")["lines"])
    assert any("brew install clamav" in x for x in av.install_hint("darwin")["lines"])
    assert any("docs.clamav.net" in x for x in av.install_hint("win32")["lines"])


def test_extra_dirs_are_searched_when_not_on_path(env, monkeypatch):
    extra = env.tmp / "elsewhere"
    extra.mkdir()
    _stub(extra / "freshclam", FRESHCLAM)
    (env.bin / "freshclam").unlink()
    monkeypatch.setattr(av, "EXTRA_DIRS", [str(extra)])
    assert av.find_tool("freshclam") == str(extra / "freshclam")


# ── freshclam only ever runs from the explicit update ──────────────────────
def test_freshclam_is_never_run_by_detect_state_scan_selftest_import_quarantine(env):
    m = av.AvManager()
    env.seed_db()
    d = scan_dir(env)
    av.detect(force=True)
    m.state(redetect=True)
    m.start_scan([str(d)])
    assert m.wait()
    m.start_selftest()
    assert m.wait()
    good = env.tmp / "main.cvd"
    good.write_bytes(cvd())
    m.start_import([str(good)])
    assert m.wait()
    m.quarantine(str(d / "we ird: name.txt"))
    m.state()
    assert env.log("freshclam") == []
    with pytest.raises(av.AvError):
        m.start_update(confirmed=False)                      # no confirmation, no freshclam
    assert env.log("freshclam") == []


def test_update_runs_freshclam_once_with_a_generated_minimal_config(env):
    m = av.AvManager()
    m.start_update(confirmed=True)
    assert m.wait()
    fc = env.log("freshclam")
    assert len(fc) == 1
    args = fc[0]["args"]
    db = av.db_dir()
    assert f"--datadir={db}" in args and any(a.startswith("--config-file=") for a in args)
    conf = Path(next(a.split("=", 1)[1] for a in args if a.startswith("--config-file="))).read_text()
    assert f"DatabaseDirectory {db}" in conf and "database.clamav.net" in conf
    assert (db / "daily.cvd").exists() and m.update_info["ok"]
    assert any("freshclam:" in x["text"] for x in m.state()["log"])           # output streamed into the log
    assert any("only time anything connects" in x["text"] for x in m.state()["log"])


def test_update_refuses_without_freshclam(env):
    (env.bin / "freshclam").unlink()
    with pytest.raises(av.AvError, match="freshclam is not installed"):
        av.AvManager().start_update(confirmed=True)


def test_controller_requires_the_confirmation_flag(env):
    from legalprivacy.controller import Controller
    c = Controller(str(env.tmp / "p.yaml"))
    with pytest.raises(ConfigError):
        c.av_action("update", {})
    with pytest.raises(ConfigError):
        c.av_action("update", {"confirmed": "yes"})
    with pytest.raises(ConfigError):
        c.av_action("nonsense", {})
    assert env.log("freshclam") == []
    assert "tools" in c.av_state()


# ── command construction and parsing ───────────────────────────────────────
def test_scan_command_uses_the_app_database_and_only_clamscan(env):
    env.seed_db()
    d = scan_dir(env)
    cmd = av.build_scan_cmd("/x/clamscan", av.db_dir(), [str(d)], ["unshare", "-rn"])
    assert cmd == ["unshare", "-rn", "/x/clamscan", f"--database={av.db_dir()}", "--recursive", "--infected", str(d)]
    m = av.AvManager()
    m.start_scan([str(d)])
    assert m.wait()
    c = env.log("clamscan")[-1]["args"]
    assert f"--database={av.db_dir()}" in c and "--recursive" in c and "--infected" in c and str(d) in c
    assert not any("clamdscan" in str(x) for x in env.log())


def test_paths_are_made_absolute_and_validated(env, monkeypatch):
    monkeypatch.chdir(env.tmp)
    (env.tmp / "-rf").write_text("x")
    assert av.validate_paths(["-rf"]) == [str(env.tmp / "-rf")]
    for bad in ([], [""], ["x\0y"], ["/definitely/not/here"], [5]):
        with pytest.raises(av.AvError):
            av.validate_paths(bad)
    with pytest.raises(av.AvError):
        av.validate_paths(["/tmp"] * 1 + [f"/tmp/{i}" for i in range(60)])


def test_parser_handles_spaces_colons_errors_and_summary():
    f = av.parse_line("/home/me/My Docs/a: b: c.exe: Win.Test.EICAR_HDB-1 FOUND\n")
    assert f == ("found", "/home/me/My Docs/a: b: c.exe", "Win.Test.EICAR_HDB-1")
    assert av.parse_line("C:\\Users\\me\\x: y.exe: Eicar-Test-Signature FOUND\r\n")[1:] == ("C:\\Users\\me\\x: y.exe", "Eicar-Test-Signature")
    assert av.parse_line("/a/b: Permission denied. ERROR")[0] == "error"
    assert av.parse_line("ERROR: Can't open file or directory")[0] == "error"
    assert av.parse_line("LibClamAV Error: cl_load(): nope")[0] == "error"
    assert av.parse_line("LibClamAV Warning: something")[0] == "warn"
    assert av.parse_line("/a/b: OK")[0] == "ok" and av.parse_line("/a/b: Empty file")[0] == "ok"
    assert av.parse_line("\n")[0] == "blank" and av.parse_line("----------- SCAN SUMMARY -----------")[0] == "other"
    assert av.parse_line("Infected files: 3") == ("summary", "infected_count", "3")
    out = av.parse_scan_output("/p/q: Sig.A FOUND\n/p/r: Can't access file ERROR\nScanned files: 9\nTime: 1.2 sec (0 m 1 s)\n")
    assert out["infected"] == [("/p/q", "Sig.A")] and len(out["errors"]) == 1
    assert out["summary"]["scanned"] == "9" and out["summary"]["time"].startswith("1.2")


# ── scanning end to end with a stub ────────────────────────────────────────
def test_scan_results_sizes_counts_and_proof(env):
    env.seed_db()
    d = scan_dir(env)
    (d / "unreadable").write_text("x")
    m = av.AvManager()
    m.start_scan([str(d)])
    assert m.wait()
    r = m.last_scan
    assert [i["path"] for i in r["infected"]] == [str(d / "we ird: name.txt")]
    assert r["infected"][0]["signature"] == "Stub.Evil" and r["infected"][0]["size"] == len("EVIL payload")
    assert r["exit_code"] == 1 and r["summary"]["scanned"] == "2" and any("unreadable" in e for e in r["errors"])
    assert r["connections"] == 0 and not r["not_offline"] and r["verdict"] == "Finished"
    assert m.proof["connections"] == 0
    assert json.loads((av.av_dir() / "last_scan.json").read_text())["infected"]       # saved for next launch
    assert av.AvManager().last_scan["infected"][0]["signature"] == "Stub.Evil"
    assert m.state()["scan"]["running"] is False


def test_scan_refused_without_signatures_or_scanner(env):
    m = av.AvManager()
    with pytest.raises(av.AvError, match="no signatures"):
        m.start_scan([str(env.tmp)])
    env.seed_db()
    (env.bin / "clamscan").unlink()
    av.detect(force=True)
    with pytest.raises(av.AvError, match="not installed"):
        m.start_scan([str(env.tmp)])


def test_stop_kills_a_running_scan(env, monkeypatch):
    env.seed_db()
    monkeypatch.setenv("STUB_SLEEP", "20")
    m = av.AvManager()
    m.start_scan([str(scan_dir(env))])
    time.sleep(0.6)
    assert m.state()["busy"] == "scan"
    t0 = time.time()
    m.stop()
    assert m.wait(10) and time.time() - t0 < 8
    assert m.last_scan["verdict"] == "Stopped by you" and m.last_scan["stopped"]


def test_only_one_job_at_a_time(env, monkeypatch):
    env.seed_db()
    monkeypatch.setenv("STUB_SLEEP", "5")
    m = av.AvManager()
    m.start_scan([str(scan_dir(env))])
    with pytest.raises(av.AvError, match="wait"):
        m.start_scan([str(env.tmp)])
    m.stop()
    m.wait(10)


# ── self-test ──────────────────────────────────────────────────────────────
def test_selftest_detects_and_deletes_its_temp_file(env):
    env.seed_db()
    m = av.AvManager()
    m.start_selftest()
    assert m.wait()
    s = m.selftest_info
    assert s["detected"] and s["signature"] == "Eicar-Test-Signature" and s["connections"] == 0
    assert list((av.av_dir() / "tmp").iterdir()) == []                  # the test file is gone
    assert m.proof["kind"] == "selftest"
    assert m.last_scan is None                                           # the results table is not overwritten


def test_selftest_says_so_when_not_detected(env, monkeypatch):
    env.seed_db()
    _stub(env.bin / "clamscan", CLAMSCAN.replace('b"EICAR" + b"-STANDARD"', 'b"NOPE" + b"NOPE"'))
    av.detect(force=True)
    m = av.AvManager()
    m.start_selftest()
    assert m.wait()
    assert m.selftest_info["detected"] is False and "NOT detected" in m.selftest_info["text"]


def test_eicar_string_is_correct_but_never_contiguous_in_any_project_file():
    s = av.eicar_text()
    assert len(s) == 68 and s.startswith("X5O!P%@AP") and s.endswith("H+H*")
    needles = [s, "7}$" + "EICAR-STANDARD", "EICAR-STANDARD" + "-ANTIVIRUS-TEST-FILE", "ANTIVIRUS-TEST-FILE" + "!$H+H*"]
    try:
        names = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=REPO, capture_output=True,
                               text=True, timeout=20, check=True).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        names = [str(p.relative_to(REPO)) for p in REPO.rglob("*") if p.is_file() and ".git" not in p.parts]
    checked = 0
    for n in names:
        p = REPO / n
        if not p.is_file():
            continue
        data = p.read_bytes()
        checked += 1
        for nd in needles:
            assert nd.encode() not in data, f"{n} contains the EICAR test string in one piece"
    assert checked > 50


# ── import: verification accepts and rejects ───────────────────────────────
def test_import_accepts_verified_files_and_rejects_the_rest(env):
    env.seed_db()
    m = av.AvManager()
    ok = env.tmp / "main.cvd"
    ok.write_bytes(cvd())
    badname = env.tmp / "evil.cvd"
    badname.write_bytes(cvd())
    nohdr = env.tmp / "bytecode.cvd"
    nohdr.write_bytes(b"x" * 2000)
    badsig = env.tmp / "daily.cld"
    badsig.write_bytes(cvd(b"BADSIG"))
    unloadable = env.tmp / "main.cld"
    unloadable.write_bytes(cvd(b"BAD"))
    tiny = env.tmp / "daily.cvd"
    tiny.write_bytes(b"ClamAV-VDB:")
    res = m.import_files([str(x) for x in (ok, badname, nohdr, badsig, unloadable, tiny, env.tmp / "missing.cvd")])
    assert res["imported"] == ["main.cvd"]
    reasons = {os.path.basename(r["path"]): r["reason"] for r in res["rejected"]}
    assert "only main, daily and bytecode" in reasons["evil.cvd"]
    assert "ClamAV-VDB" in reasons["bytecode.cvd"]
    assert "sigtool" in reasons["daily.cld"] and "could not load" in reasons["main.cld"]
    assert "too small" in reasons["daily.cvd"] and "missing.cvd" in reasons
    names = sorted(f["name"] for f in av.db_files())
    assert names == ["daily.cvd", "main.cvd"]                        # rejected files never reached the db folder
    assert not (av.av_dir() / "staging").exists()
    assert env.log("freshclam") == []


def test_import_replaces_the_other_form_of_the_same_database(env):
    (av.db_dir() / "main.cld").write_bytes(cvd())
    new = env.tmp / "main.cvd"
    new.write_bytes(cvd())
    assert av.AvManager().import_files([str(new)])["imported"] == ["main.cvd"]
    assert [f["name"] for f in av.db_files()] == ["main.cvd"]


def test_import_without_sigtool_still_requires_clamscan_to_load_it(env):
    (env.bin / "sigtool").unlink()
    av.detect(force=True)
    good, bad = env.tmp / "main.cvd", env.tmp / "daily.cvd"
    good.write_bytes(cvd())
    bad.write_bytes(cvd(b"BAD"))
    res = av.AvManager().import_files([str(good), str(bad)])
    assert res["imported"] == ["main.cvd"] and len(res["rejected"]) == 1


# ── isolation probe ────────────────────────────────────────────────────────
LO_ONLY = "Inter-|   Receive\n face |bytes\n    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
WITH_ETH = LO_ONLY + "  eth0: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n"


def test_isolation_probe_picks_the_first_method_that_really_removes_the_network():
    which = lambda n: f"/usr/bin/{n}"                                 # noqa: E731
    seen = []

    def run(cmd, timeout):
        seen.append(cmd)
        return (0, LO_ONLY) if cmd[0] == "/usr/bin/unshare" and cmd[1] == "--net" else (1, "denied")
    iso = av.probe_isolation(which, run, "linux")
    assert iso["method"] == "unshare-net" and iso["isolated"] and iso["prefix"] == ["/usr/bin/unshare", "--net"]
    assert "cannot reach the internet" in iso["label"] and len(seen) == 1


def test_isolation_probe_falls_back_to_user_namespace_then_firejail_then_none():
    which = lambda n: f"/usr/bin/{n}"                                 # noqa: E731

    def run_user(cmd, timeout):
        return (0, LO_ONLY) if "-rn" in cmd else (1, "Operation not permitted")
    assert av.probe_isolation(which, run_user, "linux")["method"] == "unshare-user-net"

    def run_fj(cmd, timeout):
        return (0, LO_ONLY) if cmd[0].endswith("firejail") else (1, "no")
    iso = av.probe_isolation(which, run_fj, "linux")
    assert iso["method"] == "firejail" and "--net=none" in iso["prefix"]

    iso = av.probe_isolation(which, lambda c, t: (1, "no"), "linux")
    assert iso["method"] == "none" and not iso["isolated"] and "Detection only" in iso["label"]


def test_isolation_probe_rejects_a_method_that_leaves_a_network_interface():
    which = lambda n: f"/usr/bin/{n}"                                 # noqa: E731
    iso = av.probe_isolation(which, lambda c, t: (0, WITH_ETH), "linux")
    assert iso["method"] == "none"


def test_isolation_probe_is_detection_only_on_other_systems():
    for plat, word in (("darwin", "macOS"), ("win32", "Windows")):
        iso = av.probe_isolation(lambda n: f"/x/{n}", lambda c, t: (0, LO_ONLY), plat)
        assert iso["method"] == "none" and word in iso["label"]


def test_isolation_probe_is_cached(monkeypatch):
    monkeypatch.setitem(av._ISO, "val", None)
    n = []
    monkeypatch.setattr(av, "probe_isolation", lambda *a, **k: n.append(1) or dict(NO_ISO))
    av.get_isolation()
    av.get_isolation()
    assert len(n) == 1
    av.get_isolation(force=True)
    assert len(n) == 2


def test_real_probe_returns_a_complete_answer():
    iso = av.probe_isolation()
    assert set(iso) == {"method", "prefix", "isolated", "label"} and iso["label"]


@pytest.mark.skipif(not sys.platform.startswith("linux") or not os.path.exists("/usr/bin/unshare"), reason="needs unshare")
def test_scan_runs_through_the_isolation_prefix_when_there_is_one(env, monkeypatch):
    env.seed_db()
    wrap = env.bin / "wrapper"
    _stub(wrap, 'import os, sys\nopen(os.environ["STUB_LOG"], "a").write(\'{"tool": "wrapper", "args": []}\\n\')\n'
                'os.execv(sys.argv[1], sys.argv[1:])\n')
    monkeypatch.setitem(av._ISO, "val", {"method": "unshare-net", "prefix": [str(wrap)], "isolated": True, "label": "x"})
    m = av.AvManager()
    m.start_scan([str(scan_dir(env))])
    assert m.wait()
    assert env.log("wrapper") and m.last_scan["isolated"] and m.last_scan["isolation"] == "unshare-net"


# ── the connection watcher, with a fake psutil ─────────────────────────────
class Addr:
    def __init__(self, ip, port):
        self.ip, self.port = ip, port


class Conn:
    def __init__(self, ip=None, port=0, pid=None):
        self.raddr = Addr(ip, port) if ip else ()
        self.pid = pid


class FakePs:
    class NoSuchProcess(Exception):
        pass

    class AccessDenied(Exception):
        pass

    def __init__(self, conns=(), names=None, deny=False, syswide=(), real_kill=False):
        self.conns, self.names, self.deny, self.syswide, self.real_kill = list(conns), names or {}, deny, list(syswide), real_kill
        self.killed = []

    def Process(self, pid):
        return FakePs.Proc(self, pid)

    def net_connections(self, kind="inet"):
        return self.syswide

    class Proc:
        def __init__(self, ps, pid):
            self.ps, self.pid = ps, pid

        def name(self):
            return self.ps.names.get(self.pid, "clamscan")

        def children(self, recursive=True):
            return [FakePs.Proc(self.ps, p) for p in self.ps.names if p != self.pid]

        def net_connections(self, kind="inet"):
            if self.ps.deny:
                raise FakePs.AccessDenied()
            return [c for c in self.ps.conns if c.pid in (None, self.pid)]

        def kill(self):
            self.ps.killed.append(self.pid)
            if self.ps.real_kill:
                os.kill(self.pid, 9)


def test_watch_ignores_loopback_and_unconnected_sockets():
    ps = FakePs([Conn("127.0.0.1", 1), Conn("::1", 2), Conn("::ffff:127.0.0.1", 3), Conn()])
    w = av.ConnWatch(10, ps=ps)
    assert w.poll_once() == [] and w.count == 0 and w.polls == 1


def test_watch_flags_a_remote_connection_in_a_child_and_a_dns_helper_once_each():
    ps = FakePs([Conn("93.184.216.34", 443, pid=11), Conn("192.168.1.5", 53, pid=10)], names={10: "clamscan", 11: "clamscan"})
    got = []
    w = av.ConnWatch(10, got.extend, ps=ps)
    new = w.poll_once()
    assert any("93.184.216.34:443" in x for x in new) and any("192.168.1.5:53" in x for x in new)
    assert w.poll_once() == [] and w.count == 2                        # reported once
    ps2 = FakePs(names={10: "clamscan", 12: "nslookup.exe"})
    w2 = av.ConnWatch(10, ps=ps2)
    assert w2.poll_once() == ["DNS helper started: nslookup"]


def test_watch_falls_back_to_the_system_wide_list_when_access_is_denied():
    ps = FakePs(deny=True, syswide=[Conn("1.2.3.4", 80, pid=10), Conn("5.6.7.8", 80, pid=999)])
    w = av.ConnWatch(10, ps=ps)
    new = w.poll_once()
    assert len(new) == 1 and "1.2.3.4:80" in new[0] and w.limited


def test_watch_without_psutil_reports_unavailable():
    w = av.ConnWatch(1, ps=None)
    w.ps, w.available = None, False
    assert w.poll_once() == []


def test_a_connection_marks_the_scan_not_offline_and_kills_the_scanner(env, monkeypatch):
    env.seed_db()
    monkeypatch.setenv("STUB_SLEEP", "15")
    ps = FakePs([Conn("93.184.216.34", 443)], real_kill=True)
    m = av.AvManager(ps=ps)
    t0 = time.time()
    m.start_scan([str(scan_dir(env))])
    assert m.wait(20)
    assert time.time() - t0 < 10                                       # killed long before the stub's 15 s sleep ended
    r = m.last_scan
    assert r["not_offline"] and r["connections"] >= 1 and "tried to connect" in r["verdict"]
    assert "93.184.216.34:443" in r["connection_details"][0] and ps.killed
    assert m.proof["connections"] >= 1
    assert any("NOT OFFLINE" in x["text"] and x["level"] == "warn" for x in m.state()["log"])


def test_a_clean_scan_with_a_watching_psutil_records_zero_connections(env):
    env.seed_db()
    m = av.AvManager(ps=FakePs())
    m.start_scan([str(scan_dir(env))])
    assert m.wait()
    assert m.last_scan["connections"] == 0 and m.last_scan["watch_polls"] >= 1


# ── quarantine ─────────────────────────────────────────────────────────────
def test_quarantine_is_explicit_reversible_and_limited_to_scan_results(env):
    env.seed_db()
    d = scan_dir(env)
    bad, clean = d / "we ird: name.txt", d / "clean file.txt"
    os.chmod(bad, 0o755)
    m = av.AvManager()
    m.start_scan([str(d)])
    assert m.wait()
    assert bad.exists()                                                # a scan never touches the files
    with pytest.raises(av.AvError, match="not in the latest scan"):
        m.quarantine(str(clean))
    q = m.quarantine(str(bad))
    assert not bad.exists() and clean.exists()
    blob = av.quarantine_dir() / q["id"] / "file.bin"
    assert blob.read_text() == "EVIL payload" and stat.S_IMODE(blob.stat().st_mode) == 0o600
    assert m.quarantine_list()[0]["original"] == str(bad) and m.state()["quarantine"][0]["signature"] == "Stub.Evil"
    m.restore(q["id"])
    assert bad.read_text() == "EVIL payload" and stat.S_IMODE(bad.stat().st_mode) == 0o755
    assert m.quarantine_list() == []


def test_restore_never_overwrites_and_delete_and_bad_ids_are_safe(env):
    env.seed_db()
    d = scan_dir(env)
    bad = d / "we ird: name.txt"
    m = av.AvManager()
    m.start_scan([str(d)])
    m.wait()
    q = m.quarantine(str(bad))
    bad.write_text("something new")
    with pytest.raises(av.AvError, match="already exists"):
        m.restore(q["id"])
    assert bad.read_text() == "something new" and m.quarantine_list()
    m.delete_quarantined(q["id"])
    assert m.quarantine_list() == []
    for bad_id in ("../x", "", "zzzzzzzzzzzz", "0" * 12):
        with pytest.raises(av.AvError):
            m.restore(bad_id)
        with pytest.raises(av.AvError):
            m.delete_quarantined(bad_id)


def test_quarantine_refuses_a_symlink(env):
    env.seed_db()
    d = scan_dir(env)
    m = av.AvManager()
    m.start_scan([str(d)])
    m.wait()
    target = d / "we ird: name.txt"
    moved = d / "real.txt"
    target.rename(moved)
    target.symlink_to(moved)
    with pytest.raises(av.AvError, match="regular file"):
        m.quarantine(str(target))
    assert moved.exists()


# ── panic and the Proof checks ─────────────────────────────────────────────
def test_panic_hard_deletes_quarantine_and_results_but_not_your_files_or_signatures(env):
    from legalprivacy.controller import Controller
    c = Controller(str(env.tmp / "p.yaml"))
    env.seed_db()
    d = scan_dir(env)
    mine = env.tmp / "my-own-file.txt"
    mine.write_text("precious")
    c.av.start_scan([str(d)])
    c.av.wait()
    c.av.quarantine(str(d / "we ird: name.txt"))
    assert c.av.quarantine_list() and (av.av_dir() / "last_scan.json").exists()
    c.panic("medium")
    assert c.av.quarantine_list()                                       # only hard panic touches antivirus data
    res = c.panic("hard")
    assert any("antivirus" in x for x in res["done"])
    assert not (av.av_dir() / "quarantine").exists() and not (av.av_dir() / "last_scan.json").exists()
    assert c.av.last_scan is None and c.av.state()["quarantine"] == []
    assert mine.read_text() == "precious" and (d / "clean file.txt").exists()
    assert (av.db_dir() / "daily.cvd").exists()


def _av_row(av_fact):
    rows = leakcheck.build_checks({"running": True, "dns": {"mode": "system"}, "av": av_fact})
    return next((r for r in rows if r["id"] == "av"), None)


def test_proof_row_reports_zero_connections_a_violation_or_no_scan_yet():
    ok = _av_row({"connections": 0, "isolation": "unshare-net", "isolated": True, "when": 1.0, "kind": "scan"})
    assert ok["title"] == "Antivirus scanner stays offline" and ok["want"] == "0 connections during scans"
    assert ok["status"] == "ok" and "0 connections" in ok["saw"] and "network removed" in ok["saw"]
    watched = _av_row({"connections": 0, "isolated": False, "when": 1.0, "kind": "selftest"})
    assert "connections watched" in watched["saw"] and "self-test" not in watched["saw"] and "selftest" in watched["saw"]
    bad = _av_row({"connections": 2, "isolated": False, "when": 1.0, "kind": "scan"})
    assert bad["status"] == "bad" and "NOT OFFLINE" in bad["saw"] and bad["hint"]
    none = _av_row({"connections": None})
    assert none["status"] == "unknown" and none["saw"] == "No scan yet"
    assert _av_row(None) is None                                         # never shown to people who do not use it


def test_gather_shows_the_row_only_after_the_feature_was_used(env):
    from legalprivacy.controller import Controller
    c = Controller(str(env.tmp / "p.yaml"))
    assert leakcheck.gather(c, with_network=False)["av"] is None
    env.seed_db()
    assert leakcheck.gather(c, with_network=False)["av"] == {"connections": None}
    c.av.start_selftest()
    c.av.wait()
    row = next(r for r in leakcheck.build_checks(leakcheck.gather(c, with_network=False)) if r["id"] == "av")
    assert row["status"] == "ok"


# ── no network calls of its own ────────────────────────────────────────────
def test_the_module_makes_no_network_calls_of_its_own():
    src = (REPO / "legalprivacy" / "av.py").read_text(encoding="utf-8")
    for word in ("import requests", "urllib.request", "import socket", "http.client", "shell=True", "os.system", "webbrowser"):
        assert word not in src, word


# ── the dashboard routes ───────────────────────────────────────────────────
def test_dashboard_routes(env):
    import http.client
    import threading
    from legalprivacy.controller import Controller
    from legalprivacy.webui import UIServer
    c = Controller(str(env.tmp / "p.yaml"))
    srv = UIServer(c, port=0)
    threading.Thread(target=srv.httpd.serve_forever, daemon=True).start()

    def req(method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers={"X-Token": srv.token})
        r = conn.getresponse()
        data = json.loads(r.read() or b"{}")
        conn.close()
        return r.status, data
    try:
        s, d = req("GET", "/api/av")
        assert s == 200 and d["found"] and d["db"]["dir"].endswith("db")
        s, d = req("POST", "/api/av/update", {})
        assert s == 400 and "confirmation" in d["error"]
        s, d = req("POST", "/api/av/scan", {"paths": []})
        assert s == 400
        assert env.log("freshclam") == []
        env.seed_db()
        s, d = req("POST", "/api/av/scan", {"paths": [str(scan_dir(env))]})
        assert s == 200, (d, [e["message"] for e in c.log.since(0)])
        c.av.wait()
        s, d = req("GET", "/api/av")
        assert d["last_scan"]["infected"] and d["can_scan"]
    finally:
        srv.httpd.shutdown()


# ── native tab (skips without Tk or a display) ─────────────────────────────
def test_security_tab_builds_and_shows_state(env):
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    from legalprivacy import gui
    from legalprivacy.controller import Controller
    ctl = Controller(str(env.tmp / "p.yaml"))
    app = gui.build_app_class()(root, ctl, 0)
    try:
        tab = next(t for t in app.tabs if t.title == "Security")
        idx = app.tabs.index(tab)
        app.nb.select(idx)
        env.seed_db()
        tab.refresh()
        end = time.time() + 3
        while time.time() < end:
            root.update()
            time.sleep(0.02)
        d = scan_dir(env)
        tab.set_paths([str(d)])
        tab.scan()
        ctl.av.wait()
        end = time.time() + 3
        while time.time() < end:
            root.update()
            time.sleep(0.02)
        assert len(tab.results.get_children()) == 1
        assert "stayed offline" in tab.verdict.get() or "offline" in tab.verdict.get().lower()
    finally:
        app.closing = True
        ctl.observer.stop()
        root.destroy()
