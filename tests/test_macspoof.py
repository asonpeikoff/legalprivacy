"""MAC spoofing: ip, nmcli and ethtool are mocked and sysfs is a temp dir, so no root needed."""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from legalprivacy import macspoof  # noqa: E402
from legalprivacy.macspoof import (ArgError, MacSpoofer, PermissionDenied, generate_mac,  # noqa: E402
                                   parse_mac)

PERM_ETH, PERM_WLAN = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"


class Fake:
    """Fake system: sysfs tree plus mock ip / nmcli / ethtool behind one runner."""

    def __init__(self, nm=False, default="eth0", tools=True):
        self.tmp = tempfile.mkdtemp()
        self.sys = Path(self.tmp, "net")
        self.calls: list[list[str]] = []
        self.nm, self.default, self.tools = nm, default, tools
        self.systemd = True
        self.permanent = {"eth0": PERM_ETH, "wlan0": PERM_WLAN}
        self.nm_props: dict[str, str] = {}
        self.timer_cmds: list[list[str]] = []
        for n in ("eth0", "wlan0"):
            self._dev(n, self.permanent[n], device=True, wireless=(n == "wlan0"))
        self._dev("lo", "00:00:00:00:00:00")
        self._dev("docker0", "02:42:00:00:00:01", bridge=True)
        self._dev("veth1", "02:42:00:00:00:02")
        self._dev("eth1", "aa:bb:cc:00:00:03", device=True, brport=True)
        self._dev("tun0", "00:00:00:00:00:00")
        self.permanent["eth1"] = "aa:bb:cc:00:00:03"
        self.sp = MacSpoofer(run=self.run, sysfs=str(self.sys), state_path=Path(self.tmp, "state.json"),
                             euid=lambda: 0, tor_probe=lambda: False, clock=lambda: self.now,
                             systemd_dir=str(Path(self.tmp, "systemd")), cron_dir=str(Path(self.tmp, "cron")),
                             systemd_active=lambda: self.systemd,
                             qubes_marker=str(Path(self.tmp, "marker-vm")), rw_config=str(Path(self.tmp, "rw")))
        Path(self.tmp, "systemd").mkdir()
        self.now = 1_000_000.0

    def _dev(self, name, mac, device=False, wireless=False, bridge=False, brport=False):
        d = self.sys / name
        d.mkdir(parents=True)
        (d / "address").write_text(mac + "\n")
        (d / "type").write_text("1\n")
        (d / "operstate").write_text("up\n")
        for flag, sub in ((device, "device"), (wireless, "wireless"), (bridge, "bridge"), (brport, "brport")):
            if flag:
                (d / sub).mkdir()

    def mac(self, n):
        return (self.sys / n / "address").read_text().strip()

    def run(self, cmd):
        self.calls.append(list(cmd))
        prog = cmd[0]
        if prog == "qubesdb-read":
            return 0, "NetVM\n", ""
        if prog == "systemctl":
            self.timer_cmds.append(cmd)
            return 0, "", ""
        if prog == "ethtool":
            if not self.tools:
                return 127, "", "not found"
            return 0, f"Permanent address: {self.permanent.get(cmd[2], '00:00:00:00:00:00')}\n", ""
        if prog == "ip":
            if cmd[1:3] == ["-j", "route"]:
                return 0, json.dumps([{"dst": "default", "dev": self.default}] if self.default else []), ""
            if cmd[1:4] == ["link", "set", "dev"]:
                if cmd[5] == "address":
                    (self.sys / cmd[4] / "address").write_text(cmd[6] + "\n")
                return 0, "", ""
            return 1, "", "unsupported"
        if prog == "nmcli":
            if not self.nm:
                return 127, "", "not found"
            if cmd[1:] == ["-t", "-f", "RUNNING", "general"]:
                return 0, "running\n", ""
            if "device" in cmd and "status" in cmd:
                return 0, "eth0:connected:Wired 1\nwlan0:connected:Home WiFi\n", ""
            if cmd[1] == "-g":
                return 0, self.nm_props.get(cmd[4] + cmd[2], "") + "\n", ""
            if cmd[1:3] == ["connection", "modify"]:
                args = [a for a in cmd[3:] if a != "--temporary"]
                self.nm_props[args[0] + args[1]] = args[2]
                return 0, "", ""
            if cmd[1:3] == ["connection", "up"]:
                conn, iface = cmd[3], cmd[5]
                prop = "wifi.cloned-mac-address" if iface == "wlan0" else "ethernet.cloned-mac-address"
                val = self.nm_props.get(conn + prop, "")
                if val == "random":
                    (self.sys / iface / "address").write_text("06:11:22:33:44:55\n")
                elif val == "stable":
                    (self.sys / iface / "address").write_text("06:aa:aa:aa:aa:aa\n")
                elif re_mac(val):
                    (self.sys / iface / "address").write_text(val + "\n")
                # "" / preserve: leave the address as it is
                return 0, "", ""
        return 1, "", f"unexpected {cmd}"


def re_mac(v):
    import re
    return bool(re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", v))


def by_iface(rows):
    return {r["iface"]: r for r in rows}


# ---- generation and validation

def test_generated_macs_are_unicast_and_locally_administered():
    for _ in range(2000):
        first = int(generate_mac().split(":")[0], 16)
        assert first & 0x01 == 0, "multicast bit must be clear"
        assert first & 0x02 == 0x02, "locally-administered bit must be set"


def test_generated_macs_have_the_right_shape_and_vary():
    macs = {generate_mac() for _ in range(50)}
    assert len(macs) == 50 and all(len(m.split(":")) == 6 for m in macs)


def test_invalid_mac_input_is_rejected():
    bad = ["", "nonsense", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "gg:bb:cc:dd:ee:ff",
           "01:00:5e:00:00:01", "00:00:00:00:00:00", "aabbccddeeff", None, 123]
    for b in bad:
        try:
            parse_mac(b)
        except ArgError:
            continue
        raise AssertionError(f"{b!r} should have been rejected")
    assert parse_mac("AA-BB-CC-DD-EE-02") == "aa:bb:cc:dd:ee:02"


def test_set_rejects_invalid_mac_without_touching_anything():
    f = Fake()
    try:
        f.sp.set_mac("wlan0", "zz:zz")
    except ArgError:
        pass
    else:
        raise AssertionError("expected ArgError")
    assert f.mac("wlan0") == PERM_WLAN and not any(c[0] == "ip" and "address" in c for c in f.calls)


# ---- restore

def test_restore_returns_the_permanent_address_ip_backend():
    f = Fake()
    row = by_iface(f.sp.randomize(["wlan0"]))["wlan0"]
    assert row["status"] == "ok" and row["backend"] == "ip" and f.mac("wlan0") != PERM_WLAN
    assert json.loads(f.sp.state_path.read_text())["permanent"]["wlan0"] == PERM_WLAN   # recorded first
    row = by_iface(f.sp.restore(["wlan0"]))["wlan0"]
    assert row["status"] == "ok" and f.mac("wlan0") == PERM_WLAN


def test_restore_returns_the_permanent_address_networkmanager_backend():
    f = Fake(nm=True)
    row = by_iface(f.sp.randomize(["wlan0"], mode="stable"))["wlan0"]
    assert row["backend"] == "networkmanager" and f.mac("wlan0") == "06:aa:aa:aa:aa:aa"
    assert f.nm_props["Home WiFiwifi.cloned-mac-address"] == "stable"
    row = by_iface(f.sp.restore(["wlan0"]))["wlan0"]
    assert row["status"] == "ok" and f.mac("wlan0") == PERM_WLAN     # NM 'preserve' → falls back to ip


def test_restore_all_and_nothing_to_restore():
    f = Fake()
    f.sp.randomize(all_=True)
    rows = by_iface(f.sp.restore(all_=True))
    assert f.mac("wlan0") == PERM_WLAN and rows["wlan0"]["status"] == "ok"
    assert by_iface(f.sp.restore(["wlan0"]))["wlan0"]["status"] == "skipped"


def test_permanent_mac_is_recorded_once_and_never_overwritten():
    f = Fake()
    f.sp.randomize(["wlan0"])
    f.sp.randomize(["wlan0"])
    assert json.loads(f.sp.state_path.read_text())["permanent"]["wlan0"] == PERM_WLAN


def test_refuses_to_change_when_permanent_mac_unknown():
    f = Fake(tools=False)
    (f.sys / "wlan0" / "addr_assign_type").write_text("3\n")      # already randomised by something else
    row = by_iface(f.sp.randomize(["wlan0"]))["wlan0"]
    assert row["status"] == "error" and "permanent" in row["reason"] and f.mac("wlan0") == PERM_WLAN


# ---- safety

def test_default_route_interface_is_skipped_without_force():
    f = Fake(default="eth0")
    rows = by_iface(f.sp.randomize(all_=True))
    assert rows["eth0"]["status"] == "skipped" and f.mac("eth0") == PERM_ETH
    assert rows["wlan0"]["status"] == "ok"


def test_explicit_default_route_interface_is_refused_without_force_and_changed_with_it():
    f = Fake(default="eth0")
    assert by_iface(f.sp.randomize(["eth0"]))["eth0"]["status"] == "refused" and f.mac("eth0") == PERM_ETH
    assert by_iface(f.sp.randomize(["eth0"], force=True))["eth0"]["status"] == "ok" and f.mac("eth0") != PERM_ETH


def test_bridges_members_and_virtual_interfaces_are_never_touched():
    f = Fake()
    rows = by_iface(f.sp.randomize(all_=True, force=True))
    assert {"lo", "docker0", "veth1", "eth1", "tun0"}.isdisjoint(rows) is True
    for n in ("docker0", "veth1", "eth1", "lo", "tun0"):
        r = by_iface(f.sp.randomize([n], force=True))[n]
        assert r["status"] == "refused", n
    assert f.mac("eth1") == "aa:bb:cc:00:00:03"


def test_ip_link_is_brought_back_up_even_if_address_change_fails():
    f = Fake()
    orig = f.run

    def failing(cmd):
        if cmd[:6] == ["ip", "link", "set", "dev", "wlan0", "address"]:
            f.calls.append(list(cmd))
            return 2, "", "RTNETLINK answers: Operation not permitted"
        return orig(cmd)
    f.sp.run = failing
    row = by_iface(f.sp.randomize(["wlan0"]))["wlan0"]
    assert row["status"] == "error"
    assert f.calls[-1] == ["ip", "link", "set", "dev", "wlan0", "up"]


def test_root_is_required_and_status_works_without_it():
    f = Fake()
    f.sp._euid = lambda: 1000
    for call in (lambda: f.sp.randomize(["wlan0"]), lambda: f.sp.restore(["wlan0"]),
                 lambda: f.sp.set_mac("wlan0", "02:00:00:00:00:01"), lambda: f.sp.rotate_enable(60)):
        try:
            call()
        except PermissionDenied:
            continue
        raise AssertionError("expected PermissionDenied")
    assert any(r["iface"] == "wlan0" for r in f.sp.status())


def test_persist_needs_networkmanager_and_default_is_temporary():
    f = Fake()
    assert by_iface(f.sp.randomize(["wlan0"], persist=True))["wlan0"]["status"] == "error"
    g = Fake(nm=True)
    g.sp.randomize(["wlan0"])
    mod = [c for c in g.calls if c[:3] == ["nmcli", "connection", "modify"]][0]
    assert "--temporary" in mod
    g.sp.restore(["wlan0"])
    g.calls.clear()
    g.sp.randomize(["wlan0"], persist=True)
    mod = [c for c in g.calls if c[:3] == ["nmcli", "connection", "modify"]][0]
    assert "--temporary" not in mod


# ---- status

def test_status_reports_current_vs_permanent():
    f = Fake()
    f.sp.randomize(["wlan0"])
    rows = by_iface(f.sp.status())
    assert rows["wlan0"]["spoofed"] and rows["wlan0"]["permanent"] == PERM_WLAN
    assert not rows["eth0"]["spoofed"] and rows["eth0"]["default_route"]
    assert rows["docker0"]["eligible"] is False


# ---- rotation

def test_rotation_validates_interval_and_is_off_by_default():
    f = Fake()
    assert f.sp.rotation_status()["enabled"] is False
    for bad in (0, 14, 1441, -5, "abc"):
        try:
            f.sp.rotate_enable(bad)
        except ArgError:
            continue
        raise AssertionError(f"{bad!r} should be rejected")
    assert f.sp.rotation_status()["enabled"] is False
    for ok in (15, 1440):
        assert f.sp.rotate_enable(ok)["interval"] == ok


def test_rotation_stops_when_disabled():
    f = Fake()
    f.sp.rotate_enable(15)
    assert f.sp.rotation_status()["timer"] and Path(f.tmp, "systemd", f"{macspoof.UNIT}.timer").exists()
    f.now += 3600
    rows = f.sp.rotate_tick()
    assert by_iface(rows)["wlan0"]["status"] == "ok" and f.mac("wlan0") != PERM_WLAN
    f.sp.rotate_disable()
    assert not f.sp.rotation_status()["timer"] and not f.sp.rotation_status()["enabled"]
    before = f.mac("wlan0")
    f.now += 7200
    assert f.sp.rotate_tick() == [] and f.mac("wlan0") == before


def test_rotation_waits_for_the_interval():
    f = Fake()
    f.sp.rotate_enable(60)
    f.now += 3600
    assert f.sp.rotate_tick()
    f.now += 900
    assert f.sp.rotate_tick() == []
    f.now += 3600
    assert f.sp.rotate_tick()


def test_rotation_never_touches_active_interface_while_tunnel_up():
    f = Fake(default="eth0")
    f.sp.rotate_enable(15, include_active=True)
    f.now += 3600
    rows = by_iface(f.sp.rotate_tick())              # tun0 exists and is up
    assert rows["eth0"]["status"] == "skipped" and "tunnel" in rows["eth0"]["reason"]
    assert f.mac("eth0") == PERM_ETH
    (f.sys / "tun0" / "operstate").write_text("down\n")
    f.now += 3600
    assert by_iface(f.sp.rotate_tick())["eth0"]["status"] == "ok"
    f.sp.tor_probe = lambda: True
    f.now += 3600
    assert "tunnel" in by_iface(f.sp.rotate_tick())["eth0"]["reason"]


def test_rotation_skips_active_interface_by_default():
    f = Fake(default="eth0")
    f.sp.rotate_enable(15)
    f.now += 3600
    assert by_iface(f.sp.rotate_tick())["eth0"]["status"] == "skipped"


# ---- CLI

def _cli(f, argv, capsys=None):
    import argparse
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    macspoof.add_parser(sub)
    args = parser.parse_args(["mac"] + argv)
    return macspoof.cmd_mac(args, f.sp)


def test_cli_exit_codes_and_json():
    import contextlib
    import io
    f = Fake()

    def run(argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            code = _cli(f, argv)
        return code, buf.getvalue()
    code, out = run(["status", "--json"])
    assert code == 0 and json.loads(out)["ok"] is True
    code, out = run(["randomize", "wlan0", "--json"])
    assert code == 0 and json.loads(out)["results"][0]["status"] == "ok"
    assert run(["set", "wlan0", "bogus"])[0] == 2
    assert run(["randomize"])[0] == 2
    assert run(["randomize", "eth0"])[0] == 1                          # default route, no force
    assert run(["rotate", "--enable", "--interval", "5"])[0] == 2
    assert run(["rotate", "--enable", "--interval", "30"])[0] == 0
    assert run(["rotate", "--disable"])[0] == 0
    f.sp._euid = lambda: 1000
    code, out = run(["randomize", "wlan0", "--json"])
    assert code == 3 and json.loads(out)["exit_code"] == 3


def test_blog_is_credited_in_help_and_module():
    import argparse
    parser = argparse.ArgumentParser()
    macspoof.add_parser(parser.add_subparsers(dest="command"))
    assert "legalizingprivacy.substack.com" in macspoof.BLOG_URL and "Amy Peikoff" in macspoof.__doc__


def test_rotation_falls_back_to_cron_without_systemd():
    f = Fake()
    f.systemd = False
    f.sp.rotate_enable(30)
    assert Path(f.tmp, "cron", macspoof.UNIT).exists()
    f.sp.rotate_disable()
    assert not Path(f.tmp, "cron", macspoof.UNIT).exists()


# ---- Qubes OS and headless

def _make_qubes(f):
    Path(f.tmp, "marker-vm").write_text("")
    Path(f.tmp, "rw").mkdir()


def test_xen_virtual_nic_has_a_mac_and_can_be_changed_when_named_with_force():
    """Inside a Qubes AppVM the only NIC is a Xen vif. It has its own MAC, so it can be changed like any other;
    it carries the default route, so only when named with --force."""
    f = Fake(default="eth0")
    drv = f.sys / "eth0" / "device"
    (Path(f.tmp, "drivers", "vif")).mkdir(parents=True)
    os.symlink(Path(f.tmp, "drivers", "vif"), drv / "driver")
    assert f.sp.interface_info("eth0")["eligible"]
    assert by_iface(f.sp.randomize(["eth0"]))["eth0"]["status"] == "refused"            # default route, no --force
    row = by_iface(f.sp.randomize(["eth0"], force=True))["eth0"]
    assert row["status"] != "refused" and f.mac("eth0") != PERM_ETH
    assert f.sp.environment()["xen_virtual_interfaces"] == ["eth0"]


def test_qubes_environment_detected_and_absent_elsewhere():
    f = Fake()
    assert f.sp.environment()["qubes_vm_type"] is None
    _make_qubes(f)
    assert f.sp.environment()["qubes_vm_type"] == "NetVM"


def test_qubes_rotation_hook_persists_in_rw_config_and_is_removed_on_disable():
    f = Fake()
    _make_qubes(f)
    rc = Path(f.tmp, "rw", "rc.local")
    rc.write_text("#!/bin/sh\necho mine\n")
    f.sp.rotate_enable(30, include_active=True)
    text = rc.read_text()
    assert "echo mine" in text and "rotate --resume" in text and "PYTHONPATH=" in text
    assert rc.stat().st_mode & 0o111
    f.sp.rotate_enable(45)                                  # re-enable: still one block
    assert rc.read_text().count("BEGIN legalprivacy-mac-rotate") == 1
    f.sp.rotate_disable()
    assert rc.read_text() == "#!/bin/sh\necho mine\n"


def test_no_qubes_hook_outside_qubes():
    f = Fake()
    Path(f.tmp, "rw").mkdir()
    f.sp.rotate_enable(30)
    assert not Path(f.tmp, "rw", "rc.local").exists()


def test_resume_reinstalls_timer_only_when_enabled():
    f = Fake()
    f.sp.rotate_enable(30)
    for p in Path(f.tmp, "systemd").iterdir():              # simulate the reboot that wipes /etc
        p.unlink()
    f.sp.rotate_resume()
    assert Path(f.tmp, "systemd", f"{macspoof.UNIT}.timer").exists()
    f.sp.rotate_disable()
    f.sp.rotate_resume()
    assert not Path(f.tmp, "systemd", f"{macspoof.UNIT}.timer").exists()


def test_timer_unit_carries_pythonpath_and_uses_the_stdlib_entry_point():
    f = Fake()
    f.sp.rotate_enable(30)
    svc = Path(f.tmp, "systemd", f"{macspoof.UNIT}.service").read_text()
    assert "Environment=PYTHONPATH=" in svc and "legalprivacy.macspoof rotate --tick" in svc


def test_rotation_warns_on_qubes_with_include_active_and_when_nothing_can_rotate():
    f = Fake(default="eth0")
    # eth0 and wlan0 eligible; wlan0 is not default, so no 'nothing rotates' warning
    assert not f.sp.rotate_enable(30)["warnings"]
    g = Fake(default="eth0")
    (g.sys / "wlan0" / "device").rmdir()                    # make wlan0 ineligible: only eth0 remains
    (g.sys / "wlan0" / "wireless").rmdir()
    assert any("nothing will rotate" in w for w in g.sp.rotate_enable(30)["warnings"])
    _make_qubes(g)
    assert any("sys-vpn" in w for w in g.sp.rotate_enable(30, include_active=True)["warnings"])


def test_macspoof_is_headless_and_stdlib_only():
    import subprocess
    code = ("import sys; import legalprivacy.macspoof as m; "
            "bad=[x for x in ('yaml','requests','playwright','psutil','tkinter','legalprivacy.config',"
            "'legalprivacy.tormanager') if x in sys.modules]; "
            "sys.exit(1 if bad else m.main(['status','--json']))")
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       cwd=os.path.join(os.path.dirname(__file__), ".."))
    assert p.returncode == 0, p.stderr + p.stdout
    assert json.loads(p.stdout)["ok"] is True


def test_standalone_main_returns_exit_codes():
    assert macspoof.main(["set", "wlan0", "bogus"]) == 2        # bad MAC is rejected before root is needed
