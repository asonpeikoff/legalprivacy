"""MAC address spoofing (Linux): randomize or set the hardware address of your network
interfaces, and put the permanent one back.

Clean-room implementation using only standard Linux tools (`ip`, `nmcli`, `ethtool`) and
/sys. It is part of legalPrivacy, which is named in homage to the blog *Legalizing Privacy*
by Amy Peikoff: https://legalizingprivacy.substack.com

Backends
  * NetworkManager (preferred): sets `wifi.cloned-mac-address` / `ethernet.cloned-mac-address`
    on the active connection to `random`, `stable` or a fixed address.
  * Fallback (no NetworkManager, or the interface has no active connection):
    `ip link set dev IF down`, `... address MAC`, `... up`.

Safety: the permanent MAC (`ethtool -P`) is recorded before anything changes; the interface
carrying the default route is skipped unless forced; bridges, bridge/bond members and virtual
interfaces are never touched; changes need root. Nothing survives a reboot unless you pass
`--persist` (NetworkManager only).

Headless by design: this module needs only the Python standard library (no dashboard, browser or
third-party packages), so `python3 -m legalprivacy.macspoof ...` (or `legalprivacy-mac`) works on a
minimal install, over SSH, from a systemd unit, or inside a Qubes OS sys-net.

Qubes OS: the MAC that matters is the physical NIC's, which lives in sys-net. Inside an AppVM
the only NIC is a Xen virtual interface (vif), which this tool refuses to touch.

Exit codes: 0 ok, 1 error, 2 bad arguments, 3 permission denied.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

BLOG_URL = "https://legalizingprivacy.substack.com"

EXIT_OK, EXIT_ERROR, EXIT_ARGS, EXIT_PERMISSION = 0, 1, 2, 3
MIN_INTERVAL, MAX_INTERVAL = 15, 1440
TICK_MINUTES = 15            # the scheduler wakes this often; the tick itself honours the interval

SYSFS = "/sys/class/net"
_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_TUNNEL_RE = re.compile(r"^(tun|tap|wg|ppp|tailscale|ipsec|nordlynx|proton|mullvad|vpn)", re.I)
TOR_PORTS = (9050, 9150)
UNIT = "legalprivacy-mac-rotate"


class MacError(Exception):
    """Operation failed (exit 1)."""


class ArgError(MacError):
    """Bad arguments (exit 2)."""


class PermissionDenied(MacError):
    """Not root (exit 3)."""


# --------------------------------------------------------------------------- addresses

def parse_mac(text: str) -> str:
    """Normalise to lower-case aa:bb:cc:dd:ee:ff. Rejects anything else, multicast
    addresses (low bit of the first octet set) and the all-zero address."""
    if not isinstance(text, str):
        raise ArgError("MAC address must be text")
    mac = text.strip().lower().replace("-", ":")
    if not _MAC_RE.match(mac):
        raise ArgError(f"invalid MAC address {text!r} (expected aa:bb:cc:dd:ee:ff)")
    if int(mac[:2], 16) & 1:
        raise ArgError(f"{mac} is a multicast address; use a unicast one (first octet even)")
    if mac == "00:00:00:00:00:00":
        raise ArgError("00:00:00:00:00:00 is not a usable MAC address")
    return mac


def generate_mac() -> str:
    """Six random octets; first octet forced unicast (bit 0 = 0) and locally administered
    (bit 1 = 1): (b & 0xFE) | 0x02."""
    while True:
        b = bytearray(secrets.token_bytes(6))
        b[0] = (b[0] & 0xFE) | 0x02
        mac = ":".join(f"{x:02x}" for x in b)
        if mac != "00:00:00:00:00:00":
            return mac


# --------------------------------------------------------------------------- plumbing

Runner = Callable[[list], "tuple[int, str, str]"]


def default_runner(cmd: list) -> "tuple[int, str, str]":
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: command not found"
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)


def _default_state_path() -> Path:
    from .paths import app_dir
    return app_dir() / "mac_state.json"


def _default_tor_probe() -> bool:
    for port in TOR_PORTS:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            continue
    return False


XEN_DRIVERS = ("vif", "xen-netfront", "xen_netfront")
QUBES_MARKER = "/usr/share/qubes/marker-vm"
QUBES_RW_CONFIG = "/rw/config"
_HOOK_BEGIN, _HOOK_END = "# BEGIN legalprivacy-mac-rotate", "# END legalprivacy-mac-rotate"


class MacSpoofer:
    def __init__(self, run: Runner = default_runner, sysfs: str = SYSFS,
                 state_path: Path | None = None, euid: Callable[[], int] | None = None,
                 tor_probe: Callable[[], bool] = _default_tor_probe,
                 clock: Callable[[], float] = time.time, systemd_dir: str = "/etc/systemd/system",
                 cron_dir: str = "/etc/cron.d",
                 systemd_active: Callable[[], bool] = lambda: Path("/run/systemd/system").is_dir(),
                 qubes_marker: str = QUBES_MARKER, rw_config: str = QUBES_RW_CONFIG):
        self.run, self.sysfs = run, sysfs
        self.state_path = Path(state_path) if state_path else None
        self._euid = euid or (lambda: os.geteuid() if hasattr(os, "geteuid") else 0)
        self.tor_probe, self.clock = tor_probe, clock
        self.systemd_dir, self.cron_dir = systemd_dir, cron_dir
        self._systemd_active = systemd_active
        self.qubes_marker, self.rw_config = qubes_marker, rw_config

    # ---- state
    def _path(self) -> Path:
        return self.state_path or _default_state_path()

    def load_state(self) -> dict:
        try:
            data = json.loads(self._path().read_text("utf-8"))
        except (OSError, ValueError):
            data = {}
        data.setdefault("permanent", {})
        data.setdefault("nm_original", {})
        data.setdefault("rotation", {"enabled": False, "interval": 60, "include_active": False,
                                     "last": 0})
        return data

    def save_state(self, st: dict) -> None:
        p = self._path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(st, f, indent=2)
        os.replace(tmp, p)

    def require_root(self) -> None:
        if self._euid() != 0:
            raise PermissionDenied("changing MAC addresses needs root: re-run with sudo")

    # ---- sysfs
    def _read(self, iface: str, name: str) -> str | None:
        try:
            return Path(self.sysfs, iface, name).read_text().strip()
        except OSError:
            return None

    def _exists(self, iface: str, name: str) -> bool:
        return os.path.lexists(os.path.join(self.sysfs, iface, name))

    def current_mac(self, iface: str) -> str | None:
        m = self._read(iface, "address")
        return m.lower() if m else None

    def driver(self, iface: str) -> str | None:
        try:
            return os.path.basename(os.readlink(os.path.join(self.sysfs, iface, "device", "driver")))
        except OSError:
            return None

    def qubes_vm_type(self) -> str | None:
        """None outside Qubes OS; otherwise the VM type if qubesdb answers, else 'unknown'."""
        if not Path(self.qubes_marker).exists():
            return None
        rc, out, _ = self.run(["qubesdb-read", "/qubes-vm-type"])
        return out.strip() if rc == 0 and out.strip() else "unknown"

    def interface_info(self, iface: str) -> dict:
        wifi = self._exists(iface, "wireless") or self._exists(iface, "phy80211")
        physical = self._exists(iface, "device")
        reason = None
        if iface == "lo":
            reason = "loopback"
        elif self._exists(iface, "bridge"):
            reason = "bridge"
        elif self._exists(iface, "brport") or self._exists(iface, "master"):
            reason = "bridge or bond member"
        elif not physical:
            reason = "virtual interface"
        elif self.driver(iface) in XEN_DRIVERS:
            reason = ("Xen virtual NIC (Qubes AppVM): the MAC on the wire belongs to the NIC in "
                      "sys-net; run this tool there")
        elif self._read(iface, "type") not in (None, "1"):
            reason = "not an Ethernet-type interface"
        return {"iface": iface, "kind": "wifi" if wifi else ("ethernet" if physical else "virtual"),
                "eligible": reason is None, "reason": reason, "current": self.current_mac(iface), "driver": self.driver(iface)}

    def list_interfaces(self) -> list[dict]:
        try:
            names = sorted(os.listdir(self.sysfs))
        except OSError:
            return []
        return [self.interface_info(n) for n in names]

    # ---- routes, permanent address
    def default_route_ifaces(self) -> set[str]:
        rc, out, _ = self.run(["ip", "-j", "route", "show", "default"])
        found: set[str] = set()
        if rc == 0 and out.strip():
            try:
                found = {r["dev"] for r in json.loads(out) if r.get("dev")}
            except (ValueError, TypeError):
                found = set()
        if not found:
            rc, out, _ = self.run(["ip", "route", "show", "default"])
            if rc == 0:
                found = set(re.findall(r"\bdev\s+(\S+)", out))
        return found

    def permanent_mac(self, iface: str) -> str | None:
        rc, out, _ = self.run(["ethtool", "-P", iface])
        m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", out) if rc == 0 else None
        if m and m.group(1).lower() != "00:00:00:00:00:00":
            return m.group(1).lower()
        if self._read(iface, "addr_assign_type") == "0":      # kernel says: factory address
            return self.current_mac(iface)
        return None

    def record_permanent(self, iface: str, st: dict) -> str:
        """Record the permanent MAC the first time we see an interface; never overwrite."""
        if iface in st["permanent"]:
            return st["permanent"][iface]
        mac = self.permanent_mac(iface)
        if not mac:
            raise MacError(f"{iface}: cannot determine the permanent MAC (is ethtool installed?); "
                           "refusing to change it without a way back")
        st["permanent"][iface] = mac
        self.save_state(st)
        return mac

    # ---- NetworkManager
    def nm_connection(self, iface: str) -> str | None:
        """Active NM connection name for iface, or None (no NM, unmanaged, not connected)."""
        rc, out, _ = self.run(["nmcli", "-t", "-f", "RUNNING", "general"])
        if rc != 0 or out.strip() != "running":
            return None
        rc, out, _ = self.run(["nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION", "device", "status"])
        if rc != 0:
            return None
        for line in out.splitlines():
            parts = re.split(r"(?<!\\):", line, maxsplit=2)
            if len(parts) == 3 and parts[0] == iface and parts[1] == "connected" and parts[2] not in ("", "--"):
                return parts[2].replace("\\:", ":")
        return None

    @staticmethod
    def _nm_prop(kind: str) -> str:
        return "wifi.cloned-mac-address" if kind == "wifi" else "ethernet.cloned-mac-address"

    def _nm_set(self, conn: str, prop: str, value: str, iface: str, persist: bool) -> None:
        cmd = ["nmcli", "connection", "modify"] + ([] if persist else ["--temporary"]) + [conn, prop, value]
        rc, _, err = self.run(cmd)
        if rc != 0:
            raise MacError(f"nmcli modify failed: {err.strip() or rc}")
        rc, _, err = self.run(["nmcli", "connection", "up", conn, "ifname", iface])
        if rc != 0:
            raise MacError(f"nmcli up failed: {err.strip() or rc}")

    def _ip_set(self, iface: str, mac: str) -> None:
        rc, _, err = self.run(["ip", "link", "set", "dev", iface, "down"])
        if rc != 0:
            raise MacError(f"ip link down failed: {err.strip() or rc}")
        try:
            rc, _, err = self.run(["ip", "link", "set", "dev", iface, "address", mac])
            if rc != 0:
                raise MacError(f"ip link set address failed: {err.strip() or rc}")
        finally:
            self.run(["ip", "link", "set", "dev", iface, "up"])      # never leave the link down

    # ---- target selection
    def _targets(self, ifaces: list[str] | None, all_: bool, force: bool, st_action: str) -> list[dict]:
        """Resolve which interfaces to act on. Returns result rows; rows with status 'todo'
        are to be processed, others are final (skipped/refused)."""
        known = {i["iface"]: i for i in self.list_interfaces()}
        active = self.default_route_ifaces()
        rows = []
        names = sorted(n for n, i in known.items() if i["eligible"]) if all_ else list(ifaces or [])
        if not names:
            raise ArgError("name an interface or pass --all")
        for n in names:
            row = {"iface": n, "action": st_action, "status": "todo"}
            info = known.get(n)
            explicit = not all_
            if info is None:
                row.update(status="error", reason="no such interface")
            elif not info["eligible"]:
                row.update(status="refused" if explicit else "skipped", reason=info["reason"])
            elif n in active and not force:
                row.update(status="refused" if explicit else "skipped",
                           reason="carries the default route (use --force / --include-active)")
            rows.append(row)
        return rows

    # ---- operations
    def status(self) -> list[dict]:
        st = self.load_state()
        active = self.default_route_ifaces()
        out = []
        for i in self.list_interfaces():
            perm = st["permanent"].get(i["iface"]) or (self.permanent_mac(i["iface"]) if i["eligible"] else None)
            out.append({**i, "permanent": perm, "spoofed": bool(perm and i["current"] and i["current"] != perm),
                        "default_route": i["iface"] in active})
        return out

    def environment(self) -> dict:
        ifs = self.list_interfaces()
        return {"qubes_vm_type": self.qubes_vm_type(),
                "xen_virtual_interfaces": [i["iface"] for i in ifs if i["driver"] in XEN_DRIVERS]}

    def _change(self, row: dict, mode: str, mac: str | None, persist: bool, st: dict) -> None:
        iface = row["iface"]
        info = self.interface_info(iface)
        self.record_permanent(iface, st)
        row["previous"] = info["current"]
        conn = self.nm_connection(iface)
        if conn:
            prop = self._nm_prop(info["kind"])
            if iface not in st["nm_original"]:
                rc, out, _ = self.run(["nmcli", "-g", prop, "connection", "show", conn])
                st["nm_original"][iface] = {"conn": conn, "prop": prop,
                                            "value": out.strip() if rc == 0 else "",
                                            "persisted": False}
            st["nm_original"][iface]["persisted"] = st["nm_original"][iface]["persisted"] or persist
            self.save_state(st)
            self._nm_set(conn, prop, mac or mode, iface, persist)
            row["backend"] = "networkmanager"
        else:
            if persist:
                raise MacError(f"{iface}: --persist needs an active NetworkManager connection")
            self._ip_set(iface, mac or generate_mac())
            row["backend"] = "ip"
        row["mac"] = self.current_mac(iface)
        row["status"] = "ok"

    def _apply(self, ifaces, all_, force, action, mode, mac, persist) -> list[dict]:
        self.require_root()
        st = self.load_state()
        rows = self._targets(ifaces, all_, force, action)
        for row in rows:
            if row["status"] != "todo":
                continue
            try:
                self._change(row, mode, mac, persist, st)
            except MacError as exc:
                row.update(status="error", reason=str(exc))
        return rows

    def randomize(self, ifaces=None, all_=False, force=False, mode="random", persist=False):
        if mode not in ("random", "stable"):
            raise ArgError("mode must be 'random' or 'stable'")
        return self._apply(ifaces, all_, force, "randomize", mode, None, persist)

    def set_mac(self, iface: str, mac: str, force=False, persist=False):
        return self._apply([iface], False, force, "set", "fixed", parse_mac(mac), persist)

    def restore(self, ifaces=None, all_=False, force=False):
        self.require_root()
        st = self.load_state()
        rows = self._targets(ifaces, all_, force, "restore")
        for row in rows:
            if row["status"] != "todo":
                continue
            iface = row["iface"]
            try:
                perm = st["permanent"].get(iface) or self.permanent_mac(iface)
                cur = self.current_mac(iface)
                row["previous"] = cur
                if not perm:
                    raise MacError("permanent MAC unknown; nothing to restore to")
                if cur == perm and iface not in st["nm_original"]:
                    row.update(status="skipped", reason="already the permanent address", mac=cur)
                    continue
                orig = st["nm_original"].get(iface)
                conn = self.nm_connection(iface)
                if orig and conn:
                    self._nm_set(conn, orig["prop"], orig["value"], iface, orig.get("persisted", False))
                    row["backend"] = "networkmanager"
                if self.current_mac(iface) != perm:       # NM 'preserve' keeps the spoof: set it directly
                    self._ip_set(iface, perm)
                    row["backend"] = "ip" if "backend" not in row else row["backend"] + "+ip"
                row["mac"] = self.current_mac(iface)
                if row["mac"] != perm:
                    raise MacError(f"restore did not take effect (now {row['mac']}, expected {perm})")
                st["nm_original"].pop(iface, None)
                self.save_state(st)
                row["status"] = "ok"
            except MacError as exc:
                row.update(status="error", reason=str(exc))
        return rows

    # ---- rotation
    def tunnel_up(self) -> str | None:
        """Name of a VPN/Tor tunnel that is up, else None."""
        for i in self.list_interfaces():
            if _TUNNEL_RE.match(i["iface"]) and self._read(i["iface"], "operstate") != "down":
                return i["iface"]
        if self.tor_probe():
            return "tor"
        return None

    def rotation_status(self) -> dict:
        r = dict(self.load_state()["rotation"])
        r["timer"] = self._timer_installed()
        return r

    def _timer_installed(self) -> bool:
        return (Path(self.systemd_dir, f"{UNIT}.timer").exists()
                or Path(self.cron_dir, UNIT).exists())

    def _use_systemd(self) -> bool:
        return self._systemd_active() and Path(self.systemd_dir).is_dir()

    def rotate_enable(self, interval: int, include_active: bool = False) -> dict:
        try:
            interval = int(interval)
        except (TypeError, ValueError):
            raise ArgError("interval must be a whole number of minutes") from None
        if not MIN_INTERVAL <= interval <= MAX_INTERVAL:
            raise ArgError(f"interval must be {MIN_INTERVAL} to {MAX_INTERVAL} minutes")
        self.require_root()
        st = self.load_state()
        st["rotation"] = {"enabled": True, "interval": interval, "include_active": bool(include_active),
                          "last": 0}
        self.save_state(st)
        self._install_timer()
        self._qubes_hook(True)
        out = self.rotation_status()
        out["warnings"] = self._rotation_warnings(bool(include_active))
        return out

    def _rotation_warnings(self, include_active: bool) -> list[str]:
        w = []
        ifs = [i for i in self.list_interfaces() if i["eligible"]]
        active = self.default_route_ifaces()
        if not include_active and ifs and all(i["iface"] in active for i in ifs):
            w.append("every eligible interface carries the default route, so nothing will rotate "
                     "without --include-active")
        if include_active and self.qubes_vm_type() is not None:
            w.append("Qubes: a VPN in a downstream qube (sys-vpn) is invisible from here; each rotation "
                     "drops the link and the VPN must reconnect (keep its kill switch on)")
        return w

    def rotate_resume(self) -> dict:
        """Reinstall the timer from the saved settings (used at boot on Qubes, where /etc resets)."""
        self.require_root()
        if self.load_state()["rotation"].get("enabled"):
            self._install_timer()
        return self.rotation_status()

    def rotate_disable(self) -> dict:
        self.require_root()
        st = self.load_state()
        st["rotation"]["enabled"] = False
        self.save_state(st)
        self._remove_timer()
        self._qubes_hook(False)
        return self.rotation_status()

    def _tick_command(self, flag: str = "--tick") -> list[str]:
        return [sys.executable, "-m", "legalprivacy.macspoof", "rotate", flag]

    def _env(self) -> str:
        """PYTHONPATH and state dir, so a root-run timer finds a package installed for another user."""
        pkg_root = str(Path(__file__).resolve().parents[1])
        return f"PYTHONPATH={pkg_root} LEGALPRIVACY_HOME={self._path().parent}"

    def _qubes_hook(self, install: bool) -> None:
        """Qubes: /etc and /usr/lib in a template-based qube reset on reboot, but /rw/config/rc.local
        persists. Keep a marked block there that reinstalls the timer at boot (only while enabled)."""
        rc_local = Path(self.rw_config, "rc.local")
        if self.qubes_vm_type() is None or not Path(self.rw_config).is_dir():
            return
        old = rc_local.read_text() if rc_local.exists() else "#!/bin/sh\n"
        keep, skipping = [], False
        for line in old.splitlines():
            if line.strip() == _HOOK_BEGIN:
                skipping = True
            elif line.strip() == _HOOK_END:
                skipping = False
            elif not skipping:
                keep.append(line)
        if install:
            keep += [_HOOK_BEGIN, f"{self._env()} {' '.join(self._tick_command('--resume'))}", _HOOK_END]
        rc_local.write_text("\n".join(keep) + "\n")
        rc_local.chmod(0o755)

    def _install_timer(self) -> None:
        cmd = " ".join(self._tick_command())
        if self._use_systemd():
            Path(self.systemd_dir, f"{UNIT}.service").write_text(
                "[Unit]\nDescription=legalPrivacy timed MAC rotation\n\n[Service]\nType=oneshot\n"
                "".join(f"Environment={kv}\n" for kv in self._env().split()) + f"ExecStart={cmd}\n")
            Path(self.systemd_dir, f"{UNIT}.timer").write_text(
                "[Unit]\nDescription=legalPrivacy timed MAC rotation\n\n[Timer]\n"
                f"OnBootSec={TICK_MINUTES}min\nOnUnitActiveSec={TICK_MINUTES}min\n\n"
                "[Install]\nWantedBy=timers.target\n")
            self.run(["systemctl", "daemon-reload"])
            rc, _, err = self.run(["systemctl", "enable", "--now", f"{UNIT}.timer"])
            if rc != 0:
                raise MacError(f"could not start the rotation timer: {err.strip() or rc}")
        else:
            Path(self.cron_dir).mkdir(parents=True, exist_ok=True)
            Path(self.cron_dir, UNIT).write_text(
                f"# legalPrivacy timed MAC rotation\n*/{TICK_MINUTES} * * * * root "
                f"{self._env()} {cmd}\n")

    def _remove_timer(self) -> None:
        if Path(self.systemd_dir, f"{UNIT}.timer").exists():
            self.run(["systemctl", "disable", "--now", f"{UNIT}.timer"])
        for p in (Path(self.systemd_dir, f"{UNIT}.timer"), Path(self.systemd_dir, f"{UNIT}.service"),
                  Path(self.cron_dir, UNIT)):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        if Path(self.systemd_dir).is_dir():
            self.run(["systemctl", "daemon-reload"])

    def rotate_tick(self) -> list[dict]:
        """One scheduler wake-up. Does nothing unless rotation is enabled and due. Never
        rotates the default-route interface while a VPN or Tor tunnel is up."""
        self.require_root()
        st = self.load_state()
        r = st["rotation"]
        if not r.get("enabled"):
            return []
        if self.clock() - r.get("last", 0) < r["interval"] * 60 - 30:
            return []
        active = self.default_route_ifaces()
        tunnel = self.tunnel_up()
        rows = []
        for i in self.list_interfaces():
            if not i["eligible"]:
                continue
            row = {"iface": i["iface"], "action": "rotate", "status": "todo"}
            if i["iface"] in active and not r.get("include_active"):
                row.update(status="skipped", reason="carries the default route")
            elif i["iface"] in active and tunnel:
                row.update(status="skipped", reason=f"tunnel up ({tunnel})")
            else:
                try:
                    self._change(row, "random", None, False, st)
                except MacError as exc:
                    row.update(status="error", reason=str(exc))
            rows.append(row)
        st = self.load_state()                       # _change saved intermediate state
        st["rotation"]["last"] = self.clock()
        self.save_state(st)
        return rows


# --------------------------------------------------------------------------- CLI

_DESC = ("Randomize, set or restore MAC addresses. Exit codes: 0 ok, 1 error, 2 bad arguments, "
         "3 permission denied. On Qubes OS run it in sys-net, not in an AppVM.")
_EPILOG = f"legalPrivacy is named in homage to the blog Legalizing Privacy by Amy Peikoff: {BLOG_URL}"


def add_parser(sub) -> None:
    p = sub.add_parser("mac", help="spoof or restore network interface MAC addresses (Linux, needs root)",
                       description=_DESC, epilog=_EPILOG,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    _populate(p)


def main(argv: list[str] | None = None) -> int:
    """Standalone headless entry point (`legalprivacy-mac`, `python -m legalprivacy.macspoof`)."""
    p = argparse.ArgumentParser(prog="legalprivacy-mac", description=_DESC, epilog=_EPILOG,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    _populate(p)
    return cmd_mac(p.parse_args(argv))


def _populate(p) -> None:
    msub = p.add_subparsers(dest="mac_command", required=True)

    def common(sp, force=True):
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        if force:
            sp.add_argument("--force", "--include-active", dest="force", action="store_true",
                            help="also touch the interface carrying the default route")

    s = msub.add_parser("status", help="current vs permanent MAC per interface (no root needed)")
    common(s, force=False)
    r = msub.add_parser("randomize", help="new random (or stable) MAC")
    r.add_argument("iface", nargs="?")
    r.add_argument("--all", action="store_true", help="every eligible interface")
    r.add_argument("--mode", choices=["random", "stable"], default="random",
                   help="NetworkManager: new address per connection (random) or one per network (stable)")
    r.add_argument("--persist", action="store_true", help="survive reboot (NetworkManager only)")
    common(r)
    st = msub.add_parser("set", help="set a specific MAC")
    st.add_argument("iface")
    st.add_argument("mac")
    st.add_argument("--persist", action="store_true", help="survive reboot (NetworkManager only)")
    common(st)
    rs = msub.add_parser("restore", help="go back to the permanent MAC")
    rs.add_argument("iface", nargs="?")
    rs.add_argument("--all", action="store_true")
    common(rs)
    ro = msub.add_parser("rotate", help="opt-in timed rotation (off by default)")
    g = ro.add_mutually_exclusive_group()
    g.add_argument("--enable", action="store_true")
    g.add_argument("--disable", action="store_true")
    g.add_argument("--tick", action="store_true", help=argparse.SUPPRESS)
    g.add_argument("--resume", action="store_true", help=argparse.SUPPRESS)
    ro.add_argument("--interval", type=int, default=60, metavar="MIN",
                    help=f"minutes between rotations, {MIN_INTERVAL} to {MAX_INTERVAL} (default 60)")
    ro.add_argument("--include-active", action="store_true",
                    help="also rotate the default-route interface (never while a VPN/Tor tunnel is up)")
    common(ro, force=False)
    p.set_defaults(func=cmd_mac)


def _fmt_rows(rows: list[dict]) -> str:
    out = []
    for r in rows:
        line = f"{r['iface']}: {r['status']}"
        if r.get("mac"):
            line += f" -> {r['mac']}"
        if r.get("backend"):
            line += f" ({r['backend']})"
        if r.get("reason"):
            line += f" [{r['reason']}]"
        out.append(line)
    return "\n".join(out)


def cmd_mac(args, spoofer: MacSpoofer | None = None) -> int:
    sp = spoofer or MacSpoofer()
    as_json = getattr(args, "json", False)
    cmd = args.mac_command
    try:
        if cmd == "status":
            rows = sp.status()
            rot = sp.rotation_status()
            env = sp.environment()
            if as_json:
                print(json.dumps({"ok": True, "interfaces": rows, "rotation": rot, "environment": env}, indent=2))
            else:
                for r in rows:
                    tag = ("spoofed" if r["spoofed"] else "original") if r["eligible"] else f"skip: {r['reason']}"
                    print(f"{r['iface']:<12} {r['kind']:<8} current={r['current']} "
                          f"permanent={r['permanent']} {tag}{' [default route]' if r['default_route'] else ''}")
                if env["qubes_vm_type"]:
                    print(f"qubes: {env['qubes_vm_type']}")
                if env["xen_virtual_interfaces"] and not any(r["eligible"] for r in rows):
                    print("note: only Xen virtual NICs here (a Qubes AppVM). Spoof the physical NIC "
                          "from sys-net instead.")
                print(f"rotation: {'on, every ' + str(rot['interval']) + ' min' if rot['enabled'] else 'off'}")
            return EXIT_OK
        if cmd == "rotate":
            if args.tick:
                rows = sp.rotate_tick()
            elif args.resume:
                rot = sp.rotate_resume()
                print(json.dumps({"ok": True, "rotation": rot}) if as_json else "rotation timer reinstalled")
                return EXIT_OK
            elif args.enable:
                rot = sp.rotate_enable(args.interval, args.include_active)
                if as_json:
                    print(json.dumps({"ok": True, "rotation": rot}))
                else:
                    print(f"rotation on: every {rot['interval']} min")
                    for w in rot.get("warnings", []):
                        print(f"warning: {w}", file=sys.stderr)
                return EXIT_OK
            elif args.disable:
                rot = sp.rotate_disable()
                print(json.dumps({"ok": True, "rotation": rot}) if as_json else "rotation off")
                return EXIT_OK
            else:
                raise ArgError("use --enable, --disable or see `mac status`")
        elif cmd == "randomize":
            if bool(args.iface) == bool(args.all):
                raise ArgError("give either an interface or --all")
            rows = sp.randomize([args.iface] if args.iface else None, args.all, args.force,
                                args.mode, args.persist)
        elif cmd == "set":
            rows = sp.set_mac(args.iface, args.mac, args.force, args.persist)
        elif cmd == "restore":
            if bool(args.iface) == bool(args.all):
                raise ArgError("give either an interface or --all")
            rows = sp.restore([args.iface] if args.iface else None, args.all, args.force)
        else:                                                # pragma: no cover
            raise ArgError(f"unknown mac command {cmd}")
    except MacError as exc:
        code = EXIT_ARGS if isinstance(exc, ArgError) else (
            EXIT_PERMISSION if isinstance(exc, PermissionDenied) else EXIT_ERROR)
        if as_json:
            print(json.dumps({"ok": False, "error": str(exc), "exit_code": code}))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return code
    bad = any(r["status"] in ("error", "refused") for r in rows)
    if as_json:
        print(json.dumps({"ok": not bad, "results": rows}, indent=2))
    elif rows:
        print(_fmt_rows(rows))
    return EXIT_ERROR if bad else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
