"""Automatic Tor management: find / install / launch / monitor / control.

Design rules
  * Managed mode runs a PRIVATE tor on non-default ports with its own data
    dir, so it never touches the user's system tor or Tor Browser.
  * Installation downloads the official Tor Expert Bundle from
    dist.torproject.org and verifies its SHA-256 against the sums file
    published in the same release directory before extracting.
  * Everything is reported through the shared EventLog.
"""
from __future__ import annotations

import bisect
import hashlib
import ipaddress
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from .config import BANNED_RELAYS, valid_bridge_line
from .events import EventLog
from .paths import tor_dir
from . import tordns
from .torcontrol import TorControl, TorControlError, split_hostport

DIST_BASE = "https://dist.torproject.org/torbrowser/"
BOOTSTRAP_RE = re.compile(r"Bootstrapped (\d+)%(?: \(([^)]*)\))?: (.*)")
_IS_WIN = sys.platform == "win32"
_EXE = "tor.exe" if _IS_WIN else "tor"


# ── helpers ─────────────────────────────────────────────────────────────────
def _port_free(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def _pick_port(preferred: int) -> int:
    if _port_free(preferred):
        return preferred
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _udp_port_free(host: str, port: int) -> bool:
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _pick_udp_port(host: str, preferred: int) -> int:
    if preferred and _udp_port_free(host, preferred):
        return preferred
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def platform_key() -> tuple[str, str] | None:
    """(os, arch) as used in Tor Expert Bundle file names, or None if unsupported."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("aarch64", "arm64"):
        arch = "aarch64"
    elif machine in ("i386", "i686", "x86"):
        arch = "i686"
    else:
        return None
    if sys.platform.startswith("linux"):
        osn = "linux"
    elif sys.platform == "darwin":
        osn = "macos"
    elif _IS_WIN:
        osn = "windows"
    else:
        return None
    return osn, arch


def find_tor_binary() -> str | None:
    """Locate a tor executable: our own bundle, PATH, then well-known install spots."""
    own = tor_dir() / "bundle" / "tor" / _EXE
    if own.exists():
        return str(own)
    on_path = shutil.which("tor")
    if on_path:
        return on_path
    home = Path.home()
    candidates = [
        "/usr/bin/tor", "/usr/sbin/tor", "/usr/local/bin/tor", "/opt/homebrew/bin/tor",
        "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor",
        home / ".local/share/torbrowser/tbb/x86_64/tor-browser/Browser/TorBrowser/Tor/tor",
        home / "Desktop/Tor Browser/Browser/TorBrowser/Tor/tor.exe",
        home / "Downloads/Tor Browser/Browser/TorBrowser/Tor/tor.exe",
        "C:/Program Files/Tor Browser/Browser/TorBrowser/Tor/tor.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return str(c)
    return None


def _http_get(url: str, timeout: float = 30.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "legalPrivacy-installer"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # nosec - fixed https host
        return r.read()


def _version_key(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def _torrc_quote(path: Path) -> str:
    return '"' + str(path).replace("\\", "/") + '"'


# ── bridges vs. the avoid list ───────────────────────────────────────────────
# Snowflake, meek and conjure bridge lines carry a placeholder address from TEST-NET-1: the real connection goes to a broker
# or a CDN, never to that address. Tor's GeoIP has no country for it, so with any {country} in ExcludeNodes Tor's default
# (GeoIPExcludeUnknown auto) refuses those bridges outright: "Not using bridge at [scrubbed]: it is in ExcludeNodes".
PLACEHOLDER_NETS = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("2001:db8::/32"))   # webtunnel uses the IPv6 one
_BRIDGE_ADDR = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*\s+)?(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]+\]):\d+(?:\s+([0-9A-Fa-f]{40}))?")
_geoip_cache: dict[str, tuple[list[int], list[tuple[int, str]]]] = {}


def geoip_country(ip: str, geoip_file: Path | None) -> str:
    """Two-letter country (lower case) of an IPv4 address in Tor's own GeoIP file, '??' if unknown or no file."""
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return "??"
    if addr.version != 4 or not geoip_file:
        return "??"
    key = str(geoip_file)
    if key not in _geoip_cache:
        starts, rows = [], []
        try:
            with open(geoip_file, encoding="ascii", errors="ignore") as fh:
                for ln in fh:
                    if ln[:1].isdigit():
                        a, b, cc = ln.strip().split(",")[:3]
                        starts.append(int(a))
                        rows.append((int(b), cc.lower()))
        except (OSError, ValueError):
            starts, rows = [], []
        _geoip_cache[key] = (starts, rows)
    starts, rows = _geoip_cache[key]
    n = int(addr)
    i = bisect.bisect_right(starts, n) - 1
    return rows[i][1] if i >= 0 and rows[i][0] >= n else "??"


def bridge_refusal(line: str, countries: set[str], nets: list, fingerprints: set[str], geoip_file: Path | None) -> str | None:
    """Why Tor would refuse this bridge under the avoid list (so the app never offers it), or None if it is usable.
    The avoid list itself is never loosened: a bridge in an avoided country, range or identity is dropped."""
    m = _BRIDGE_ADDR.match(line.strip())
    if not m:
        return "not a bridge line"
    ip, fp = m.group(1).strip("[]"), (m.group(2) or "").upper()
    if fp and fp in fingerprints:
        return "its relay is on the avoid list"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "bad address"
    if any(addr.version == p.version and addr in p for p in PLACEHOLDER_NETS):
        return None                                   # Snowflake/meek/webtunnel: not a real address, nothing to geolocate
    for n in nets:
        if addr.version == n.version and addr in n:
            return f"its address is in {n}"
    cc = geoip_country(ip, geoip_file)
    if cc in countries:
        return f"it is in {{{cc}}}"
    return None


# ── manager ─────────────────────────────────────────────────────────────────
class TorManager:
    """Owns the lifecycle of the Tor the app uses. Thread-safe, non-blocking API."""

    def __init__(self, log: EventLog, mode: str = "managed",
                 socks: str = "127.0.0.1:9050", control: str | None = "127.0.0.1:9051",
                 control_password: str | None = None, bridges: list[str] | None = None,
                 bridge_mode: str = "off", bridge_auto: bool = True,
                 auto_install: bool = True, dns_port: int = 0, dns_lan: bool = False,
                 dns_lan_addr: str = "", exclude_nodes: list[str] | None = None,
                 share_browser: bool = False):
        self.log = log
        self.share_browser = bool(share_browser)
        self.user_socks_port = 0
        self.exclude_nodes = [e.strip() for e in (exclude_nodes or []) if e.strip()]
        self.mode = mode                      # managed | external
        self.ext_socks, self.ext_control = socks, control
        self.control_password = control_password
        self.bridges = [b.strip() for b in (bridges or []) if b.strip()]
        self.bridge_mode = bridge_mode          # off | obfs4 | snowflake | meek | custom (may change by itself)
        self.configured_bridge_mode = bridge_mode   # what the user chose
        self.bridge_auto = bridge_auto          # try built-in bridges if a direct connection gets stuck
        self._attempt = 0                       # position on the ladder (see ladder())
        self._rounds = 0                        # full rounds of the ladder without connecting
        self._recovering: float | None = None   # the start a recovery is already under way for
        self._wipe_next = False
        self._refused_since: float | None = None   # when Tor first said a bridge is in ExcludeNodes (this start)
        self._refused_n = 0
        self.bridge_in_use: dict | None = None  # the bridge Tor is connected through right now
        self.auto_install = auto_install
        self.dns_port_cfg, self.dns_lan, self.dns_lan_addr = dns_port, dns_lan, dns_lan_addr   # Tor DNS (optional)
        self.dns_host = tordns.bind_address(dns_lan, dns_lan_addr)
        self.dns_port = 0                       # the port actually in use (set when Tor is launched)

        self.state = "stopped"   # stopped|installing|starting|bootstrapping|ready|error
        self.error: str | None = None
        self.bootstrap_pct = 0
        self.bootstrap_summary = ""
        self.version: str | None = None
        self.version_status: str | None = None   # Tor's own verdict on its version: recommended | new | old | unrecommended | obsolete...
        self.alert: str | None = None            # shown in red until the problem is gone (an obsolete Tor, a failed update)
        self._version_checked = False
        self._upgrading = False
        self.binary: str | None = None
        self.pid: int | None = None
        self.started_at: float | None = None
        self.socks_host, self.socks_port = "127.0.0.1", 0
        self.control_host, self.control_port = "127.0.0.1", 0
        self.cookie_path: str | None = None
        self.stats: dict[str, Any] = {"read": 0, "written": 0, "circuits_built": 0, "circuits": []}
        self.install_progress = 0.0

        self._proc: subprocess.Popen | None = None
        self._lock = threading.RLock()
        self._worker: threading.Thread | None = None
        self._monitor: threading.Thread | None = None
        self._stop_evt = threading.Event()

    # -- public API (all non-blocking) -------------------------------------
    @property
    def socks_addr(self) -> str:
        return f"{self.socks_host}:{self.socks_port}"

    @property
    def control_addr(self) -> str | None:
        return f"{self.control_host}:{self.control_port}" if self.control_port else None

    @property
    def ready(self) -> bool:
        return self.state == "ready"

    def start(self) -> None:
        """Begin bringing Tor up in the background (install → launch → bootstrap)."""
        with self._lock:
            if self._worker and self._worker.is_alive():
                return
            if self.state in ("starting", "bootstrapping", "ready", "installing"):
                return
            self._stop_evt.clear()
            self.error = None
            self._version_checked = False
            self._worker = threading.Thread(target=self._bring_up, daemon=True, name="tor-start")
            self._worker.start()

    def stop(self) -> None:
        self._stop_evt.set()
        with self._lock:
            proc = self._proc
        if proc and proc.poll() is None:
            self.log.info("tor", "Stopping Tor…")
            try:
                with TorControl(self.control_host, self.control_port,
                                self.control_password, self.cookie_path, timeout=3) as c:
                    c.shutdown()
            except Exception:
                pass
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()
            self.log.info("tor", "Tor stopped.")
        elif self.mode == "external" and self.state != "stopped":
            self.log.info("tor", "Detached from external Tor (it is left running).")
        with self._lock:
            self._proc, self.pid = None, None
            self.state = "stopped"
            self.bootstrap_pct = 0

    def restart(self) -> None:
        def _r():
            self.stop()
            time.sleep(0.5)
            self.start()
        threading.Thread(target=_r, daemon=True, name="tor-restart").start()

    def new_identity(self) -> bool:
        """SIGNAL NEWNYM: fresh circuits for new connections."""
        if self.share_browser:       # it would cut off the pages you have open in Tor Browser
            self.log.info("tor", "New identity skipped: Tor is shared with Tor Browser (use its own New Identity button).")
            return False
        try:
            with TorControl(self.control_host, self.control_port,
                            self.control_password, self.cookie_path) as c:
                c.newnym()
            self.log.info("tor", "New Tor identity requested (NEWNYM).")
            return True
        except Exception as exc:
            self.log.warn("tor", f"NEWNYM failed: {exc}")
            return False

    def install(self) -> None:
        """Download + verify the official Tor Expert Bundle (background)."""
        threading.Thread(target=self._install_safe, daemon=True, name="tor-install").start()

    def snapshot(self) -> dict[str, Any]:
        uptime = int(time.time() - self.started_at) if self.started_at and self.state != "stopped" else 0
        return {
            "mode": self.mode, "state": self.state, "error": self.error,
            "bootstrap_pct": self.bootstrap_pct, "bootstrap_summary": self.bootstrap_summary,
            "version": self.version, "binary": self.binary or find_tor_binary(),
            "installed_bundle": (tor_dir() / "bundle" / "tor" / _EXE).exists(),
            "pid": self.pid, "uptime": uptime,
            "socks": self.socks_addr if self.socks_port else None,
            "control": self.control_addr, "bridges": len(self.effective_bridges()),
            "bridge_mode": self.bridge_mode, "builtin": {k: len(v) for k, v in self.builtin_bridges().items()},
            "bridge_in_use": self.bridge_in_use, "bridge_label": self.bridge_label(),
            "install_progress": self.install_progress,
            "dns": self.dns_info(), "shared_browser": bool(self.share_browser and self.user_socks_port),
            "supported_platform": platform_key() is not None,
            "hint": self._hint(uptime),
            **{k: self.stats.get(k) for k in ("read", "written", "circuits_built")},
        }

    def bridge_label(self) -> str:
        """For the Details card: 'none (direct)', or the bridge type and, once connected, the one in use."""
        if self.bridge_mode == "off" or not self.effective_bridges():
            return "none (direct)"
        kind = "your saved" if self.bridge_mode == "custom" else f"built-in {self.bridge_mode}"
        b = self.bridge_in_use
        if not b:
            return f"{kind} ({len(self.usable_bridges())} usable; connecting)" if self.state != "ready" else kind
        where = (f"{b['address']}" + (f", {b['country'].upper()}" if b.get("country") and b["country"] != "??" else "")
                 if b.get("address") else "via the " + b["transport"] + " network")
        auto = " (chosen automatically)" if self.bridge_mode != self.configured_bridge_mode else ""
        return f"{b['transport']} {where}, {b['fingerprint'][:8]}…{auto}"

    def dns_info(self) -> dict:
        """Tor DNS state: whether it is switched on, where it listens, whether Tor is serving it now."""
        on = self.dns_port_cfg != 0
        managed = self.mode == "managed"
        live = bool(on and managed and self.dns_port and self.state == "ready")
        return {"on": on, "managed": managed, "address": self.dns_host if on else None,
                "port": self.dns_port if on and self.dns_port else None, "lan": bool(on and self.dns_lan),
                "ready": live}

    def circuits(self) -> list[dict]:
        return list(self.stats.get("circuits", []))

    def _hint(self, uptime: int) -> str | None:
        if self.state == "bootstrapping" and uptime > 60 and self.bootstrap_pct < 30:
            return ("Tor is stuck connecting. Your network may block Tor — add bridges "
                    "(bridges.torproject.org) in the Bridges box below, then Restart.")
        if self.state == "error" and "unexpectedly" in (self.error or ""):
            return "Check the Tor log below for the reason (port in use, bad bridge line, permissions)."
        return None

    # -- bring-up ----------------------------------------------------------
    def _bring_up(self) -> None:
        try:
            if self.mode == "external":
                self._attach_external()
            else:
                self._launch_managed()
        except Exception as exc:     # surfaced in UI, never crashes the app
            self._fail(str(exc))

    def _fail(self, msg: str) -> None:
        self.error = msg
        self.state = "error"
        self.log.error("tor", msg)

    def _attach_external(self) -> None:
        self.state = "starting"
        self.socks_host, self.socks_port = split_hostport(self.ext_socks, 9050)
        candidates = [(self.socks_host, self.socks_port)]
        if self.socks_port == 9050:
            candidates.append(("127.0.0.1", 9150))     # Tor Browser default
        for host, port in candidates:
            if port_open(host, port):
                self.socks_host, self.socks_port = host, port
                break
        else:
            raise RuntimeError(f"No Tor found at {self.ext_socks}. Switch to 'managed' mode "
                               "and legalPrivacy will run its own private Tor.")
        if self.ext_control:
            self.control_host, self.control_port = split_hostport(self.ext_control, 9051)
            if self.socks_port == 9150 and self.control_port == 9051:
                self.control_port = 9151
        self.log.info("tor", f"Using external Tor at {self.socks_addr}")
        self.started_at = time.time()
        self.state = "ready"
        self.bootstrap_pct = 100
        self._start_monitor()

    def _launch_managed(self) -> None:
        self.state = "starting"
        self.binary = find_tor_binary()
        if not self.binary:
            if not self.auto_install:
                raise RuntimeError("Tor is not installed. Click 'Install Tor' on the Tor tab.")
            self.log.info("tor", "Tor not found on this computer — installing the official bundle…")
            self.state = "installing"
            self._install()
            self.binary = find_tor_binary()
            if not self.binary:
                raise RuntimeError("Tor installation did not produce a usable binary.")
        own = tor_dir() / "bundle" / "tor" / _EXE
        if self.auto_install and Path(self.binary) != own:
            # The Tor on this computer (a distribution package, Tor Browser's copy) is usually behind. The app runs its own
            # up-to-date Tor, installed with the signature checked; the other one is only used if that is impossible.
            self.log.info("tor", "Installing the app's own current Tor (the one on this computer may be out of date)…")
            self.state = "installing"
            try:
                self._install()
                self.binary = find_tor_binary()
            except Exception as exc:
                self.alert = (f"Could not install the current official Tor ({exc}); using the Tor already on this computer, "
                              "which may be out of date.")
                self.log.warn("tor", self.alert)
            self.state = "starting"
        self._maybe_update_bundle()
        if self._stop_evt.is_set():
            return
        self.state = "starting"
        data_dir = tor_dir() / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        try:
            data_dir.chmod(0o700)
        except OSError:
            pass
        self.socks_host, self.socks_port = "127.0.0.1", _pick_port(19050)
        self.control_host, self.control_port = "127.0.0.1", _pick_port(19051)
        if self.control_port == self.socks_port:
            self.control_port = _pick_port(0)
        self.user_socks_port = 0
        if self.share_browser:            # a second door for Tor Browser: its streams never share circuits with the noise
            self.user_socks_port = _pick_port(19150)
            if self.user_socks_port in (self.socks_port, self.control_port):
                self.user_socks_port = _pick_port(0)
        self.dns_port = (_pick_udp_port(self.dns_host, self.dns_port_cfg or tordns.DEFAULT_PORT)
                         if self.dns_port_cfg else 0)
        self.cookie_path = str(tor_dir() / "control_auth_cookie")
        try:                                       # a Tor left by an earlier run would hold the data folder and the ports
            from .procclean import kill_stale_tors
            kill_stale_tors(self.log)
        except Exception as exc:
            self.log.info("tor", f"Leftover-Tor check failed: {exc!r}")
        torrc = self._write_torrc(data_dir)
        env = os.environ.copy()
        libdir = str(Path(self.binary).parent)
        env["LD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
        env["DYLD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("DYLD_LIBRARY_PATH", "")
        self.log.info("tor", f"Launching Tor ({self.binary}) SOCKS {self.socks_addr}, control {self.control_addr}")
        creation = 0x08000000 if _IS_WIN else 0     # CREATE_NO_WINDOW
        self._proc = subprocess.Popen(
            [self.binary, "-f", str(torrc)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1, env=env, creationflags=creation)
        self.pid = self._proc.pid
        self.started_at = time.time()
        self.state = "bootstrapping"
        self.bootstrap_pct = 0
        self._refused_since, self._refused_n, self.bridge_in_use = None, 0, None
        threading.Thread(target=self._pump_output, args=(self._proc,), daemon=True,
                         name="tor-log").start()
        threading.Thread(target=self._watchdog, args=(self.started_at,), daemon=True, name="tor-watchdog").start()
        self._start_monitor()

    def _write_torrc(self, data_dir: Path) -> Path:
        lines = [
            f"DataDirectory {_torrc_quote(data_dir)}",
            f"SocksPort {self.socks_addr} IsolateSOCKSAuth",
            f"ControlPort {self.control_addr}",
            "CookieAuthentication 1",
            f"CookieAuthFile {_torrc_quote(Path(self.cookie_path))}",
            "ClientOnly 1",
            "AvoidDiskWrites 1",
            "SafeSocks 1",                           # refuse SOCKS requests that leak a local DNS lookup
            "ClientDNSRejectInternalAddresses 1",   # an answer that points inside your network is refused
            "ClientRejectInternalAddresses 1",
            "Log notice stdout",
        ]
        if self.user_socks_port:
            lines.append(f"SocksPort 127.0.0.1:{self.user_socks_port} IsolateSOCKSAuth IsolateClientAddr "
                         "IsolateDestAddr IsolateDestPort")
        dns_line = tordns.torrc_line(self.dns_port, self.dns_lan, self.dns_lan_addr) if self.dns_port else None
        if dns_line:        # optional Tor DNS: loopback unless one private LAN address was explicitly chosen
            lines.append(dns_line)
        excl, countries, _nets, _fps = self.avoid_list()
        if excl:                                  # relays you don't trust: Tor avoids them for every hop, bridges included
            lines += ["ExcludeNodes " + ",".join(excl), "StrictNodes 1"]
            if countries:
                # Tor's default (GeoIPExcludeUnknown auto) would also refuse every address it cannot place in a country, which
                # is exactly the placeholder address Snowflake and meek bridges use, so they could never connect. Unknown-country
                # RELAYS stay excluded: they are listed one by one above (from Tor's public relay list, see geoban.py).
                lines.append("GeoIPExcludeUnknown 0")
            self.log.info("tor", f"Avoiding {len(excl)} relay(s)/countries/ranges at every hop ({len(BANNED_RELAYS)} banned "
                                 "for good) (strictly, always).")
        for name, key in (("geoip", "GeoIPFile"), ("geoip6", "GeoIPv6File")):
            if (self._bundle_data() / name).exists():
                lines.append(f"{key} {_torrc_quote(self._bundle_data() / name)}")
        bridges = self.usable_bridges(log=True)
        if self.effective_bridges() and not bridges:
            self.log.warn("tor", f"None of the {self.bridge_mode} bridges can be used with your avoid list; trying something else.")
        if bridges:
            lines.append("UseBridges 1")
            for transport in sorted({b.split()[0] for b in bridges if re.match(r"[A-Za-z_]", b)}):
                line = self._pt_line(transport)
                if line:
                    lines.append(line)
                else:
                    self.log.warn("tor", f"No pluggable-transport program found for '{transport}' bridges.")
            lines += [f"Bridge {b}" for b in bridges]
            self.log.info("tor", f"Using {len(bridges)} {self.bridge_mode if self.bridge_mode != 'custom' else 'saved'} "
                                 "bridge(s).")
        path = tor_dir() / "torrc"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    # ── bridges ───────────────────────────────────────────────────────────
    def pt_config(self) -> dict:
        """The bundle's own pluggable_transports/pt_config.json (built-in bridges + how to run each PT)."""
        binary = self.binary or find_tor_binary()
        if not binary:
            return {}
        p = Path(binary).resolve().parent / "pluggable_transports" / "pt_config.json"
        try:
            import json
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def builtin_bridges(self) -> dict[str, list[str]]:
        return {k: list(v) for k, v in (self.pt_config().get("bridges") or {}).items()}

    def _bundle_data(self) -> Path:
        binary = self.binary or find_tor_binary() or ""
        return Path(binary).resolve().parent.parent / "data" if binary else Path("/nonexistent")

    def avoid_list(self) -> tuple[list[str], set[str], list, set[str]]:
        """(ExcludeNodes entries, avoided countries, avoided address ranges, avoided fingerprints). Never loosened by the app."""
        from .config import valid_exclude_entry
        excl = [e if e.startswith("{") else "$" + e.lstrip("$") for e in self.exclude_nodes if valid_exclude_entry(e)]
        excl += ["$" + fp for fp in BANNED_RELAYS if "$" + fp not in excl]     # relays banned for good (see config.BANNED_RELAYS)
        if getattr(self, "geoban", True):                                      # government ranges and Virginia relays (see geoban.py)
            try:
                from . import geoban
                excl += [e for e in geoban.shared().tor_excludes() if e not in excl]
            except Exception as exc:
                self.log.info("tor", f"Address ban not applied to Tor: {exc!r}")
        countries = {e.strip("{}").lower() for e in excl if e.startswith("{")}
        if countries:                              # relays Tor cannot place in a country: excluded one by one (see _write_torrc)
            try:
                from . import geoban
                excl += [e for e in ("$" + f for f in geoban.shared().unknown_country) if e not in excl]
            except Exception:
                pass
        nets = []
        for e in excl:
            if not e.startswith(("{", "$")):
                try:
                    nets.append(ipaddress.ip_network(e, strict=False))
                except ValueError:
                    pass
        fps = {e[1:].upper() for e in excl if e.startswith("$")}
        return excl, countries, nets, fps

    def usable_bridges(self, mode: str | None = None, log: bool = False) -> list[str]:
        """The bridges of a mode that are well formed and that the avoid list allows (Tor would refuse the others)."""
        lines = self.bridges_for(self.bridge_mode if mode is None else mode)
        good = [b for b in lines if valid_bridge_line(b)]          # one line each, never a setting
        if log and len(good) != len(lines):
            self.log.warn("tor", "Ignored bridge line(s) that were not in the usual bridge format.")
        _excl, countries, nets, fps = self.avoid_list()
        geo = self._bundle_data() / "geoip"
        out, dropped = [], []
        for b in good:
            why = bridge_refusal(b, countries, nets, fps, geo)
            (dropped if why else out).append(why or b)
        if log and dropped:
            self.log.info("tor", f"Skipped {len(dropped)} bridge(s) your avoid list rules out ({'; '.join(sorted(set(dropped)))}); "
                                 f"{len(out)} left.")
        return out

    def bridges_for(self, mode: str) -> list[str]:
        if mode == "custom":
            return list(self.bridges)
        if mode in ("obfs4", "snowflake", "meek"):
            return self.builtin_bridges().get(mode, [])
        return []

    def effective_bridges(self) -> list[str]:
        if self.bridge_mode == "custom":
            return list(self.bridges)
        if self.bridge_mode in ("obfs4", "snowflake", "meek"):
            return self.builtin_bridges().get(self.bridge_mode, [])
        return []

    def _pt_line(self, transport: str) -> str | None:
        """A ClientTransportPlugin line: from the bundle's pt_config.json when present, else by binary name."""
        pt_dir = Path(self.binary).resolve().parent / "pluggable_transports"
        for entry in (self.pt_config().get("pluggableTransports") or {}).values():
            m = re.match(r"ClientTransportPlugin\s+(\S+)\s+exec\s+(.*)$", entry)
            if m and transport in m.group(1).split(","):
                cmd = m.group(2).replace("${pt_path}", str(pt_dir) + os.sep)
                return f"ClientTransportPlugin {transport} exec {cmd}"
        exe = self._pt_binary(transport)
        return f"ClientTransportPlugin {transport} exec {exe}" if exe else None

    # ── staying connected ────────────────────────────────────────────────
    STALL_SECS = 90            # no bootstrap progress for this long (and not connected) = stuck
    REFUSED_SECS = 20          # every bridge refused by the avoid list for this long = stuck (it will never change by itself)
    MAX_BACKOFF = 600
    RETRY_DELAY = 2            # seconds before the next way is tried

    def ladder(self) -> list[str]:
        """Ways to connect, in order: what you chose, then direct, then each built-in bridge type, then your own bridges.
        A way whose bridges the avoid list rules out entirely is skipped. The avoid list is never part of what changes."""
        order = [self.configured_bridge_mode]
        if self.bridge_auto:
            order += ["off", "obfs4", "snowflake", "meek", "custom"]
        out = []
        for m in order:
            if m in out or (m == "custom" and not self.bridges):
                continue
            if m != "off" and not self.usable_bridges(m):
                continue
            out.append(m)
        return out or ["off"]

    def _watchdog(self, started: float) -> None:
        """Watches one start. Stuck (no progress, Tor exited, or every bridge refused) -> the next way on the ladder."""
        last_pct, last_move = -1, time.time()
        while not self._stop_evt.wait(5) and self.started_at == started:
            if self.state == "ready":
                if self._attempt or self._rounds:
                    self.log.info("tor", f"Connected ({self.bridge_mode if self.bridge_mode != 'off' else 'direct'}).")
                self._attempt, self._rounds = 0, 0
                return
            if self.state == "stopped":
                return
            now = time.time()
            if self.bootstrap_pct > last_pct:
                last_pct, last_move = self.bootstrap_pct, now
            refused = self._refused_since and now - self._refused_since > self.REFUSED_SECS and self.bootstrap_pct < 10
            if self.state == "error" or now - last_move > self.STALL_SECS or refused:
                why = ("Tor stopped" if self.state == "error" else "every bridge was refused by the avoid list" if refused
                       else f"no progress for {int(now - last_move)} s at {self.bootstrap_pct}%")
                self._recover(why, started)
                return

    def _recover(self, why: str, started: float | None = None) -> None:
        """Move to the next way of connecting; after the last one, reset Tor completely (fresh data folder) and start the
        ladder again, waiting longer each round. Stops only when you stop Tor. Never touches the avoid list."""
        with self._lock:
            if self.mode != "managed" or self._stop_evt.is_set() or self._recovering == (started or self.started_at):
                return
            self._recovering = started or self.started_at
            ladder = self.ladder()
            self._attempt += 1
            delay = self.RETRY_DELAY
            if self._attempt >= len(ladder):
                self._attempt, self._rounds = 0, self._rounds + 1
                delay = min(30 * 2 ** (self._rounds - 1), self.MAX_BACKOFF)
                self._wipe_next = True
            mode = ladder[self._attempt]
        how = "directly" if mode == "off" else f"with the {'saved' if mode == 'custom' else 'built-in ' + mode} bridges"
        if self._wipe_next:
            self.log.warn("tor", f"Tor could not connect ({why}), and every way has been tried. Resetting Tor completely "
                                 f"(fresh state, nothing cached) and trying again {how} in {delay} s. Your avoid list stays "
                                 "as it is.")
        else:
            self.log.warn("tor", f"Tor could not connect ({why}). Trying {how}.")

        def go():
            if self._stop_evt.wait(delay) and self.state == "stopped":
                return                       # you stopped Tor meanwhile
            if self.started_at != (started or self._recovering):
                return                       # someone else restarted it
            self.bridge_mode = mode
            self.stop()
            if self._wipe_next:
                self._wipe_next = False
                self._wipe_state()
            self._recovering = None
            self.start()
        threading.Thread(target=go, daemon=True, name="tor-recover").start()

    def _wipe_state(self) -> None:
        """Delete Tor's data folder (guards, cached relay lists, state): the next start is like a first start."""
        data = tor_dir() / "data"
        try:
            shutil.rmtree(data, ignore_errors=True)
            self.log.info("tor", "Tor's saved state was deleted; it starts fresh.")
        except Exception as exc:
            self.log.info("tor", f"Could not delete Tor's saved state: {exc!r}")

    def _pt_binary(self, transport: str) -> str | None:
        pt_dir = Path(self.binary).resolve().parent / "pluggable_transports"
        names = {"obfs4": ["lyrebird", "obfs4proxy"], "meek_lite": ["lyrebird"],
                 "webtunnel": ["lyrebird"], "conjure": ["conjure-client"],
                 "snowflake": ["lyrebird", "snowflake-client"]}.get(transport, [transport])
        for n in names:
            for cand in (pt_dir / n, pt_dir / f"{n}.exe"):
                if cand.exists():
                    return str(cand)
            found = shutil.which(n)
            if found:
                return found
        return None

    def _pump_output(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:           # type: ignore[union-attr]
            line = line.rstrip()
            if not line:
                continue
            m = BOOTSTRAP_RE.search(line)
            if m:
                self.bootstrap_pct = int(m.group(1))
                self.bootstrap_summary = m.group(3)
                if self.bootstrap_pct >= 100 and self.state in ("bootstrapping", "starting"):
                    self.state = "ready"
                    self.log.info("tor", "Tor is ready (bootstrapped 100%).")
            refused = "Not using bridge" in line and "ExcludeNodes" in line
            if refused:
                self._refused_n += 1
                if self._refused_since is None:
                    self._refused_since = time.time()
                    self.log.warn("tor", line + "  (A bridge is on the avoid list, so Tor skips it. Further repeats of this "
                                                "line are hidden; the app moves on to other bridges if none can be used.)")
                continue                         # Tor repeats it every second for as long as it runs: once is enough
            level = "warn" if "[warn]" in line else "error" if "[err]" in line else "info"
            if "[debug]" in line or "[info]" in line:
                level = "debug"
            self.log.add(level, "tor", line)
        code = proc.wait()
        if proc is not self._proc:          # an older Tor that was stopped or replaced: not a failure of the new one
            return
        if not self._stop_evt.is_set() and self.state != "stopped":
            self._fail(f"Tor exited unexpectedly (code {code}). See the log for details.")
            self._recover(f"Tor exited with code {code}")

    # -- monitor -----------------------------------------------------------
    def _start_monitor(self) -> None:
        if self._monitor and self._monitor.is_alive():
            return
        self._monitor = threading.Thread(target=self._monitor_loop, daemon=True, name="tor-monitor")
        self._monitor.start()

    def _monitor_loop(self) -> None:
        ctrl: TorControl | None = None
        last_err = ""
        while not self._stop_evt.is_set() and self.state not in ("stopped", "error"):
            try:
                if ctrl is None:
                    if not self.control_port or not port_open(self.control_host, self.control_port):
                        time.sleep(1)
                        continue
                    ctrl = TorControl(self.control_host, self.control_port,
                                      self.control_password, self.cookie_path, timeout=4)
                    ctrl.connect()
                    self.version = ctrl.getinfo("version")
                self._poll(ctrl)
            except TorControlError as exc:
                if ctrl:
                    ctrl.close()
                ctrl = None
                if self.mode == "external" or self.state == "ready":
                    self.stats.setdefault("control_error", str(exc))
            except Exception as exc:               # a bug or odd reply: keep monitoring, but say so (once per kind)
                if ctrl:
                    ctrl.close()
                ctrl = None
                if repr(exc) != last_err:
                    last_err = repr(exc)
                    self.log.debug("tor", f"Tor monitor error: {last_err}")
            self._stop_evt.wait(2.0)
        if ctrl:
            ctrl.close()

    # Tor's own word for each version: it compares itself with the list the directory authorities publish.
    GOOD_VERSION = ("recommended", "new", "new in series")

    def _check_version(self, c: TorControl) -> None:
        """Once per start: ask Tor whether its version is still supported. An obsolete Tor is not acceptable: say so loudly,
        install the current official Tor (its signature checked) and restart on it."""
        if self._version_checked:
            return
        self._version_checked = True
        try:
            status = (c.getinfo("status/version/current") or "").strip().lower()
        except TorControlError:
            return
        self.version_status = status
        if status in self.GOOD_VERSION or not status:
            self.alert = None
            return
        own = tor_dir() / "bundle" / "tor" / _EXE
        using_own = bool(self.binary) and Path(self.binary) == own
        why = (f"The Tor in use ({self.version or 'unknown version'}) is {status}: the Tor network no longer fully supports it, "
               "which can make onion visits fail even though Tor says it is connected.")
        if self.mode != "managed" or not self.auto_install or using_own:
            self.alert = why + (" This is the newest official Tor the app can install, so the Tor network itself may be "
                                "changing: check torproject.org." if using_own else
                                " Update it, or let the app run its own verified Tor (Tor tab).")
            self.log.error("tor", "PANIC: " + self.alert)
            return
        self.alert = why + " Installing the current official Tor now (its signature is checked)."
        self.log.error("tor", "PANIC: " + self.alert)
        self._upgrade_tor()

    def _upgrade_tor(self) -> None:
        with self._lock:
            if self._upgrading:
                return
            self._upgrading = True

        def run() -> None:
            try:
                self._install()                                   # official bundle: signature and checksum checked
                self.binary = find_tor_binary()                   # the app's own copy comes first from now on
                self.log.info("tor", "The current Tor is installed and verified. Restarting Tor on it.")
                self.alert = "Tor was out of date; it is being replaced with the current official version and restarted."
                self.restart()
            except Exception as exc:
                self.alert = (f"Tor is out of date and the update failed: {exc}. Fix that (for example install GnuPG, "
                              "or check the network) and restart Tor; the app tries again in six hours.")
                self.log.error("tor", "PANIC: " + self.alert)
                threading.Timer(6 * 3600, lambda: setattr(self, "_version_checked", False)).start()
            finally:
                self._upgrading = False
        threading.Thread(target=run, daemon=True, name="tor-upgrade").start()

    def _poll(self, c: TorControl) -> None:
        if self.state == "ready":
            self._check_version(c)
        phase = c.getinfo("status/bootstrap-phase")
        m = re.search(r"PROGRESS=(\d+)", phase)
        if m and self.mode == "managed":
            self.bootstrap_pct = max(self.bootstrap_pct, int(m.group(1)))
            s = re.search(r'SUMMARY="([^"]*)"', phase)
            if s:
                self.bootstrap_summary = s.group(1)
            if self.bootstrap_pct >= 100 and self.state == "bootstrapping":
                self.state = "ready"
        circs = c.circuits()
        self.stats.update({
            "read": int(c.getinfo("traffic/read") or 0),
            "written": int(c.getinfo("traffic/written") or 0),
            "circuits": circs,
            "circuits_built": sum(1 for x in circs if x["status"] == "BUILT"),
        })
        self.stats.pop("control_error", None)
        if self.effective_bridges():
            try:
                self.bridge_in_use = self._bridge_now(c.getinfo("entry-guards"))
            except TorControlError:
                pass
        else:
            self.bridge_in_use = None

    def _bridge_now(self, guards: str) -> dict | None:
        """Which of our bridges Tor is using, from GETINFO entry-guards ('$FP~nick up' lines; the first usable is used)."""
        by_fp = {}
        for b in self.usable_bridges():
            m = _BRIDGE_ADDR.match(b)
            if m and m.group(2):
                by_fp[m.group(2).upper()] = b
        for ln in guards.splitlines():
            parts = ln.split()
            if len(parts) < 2 or parts[1] != "up":
                continue
            fp = parts[0].lstrip("$").split("~")[0].split("=")[0].upper()
            line = by_fp.get(fp)
            if line:
                transport = line.split()[0] if re.match(r"[A-Za-z_]", line) else "vanilla"
                addr = line.split()[1] if transport != "vanilla" else line.split()[0]
                placeholder = addr.startswith(("192.0.2.", "[2001:db8:"))
                return {"transport": transport, "address": None if placeholder else addr, "fingerprint": fp,
                        "country": None if placeholder else geoip_country(addr.rsplit(":", 1)[0], self._bundle_data() / "geoip")}
        return None

    # -- installer ---------------------------------------------------------
    def _install_safe(self) -> None:
        try:
            prev, self.state = self.state, "installing"
            self._install()
            self.state = "stopped" if prev in ("stopped", "error") else prev
        except Exception as exc:
            self._fail(f"Tor install failed: {exc}")

    @staticmethod
    def _pick_bundle(osn: str, arch: str) -> tuple[str, str]:
        """(version, file name) of the newest Tor Expert Bundle for this computer."""
        index = _http_get(DIST_BASE).decode("utf-8", "ignore")
        versions = sorted({v for v in re.findall(r'href="(\d+(?:\.\d+)+)/"', index)},
                          key=_version_key, reverse=True)
        for ver in versions[:6]:            # newest stable first; skip dirs without desktop bundle
            fname = f"tor-expert-bundle-{osn}-{arch}-{ver}.tar.gz"
            if fname in _http_get(f"{DIST_BASE}{ver}/").decode("utf-8", "ignore"):
                return ver, fname
        raise RuntimeError("Could not find a Tor Expert Bundle for this platform on dist.torproject.org")

    @staticmethod
    def bundle_version() -> str | None:
        try:
            return (tor_dir() / "bundle" / "VERSION").read_text().strip() or None
        except OSError:
            return None

    def _maybe_update_bundle(self) -> None:
        """The Tor the app downloaded itself is kept current: once a day, before it starts, the newest official
        bundle is looked up and installed if it is newer. Tor you installed yourself is never touched."""
        own = tor_dir() / "bundle" / "tor" / _EXE
        if not self.auto_install or not self.binary or Path(self.binary) != own:
            return
        stamp = tor_dir() / "update_checked"
        try:
            if time.time() - float(stamp.read_text()) < 86400:
                return
        except (OSError, ValueError):
            pass
        try:
            key = platform_key()
            if not key:
                return
            ver, _ = self._pick_bundle(*key)
            stamp.write_text(str(time.time()))
            have = self.bundle_version()
            if have is None or _version_key(ver) > _version_key(have):
                self.log.info("tor", f"A newer Tor is available ({have or 'unknown'} -> {ver}). Updating before it starts…")
                self.state = "installing"
                self._install()
                self.binary = find_tor_binary()
        except Exception as exc:                  # offline or the site is down: carry on with what is installed
            self.log.info("tor", f"Couldn't check for a newer Tor ({exc}); using the installed one.")

    def _verify_sums_signature(self, sums: bytes, sig: bytes) -> None:
        """The checksum file must carry a valid OpenPGP signature from the Tor Browser Developers key (the fingerprint is
        pinned in torbrowser.py); then the bundle's checksum is checked against it. No GnuPG, no valid signature: no install."""
        import tempfile

        from . import torbrowser as TB
        try:
            key = TB._http_get(TB.KEY_URL)
            with tempfile.TemporaryDirectory(prefix="lp-tor-") as d:
                (Path(d) / "sums").write_bytes(sums)
                (Path(d) / "sums.asc").write_bytes(sig)
                TB.verify_signature(Path(d) / "sums", Path(d) / "sums.asc", key)
        except TB.TorBrowserError as exc:
            raise RuntimeError(f"the signature on Tor's checksum file could not be verified ({exc})") from exc
        self.log.info("tor", "Signature on the checksum file verified (Tor Browser Developers key).")

    def refresh_if_newer(self) -> bool:
        """While Tor runs: if a newer official Tor exists, install it (checked) and restart Tor on it. True if it did."""
        own = tor_dir() / "bundle" / "tor" / _EXE
        if not self.auto_install or self.mode != "managed" or self.state != "ready" or self._upgrading:
            return False
        if not self.binary or Path(self.binary) != own:
            return False
        key = platform_key()
        if not key:
            return False
        ver, _ = self._pick_bundle(*key)
        have = self.bundle_version()
        if have is not None and _version_key(ver) <= _version_key(have):
            return False
        self.log.info("tor", f"A newer Tor is out ({have or 'unknown'} -> {ver}). Installing it and restarting Tor on it.")
        with self._lock:
            self._upgrading = True
        try:
            self._install()
            self.binary = find_tor_binary()
            self.restart()
            return True
        except Exception as exc:
            self.log.warn("tor", f"Could not update Tor: {exc}")
            return False
        finally:
            self._upgrading = False

    def _install(self) -> None:
        key = platform_key()
        if not key:
            raise RuntimeError(f"No official Tor bundle for {sys.platform}/{platform.machine()}. "
                               "Install Tor with your package manager instead.")
        osn, arch = key
        self.install_progress = 0.02
        self.log.info("tor", f"Looking up latest Tor Expert Bundle for {osn}-{arch}…")
        ver, fname = self._pick_bundle(osn, arch)
        sums_raw = _http_get(f"{DIST_BASE}{ver}/sha256sums-signed-build.txt")
        self._verify_sums_signature(sums_raw, _http_get(f"{DIST_BASE}{ver}/sha256sums-signed-build.txt.asc"))
        sums = sums_raw.decode()
        want = next((ln.split()[0] for ln in sums.splitlines() if ln.strip().endswith(fname)), None)
        if not want:
            raise RuntimeError(f"No published checksum for {fname}; refusing to install")
        self.log.info("tor", f"Downloading {fname} (Tor Browser release {ver})…")
        dest = tor_dir() / fname
        h = hashlib.sha256()
        req = urllib.request.Request(f"{DIST_BASE}{ver}/{fname}", headers={"User-Agent": "legalPrivacy-installer"})
        with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as out:   # nosec
            total = int(r.headers.get("Content-Length") or 0)
            got = 0
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                out.write(chunk)
                h.update(chunk)
                got += len(chunk)
                if total:
                    self.install_progress = 0.05 + 0.85 * got / total
        if h.hexdigest() != want:
            dest.unlink(missing_ok=True)
            raise RuntimeError("Checksum mismatch — download discarded (expected "
                               f"{want[:12]}…, got {h.hexdigest()[:12]}…)")
        self.log.info("tor", "Checksum verified against dist.torproject.org sums file. Extracting…")
        target = tor_dir() / "bundle"
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True)
        _safe_extract(dest, target)
        dest.unlink(missing_ok=True)
        binp = target / "tor" / _EXE
        if not _IS_WIN:
            for p in (target / "tor").rglob("*"):
                if p.is_file() and (p.name in ("tor", "lyrebird", "conjure-client", "snowflake-client")):
                    p.chmod(0o755)
        self.install_progress = 1.0
        if not binp.exists():
            raise RuntimeError("Bundle extracted but tor binary not found")
        (tor_dir() / "bundle" / "VERSION").write_text(ver)
        self.log.info("tor", f"Tor {ver} installed to {target}")


def _safe_extract(archive: Path, target: Path) -> None:
    root = target.resolve()
    with tarfile.open(archive, "r:*") as tf:
        for m in tf.getmembers():
            dest = (target / m.name).resolve()
            if root not in dest.parents and dest != root:
                raise RuntimeError(f"unsafe path in archive: {m.name}")
            if not (m.isreg() or m.isdir()):
                continue                       # no links, devices or pipes: the bundle needs none of them
            if hasattr(tarfile, "data_filter"):       # strips owner/setuid bits (Python 3.12+, and recent 3.10/3.11)
                tf.extract(m, target, filter="data")
            else:
                tf.extract(m, target)


MOAT = "https://bridges.torproject.org/moat/circumvention/settings"


MOAT_DEFAULTS = "https://bridges.torproject.org/moat/circumvention/defaults"
MOAT_TRANSPORTS = ["obfs4", "snowflake", "webtunnel", "meek"]


def _moat(url: str, body: dict, opener=None) -> dict:
    import json as _json
    req = urllib.request.Request(url, data=_json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/vnd.api+json", "User-Agent": "legalPrivacy-bridges"})
    with (opener or urllib.request.urlopen)(req, timeout=30) as r:          # nosec - fixed https host
        return _json.loads(r.read().decode())


def _sets(data: dict) -> list[dict]:
    out = []
    for s in data.get("settings") or []:
        b = s.get("bridges") or {}
        if b.get("bridge_strings"):
            out.append({"type": b.get("type", "?"), "lines": list(b["bridge_strings"])})
    return out


def fetch_bridges_for_country(country: str = "", opener=None) -> dict:
    """Ask the Tor Project's bridge service (the one Tor Browser's Connection Assist uses) which bridges work in a country
    ('' = it detects the country from this connection). Returns {"country": "us", "source": "country" | "defaults",
    "sets": [{"type": "obfs4", "lines": [...]}]}. Where the service sees no censorship (for example the US) it suggests
    nothing for the country; the service's general default bridges are used then, as Tor Browser does."""
    body = {"transports": MOAT_TRANSPORTS}
    if country:
        body["country"] = country.lower()[:2]
    data = _moat(MOAT, body, opener)
    if data.get("errors"):
        e = data["errors"][0]
        raise RuntimeError(f"bridges.torproject.org: {e.get('detail') or e.get('code') or 'error'}")
    cc = str(data.get("country") or country or "").lower()
    sets = _sets(data)
    if sets:
        return {"country": cc, "source": "country", "sets": sets}
    return {"country": cc, "source": "defaults", "sets": _sets(_moat(MOAT_DEFAULTS, {"transports": MOAT_TRANSPORTS}, opener))}
