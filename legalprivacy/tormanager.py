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

import hashlib
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

from .config import valid_bridge_line
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


# ── manager ─────────────────────────────────────────────────────────────────
class TorManager:
    """Owns the lifecycle of the Tor the app uses. Thread-safe, non-blocking API."""

    def __init__(self, log: EventLog, mode: str = "managed",
                 socks: str = "127.0.0.1:9050", control: str | None = "127.0.0.1:9051",
                 control_password: str | None = None, bridges: list[str] | None = None,
                 bridge_mode: str = "off", bridge_auto: bool = True,
                 auto_install: bool = True, dns_port: int = 0, dns_lan: bool = False,
                 dns_lan_addr: str = ""):
        self.log = log
        self.mode = mode                      # managed | external
        self.ext_socks, self.ext_control = socks, control
        self.control_password = control_password
        self.bridges = [b.strip() for b in (bridges or []) if b.strip()]
        self.bridge_mode = bridge_mode          # off | obfs4 | snowflake | meek | custom (may change by itself)
        self.configured_bridge_mode = bridge_mode   # what the user chose
        self.bridge_auto = bridge_auto          # try built-in bridges if a direct connection gets stuck
        self._auto_tried: list[str] = []
        self.auto_install = auto_install
        self.dns_port_cfg, self.dns_lan, self.dns_lan_addr = dns_port, dns_lan, dns_lan_addr   # Tor DNS (optional)
        self.dns_host = tordns.bind_address(dns_lan, dns_lan_addr)
        self.dns_port = 0                       # the port actually in use (set when Tor is launched)

        self.state = "stopped"   # stopped|installing|starting|bootstrapping|ready|error
        self.error: str | None = None
        self.bootstrap_pct = 0
        self.bootstrap_summary = ""
        self.version: str | None = None
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
            "install_progress": self.install_progress,
            "dns": self.dns_info(),
            "supported_platform": platform_key() is not None,
            "hint": self._hint(uptime),
            **{k: self.stats.get(k) for k in ("read", "written", "circuits_built")},
        }

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
        self.dns_port = (_pick_udp_port(self.dns_host, self.dns_port_cfg or tordns.DEFAULT_PORT)
                         if self.dns_port_cfg else 0)
        self.cookie_path = str(tor_dir() / "control_auth_cookie")
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
        threading.Thread(target=self._pump_output, args=(self._proc,), daemon=True,
                         name="tor-log").start()
        if self.bridge_auto and self.bridge_mode in ("off",) + tuple(self._auto_tried):
            threading.Thread(target=self._auto_bridges_watch, args=(self.started_at,), daemon=True,
                             name="tor-bridge-assist").start()
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
            "SafeSocks 1",
            "Log notice stdout",
        ]
        dns_line = tordns.torrc_line(self.dns_port, self.dns_lan, self.dns_lan_addr) if self.dns_port else None
        if dns_line:        # optional Tor DNS: loopback unless one private LAN address was explicitly chosen
            lines.append(dns_line)
        bundle_data = Path(self.binary).resolve().parent.parent / "data"
        for name, key in (("geoip", "GeoIPFile"), ("geoip6", "GeoIPv6File")):
            if (bundle_data / name).exists():
                lines.append(f"{key} {_torrc_quote(bundle_data / name)}")
        bridges = [b for b in self.effective_bridges() if valid_bridge_line(b)]   # one line each, never a setting
        if len(bridges) != len(self.effective_bridges()):
            self.log.warn("tor", "Ignored bridge line(s) that were not in the usual bridge format.")
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

    def _auto_bridges_watch(self, started: float) -> None:
        """Like Tor Browser's Connection Assist: a direct connection stuck early -> built-in bridges."""
        while not self._stop_evt.is_set() and self.started_at == started:
            time.sleep(5)
            if self.state == "ready" or self.state in ("stopped", "error"):
                return
            if time.time() - started > 75 and self.bootstrap_pct < 30:
                order = [m for m in ("obfs4", "snowflake") if m not in self._auto_tried
                         and self.builtin_bridges().get(m)]
                if not order:
                    self.log.warn("tor", "Tor still can't connect, even with built-in bridges. Get bridges for "
                                         "your country on the Tor tab, or from bridges.torproject.org.")
                    return
                mode = order[0]
                self._auto_tried.append(mode)
                self.log.warn("tor", f"Tor can't seem to connect directly; your network may block it. "
                                     f"Trying the built-in {mode} bridges.")
                self.bridge_mode = mode
                self.restart()
                return

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
            level = "warn" if "[warn]" in line else "error" if "[err]" in line else "info"
            if "[debug]" in line or "[info]" in line:
                level = "debug"
            self.log.add(level, "tor", line)
        code = proc.wait()
        if proc is not self._proc:          # an older Tor that was stopped or replaced: not a failure of the new one
            return
        if not self._stop_evt.is_set() and self.state != "stopped":
            self._fail(f"Tor exited unexpectedly (code {code}). See the log for details.")

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

    def _poll(self, c: TorControl) -> None:
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

    # -- installer ---------------------------------------------------------
    def _install_safe(self) -> None:
        try:
            prev, self.state = self.state, "installing"
            self._install()
            self.state = "stopped" if prev in ("stopped", "error") else prev
        except Exception as exc:
            self._fail(f"Tor install failed: {exc}")

    def _install(self) -> None:
        key = platform_key()
        if not key:
            raise RuntimeError(f"No official Tor bundle for {sys.platform}/{platform.machine()}. "
                               "Install Tor with your package manager instead.")
        osn, arch = key
        self.install_progress = 0.02
        self.log.info("tor", f"Looking up latest Tor Expert Bundle for {osn}-{arch}…")
        index = _http_get(DIST_BASE).decode("utf-8", "ignore")
        versions = sorted({v for v in re.findall(r'href="(\d+(?:\.\d+)+)/"', index)},
                          key=_version_key, reverse=True)
        chosen = None
        for ver in versions[:6]:            # newest stable first; skip dirs without desktop bundle
            fname = f"tor-expert-bundle-{osn}-{arch}-{ver}.tar.gz"
            listing = _http_get(f"{DIST_BASE}{ver}/").decode("utf-8", "ignore")
            if fname in listing:
                chosen = (ver, fname)
                break
        if not chosen:
            raise RuntimeError("Could not find a Tor Expert Bundle for this platform on dist.torproject.org")
        ver, fname = chosen
        sums = _http_get(f"{DIST_BASE}{ver}/sha256sums-signed-build.txt").decode()
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
        self.log.info("tor", f"Tor {ver} installed to {target}")


def _safe_extract(archive: Path, target: Path) -> None:
    root = target.resolve()
    with tarfile.open(archive, "r:gz") as tf:
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


def fetch_bridges_for_country(country: str = "") -> list[dict]:
    """Ask the Tor Project's bridge service which bridges work in a country ('' = detect from this IP).
    Returns [{"type": "obfs4", "lines": [...]}]. Contacts bridges.torproject.org directly."""
    import json as _json
    body = _json.dumps({"country": country.lower()[:2], "transports": ["obfs4", "snowflake", "webtunnel", "meek"]}
                       if country else {"transports": ["obfs4", "snowflake", "webtunnel", "meek"]}).encode()
    req = urllib.request.Request(MOAT, data=body, method="POST",
                                 headers={"Content-Type": "application/vnd.api+json",
                                          "User-Agent": "legalPrivacy-bridges"})
    with urllib.request.urlopen(req, timeout=30) as r:          # nosec - fixed https host
        data = _json.loads(r.read().decode())
    out = []
    for s in data.get("settings") or []:
        b = s.get("bridges") or {}
        if b.get("bridge_strings"):
            out.append({"type": b.get("type", "?"), "lines": list(b["bridge_strings"])})
    return out
