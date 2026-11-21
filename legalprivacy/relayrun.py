"""Runs the optional Tor relay as its OWN Tor process.

It is separate from the client Tor that the noise uses: its own data directory under app_dir()/relay/,
its own ports (an ORPort only: no SOCKS, no control port), its own log. It starts with the app by default, in practice mode only, and it
only ever runs a non-exit relay (middle or bridge): the torrc comes from relay.generate_torrc, which pins
the exit policy to reject-all.
"""
from __future__ import annotations

import atexit
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import weakref
from collections import deque
from pathlib import Path
from typing import Any, Callable

from .events import EventLog
from .paths import relay_dir, write_private
from .relay import RelaySpec, generate_torrc
from .tormanager import _IS_WIN, find_tor_binary

TAIL_LINES = 200
BOOTSTRAP_RE = re.compile(r"Bootstrapped (\d+)%")
FINGERPRINT_RE = re.compile(r"identity key fingerprint is '([A-Za-z0-9]{1,19}) ([0-9A-F]{40})'")


def monthly_estimate(megabytes_per_second: float) -> dict:
    """The most a bandwidth cap lets through, per month, in each direction (a relay rarely fills it)."""
    gb = megabytes_per_second * 86400 * 30 / 1000
    return {"max_gb_per_direction": round(gb, 1), "max_gb_total": round(gb * 2, 1)}


def _port_free(host: str, port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


class RelayManager:
    """start / stop / status for one relay process. Thread-safe; start() returns quickly."""

    def __init__(self, log: EventLog, find_binary: Callable[[], str | None] = find_tor_binary):
        self.log = log
        self._find_binary = find_binary
        self.state = "stopped"              # stopped | starting | running | error
        self.error: str | None = None
        self.spec: RelaySpec | None = None
        self.torrc: str = ""
        self.pid: int | None = None
        self.started_at: float | None = None
        self.bootstrap_pct = 0
        self.reachable: bool | None = None  # None = not known yet (never for practice mode)
        self.fingerprint: str | None = None
        self.tail: deque[str] = deque(maxlen=TAIL_LINES)
        self._proc: subprocess.Popen | None = None
        self._lock = threading.RLock()
        self._stopping = False
        self._registered = False

    # ── paths ───────────────────────────────────────────────────────────────
    @staticmethod
    def data_dir() -> Path:
        d = relay_dir() / "data"
        d.mkdir(parents=True, exist_ok=True)
        try:
            d.chmod(0o700)
        except OSError:
            pass
        return d

    # ── lifecycle ───────────────────────────────────────────────────────────
    @property
    def running(self) -> bool:
        return self.state in ("starting", "running")

    def start(self, spec: RelaySpec) -> None:
        """Validate, write the torrc and launch. Raises RelayConfigError for a bad setting and RuntimeError
        for anything else the user can act on (no Tor installed, port in use)."""
        torrc_dir_preview = str(relay_dir() / "data")
        generate_torrc(spec, data_dir=torrc_dir_preview)          # validates before anything is touched
        with self._lock:
            if self.running:
                raise RuntimeError("The relay is already running. Stop it first to change its settings.")
            binary = self._find_binary()
            if not binary:
                raise RuntimeError("Tor is not installed yet. Start Tor once from the Tor tab (it installs the "
                                   "official bundle), then come back.")
            host = "127.0.0.1" if spec.practice else "0.0.0.0"
            if not _port_free(host, spec.or_port):
                raise RuntimeError(f"Port {spec.or_port} is already in use on this computer. Pick another one.")
            data = self.data_dir()
            self.torrc = generate_torrc(spec, data_dir=str(data))
            torrc_path = relay_dir() / "torrc"
            write_private(torrc_path, self.torrc)
            env = os.environ.copy()
            libdir = str(Path(binary).parent)
            env["LD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
            env["DYLD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("DYLD_LIBRARY_PATH", "")
            self.spec, self.error, self.pid = spec, None, None
            self.bootstrap_pct, self.reachable, self.fingerprint = 0, None, None
            self.tail.clear()
            self._stopping = False
            try:
                proc = subprocess.Popen(
                    [binary, "-f", str(torrc_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace", bufsize=1, env=env,
                    creationflags=0x08000000 if _IS_WIN else 0)
            except OSError as exc:
                self.state, self.error = "error", f"Could not start Tor: {exc.strerror or exc}"
                self.log.error("relay", self.error)
                raise RuntimeError(self.error) from None
            self._proc, self.pid, self.started_at, self.state = proc, proc.pid, time.time(), "starting"
            if not self._registered:
                ref = weakref.ref(self)
                atexit.register(lambda: (lambda m: m and m.stop())(ref()))      # never outlive the app
                self._registered = True
        self.log.info("relay", f"Starting a {spec.mode} relay ({'practice mode, not published' if spec.practice else 'public'}).")
        threading.Thread(target=self._pump, args=(proc,), daemon=True, name="relay-log").start()

    def stop(self) -> None:
        with self._lock:
            proc = self._proc
            self._stopping = True
        if proc and proc.poll() is None:
            self.log.info("relay", "Stopping the relay…")
            try:
                proc.terminate()
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    pass
            except OSError:
                pass
            self.log.info("relay", "Relay stopped.")
        with self._lock:
            if proc is self._proc:
                self._proc, self.pid = None, None
                self.state, self.error = "stopped", None
                self.bootstrap_pct, self.reachable = 0, None

    def wipe_data(self) -> bool:
        """Delete the relay's keys and data. Refuses (returns False) while the relay is running."""
        with self._lock:
            if self._proc is not None and self._proc.poll() is None:
                return False
        shutil.rmtree(relay_dir(), ignore_errors=True)
        self.fingerprint = None
        return True

    # ── reading the process output ──────────────────────────────────────────
    def _pump(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:                      # type: ignore[union-attr]
            line = line.rstrip()
            if line:
                self._line(proc, line)
        code = proc.wait()
        with self._lock:
            if proc is not self._proc or self._stopping:
                return
            self.state, self.pid = "error", None
            self.error = (f"The relay stopped on its own (exit code {code}). Read the log below; common causes "
                          "are a port that is already in use or a folder the app can't write to.")
        self.log.error("relay", self.error)

    def _line(self, proc: subprocess.Popen, line: str) -> None:
        with self._lock:
            if proc is not self._proc:
                return
            self.tail.append(line)
            m = BOOTSTRAP_RE.search(line)
            if m:
                self.bootstrap_pct = int(m.group(1))
            f = FINGERPRINT_RE.search(line)
            if f:
                self.fingerprint = f.group(2)
            if self.state == "starting" and (f or "You are running a new relay" in line or self.bootstrap_pct >= 100):
                self.state = "running"
                self.log.info("relay", "The relay is running.")
            if "Self-testing indicates your ORPort is reachable" in line:
                self.reachable = True
            elif "not managed to confirm reachability" in line or "ORPort is not reachable" in line:
                self.reachable = False
            if "[err]" in line and self.state != "error":
                self.error = line.split("] ", 1)[-1][:300]

    # ── status ──────────────────────────────────────────────────────────────
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            sp = self.spec
            practice = bool(sp and sp.practice)
            uptime = int(time.time() - self.started_at) if self.started_at and self.running else 0
            return {
                "state": self.state, "error": self.error, "pid": self.pid, "uptime": uptime,
                "mode": sp.mode if sp else None, "practice": practice if sp else None,
                "or_port": sp.or_port if sp else None, "bootstrap_pct": self.bootstrap_pct,
                "reachable": self.reachable, "fingerprint": self.fingerprint,
                "hint": self._hint(practice, uptime),
                "log": list(self.tail)[-80:],
            }

    def _hint(self, practice: bool, uptime: int) -> str | None:
        if self.state != "running" or practice:
            return None
        if self.reachable is False:
            return ("Tor could not connect to your relay from the outside. Check that the router forwards the "
                    "ORPort to this computer and that the firewall allows it.")
        if self.reachable is None and uptime > 600:
            return "Still waiting for Tor's reachability check. A new relay can take a while; keep the log open."
        return None
