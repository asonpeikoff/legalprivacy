"""Remote machines: run the noise on other computers you own, over SSH.

How it works (one machine):
  1. connect over SSH (host key checked first, see sshconn.py) and look at the machine: system, Python, browsers;
  2. copy ONE small file (the stdlib-only runner, remoteagent.py) and a settings file into a private folder in your
     account on that machine (`~/.cache/legalprivacy`; `%LOCALAPPDATA%\\legalprivacy` on Windows). No root, no service;
  3. start it over SSH and stream its log back here. It stops when this connection ends, when you press Stop, or
     when you remove the machine; Remove also deletes the folder.

Every machine gets its OWN random settings every time it starts (its own rhythm, daily peak, budgets, lane mix, browser
identities, and a different slice of sites and searches), so no two machines ever follow the same schedule.

Only for machines you own or are authorised to use. Passwords are never saved: they stay in memory while the app runs
(a private-key path is saved, the key itself never is). Windows (OpenSSH, PowerShell) is built for but Linux is the
tested path; see docs in the README.
"""
from __future__ import annotations

import atexit
import json
import os
import posixpath
import random
import re
import shlex
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import remoteagent
from .config import ConfigError
from .events import EventLog
from .paths import app_dir, write_private
from .sshconn import (
    Credentials,
    HostKeyChanged,
    HostKeyStore,
    HostKeyUnknown,
    SSHError,
    Transport,
    _scrub,
    make_transport,
    paramiko_available,
)
from .sshtarget import Target, TargetError, parse_target

LOG_LINES = 300
SNAPSHOT_LOG = 80
INTENSITY = {"light": 10, "normal": 30, "busy": 80}          # actions per hour, before each machine's own jitter
AUTHORISED_NOTE = ("Only add computers you own or are explicitly authorised to use. This app logs in to them and "
                   "makes web, search, DNS and download traffic from them.")
SECRET_NOTE = ("Passwords are kept in memory only, for as long as this app runs, and are never saved or logged. "
               "A private-key path is saved (never the key). Prefer a key.")
# How both front ends (the web dashboard and the native app) word a machine's state: (label, tone)
STATE_LABELS = {"idle": ("Stopped", "off"), "testing": ("Testing…", "warn"), "needs_trust": ("Confirm fingerprint", "warn"),
                "starting": ("Starting…", "warn"), "running": ("Running", "ok"), "stopping": ("Stopping…", "warn"),
                "error": ("Error", "bad")}
AGENT_FILE = "agent.py"
SETTINGS_FILE = "settings.json"


class RemoteConfigError(SSHError, ConfigError):
    """A bad setting for a remote machine (the text is safe to show)."""


# ── settings of one machine ─────────────────────────────────────────────────
@dataclass
class RemoteSettings:
    intensity: str = "normal"                     # light | normal | busy
    visits: bool = True
    searches: bool = True
    dns: bool = True
    downloads: bool = True
    browser: str = "auto"                         # auto (a headless browser if one is installed) | off
    max_mb_per_day: int = 200
    max_download_mb: float = 5.0
    download_urls: list[str] = field(default_factory=list)
    dry_run: bool = False                         # makes no network traffic at all: for checking a machine

    @classmethod
    def from_dict(cls, d: dict | None) -> RemoteSettings:
        d = d or {}
        s = cls()
        if "intensity" in d:
            if d["intensity"] not in INTENSITY:
                raise RemoteConfigError("Intensity must be light, normal or busy.")
            s.intensity = d["intensity"]
        for k in ("visits", "searches", "dns", "downloads", "dry_run"):
            if k in d:
                setattr(s, k, bool(d[k]))
        if "browser" in d:
            if d["browser"] not in ("auto", "off"):
                raise RemoteConfigError("Browser must be auto or off.")
            s.browser = d["browser"]
        try:
            if "max_mb_per_day" in d:
                s.max_mb_per_day = int(max(1, min(remoteagent.MAX_MB_PER_DAY, float(d["max_mb_per_day"]))))
            if "max_download_mb" in d:
                s.max_download_mb = float(max(0.1, min(remoteagent.MAX_DOWNLOAD_MB, float(d["max_download_mb"]))))
        except (TypeError, ValueError):
            raise RemoteConfigError("The data limits must be numbers.") from None
        urls = d.get("download_urls") or []
        if isinstance(urls, str):
            urls = [u.strip() for u in urls.splitlines()]
        clean = [u for u in urls if isinstance(u, str) and u]
        if any(not re.match(r"^https://[^\s]+$", u) for u in clean):
            raise RemoteConfigError("Download addresses must start with https://")
        s.download_urls = clean[:50]
        if not (s.visits or s.searches or s.dns or s.downloads):
            raise RemoteConfigError("Turn on at least one kind of noise.")
        return s


# ── the operating system of the remote machine ──────────────────────────────
class Platform:
    """Commands for one kind of remote system. Linux (and macOS) is tested; Windows is built from the documented
    behaviour of Windows OpenSSH and cmd.exe and has only been exercised with a fake machine."""
    name = "posix"

    def __init__(self, home: str, python: str):
        self.home, self.python = home, python

    @property
    def folder(self) -> str:
        return posixpath.join(self.home, ".cache", "legalprivacy")

    def sftp(self, path: str) -> str:
        return path

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def make_folder(self) -> str:
        d = shlex.quote(self.folder)
        return f"umask 077 && mkdir -p {d} && chmod 700 {d}"

    def start(self) -> str:
        d = shlex.quote(self.folder)
        return (f"cd {d} && exec {shlex.quote(self.python)} {AGENT_FILE} run {SETTINGS_FILE}")

    def stop(self) -> str:
        d = shlex.quote(self.folder)
        return f"cd {d} && {shlex.quote(self.python)} {AGENT_FILE} stop {d}"

    def wipe(self) -> str:
        d = shlex.quote(self.folder)
        return f"case {d} in */.cache/legalprivacy) rm -rf -- {d} && echo removed;; *) echo refused;; esac"


class WindowsPlatform(Platform):
    name = "windows"

    @property
    def folder(self) -> str:
        return self.home.rstrip("\\") + "\\legalprivacy"

    def sftp(self, path: str) -> str:
        p = path.replace("\\", "/")
        return "/" + p if re.match(r"^[A-Za-z]:", p) else p

    def join(self, *parts: str) -> str:
        return "\\".join(p.rstrip("\\") for p in parts)

    def make_folder(self) -> str:
        return f'if not exist "{self.folder}" mkdir "{self.folder}"'

    def start(self) -> str:
        return f'cd /d "{self.folder}" && {self.python} {AGENT_FILE} run {SETTINGS_FILE}'

    def stop(self) -> str:
        return f'cd /d "{self.folder}" && {self.python} {AGENT_FILE} stop "{self.folder}"'

    def wipe(self) -> str:
        f = self.folder
        return f'if /i "{f[-14:]}"=="\\legalprivacy" (rmdir /s /q "{f}" && echo removed) else (echo refused)'


_PROBE_POSIX = ('uname -s; printf "%s\\n" "$HOME"; '
                '(command -v python3 || command -v python || echo NOPYTHON) 2>/dev/null; '
                'echo ---; for b in chromium chromium-browser google-chrome google-chrome-stable firefox; '
                'do command -v "$b" 2>/dev/null; done; true')


def detect(t: Transport) -> tuple[Platform, dict]:
    """Look at the machine. Returns the platform helper and what was found. Raises SSHError with advice."""
    code, out, _err = t.run(_PROBE_POSIX, timeout=20)
    lines = [ln.strip() for ln in out.splitlines()]
    if code == 0 and lines and lines[0] in ("Linux", "Darwin", "FreeBSD", "OpenBSD", "NetBSD"):
        home = lines[1] if len(lines) > 1 else ""
        py = lines[2] if len(lines) > 2 else "NOPYTHON"
        found = [x for x in lines[lines.index("---") + 1:] if x] if "---" in lines else []
        if not home.startswith("/"):
            raise SSHError("Could not find the home folder on that machine.")
        info = {"os": lines[0], "home": home, "python_path": None if py == "NOPYTHON" else py,
                "browser": os.path.basename(found[0]) if found else None}
        if info["python_path"] is None:
            raise SSHError("Python 3 is not installed on that machine (the runner needs `python3`). "
                           "Install it with the machine's package manager, then test again.")
        return Platform(home, py), info
    # not a POSIX shell: try Windows OpenSSH (default shell cmd.exe)
    code, out, _err = t.run('cmd /c "echo %LOCALAPPDATA%& where python & where py & where chrome & where msedge '
                            '& where firefox"', timeout=25)
    parts = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if parts and re.match(r"^[A-Za-z]:\\", parts[0]):
        home = parts[0]
        exe = [p for p in parts[1:] if p.lower().endswith(".exe")]
        py = next((p for p in exe if p.lower().endswith("python.exe") and "WindowsApps" not in p), None)
        launcher = next((p for p in exe if p.lower().endswith("py.exe")), None)
        python = f'"{py}"' if py else (f'"{launcher}" -3' if launcher else None)
        if not python:
            raise SSHError("Python 3 was not found on that Windows machine (install it from python.org, "
                           "or `winget install Python.Python.3.12`, then test again).")
        browser = next((re.split(r"[\\/]", p)[-1] for p in exe if p.lower().endswith(("chrome.exe", "msedge.exe", "firefox.exe"))),
                       None)
        return WindowsPlatform(home, python), {"os": "Windows", "home": home, "python_path": python, "browser": browser}
    raise SSHError("That machine answered, but it is not a system this app knows how to run on (Linux, macOS and "
                   "Windows OpenSSH are supported).")


# ── one machine ─────────────────────────────────────────────────────────────
class RemoteMachine:
    def __init__(self, mid: str, target: Target, auth: str, key_path: str | None, label: str,
                 settings: RemoteSettings):
        self.id, self.target, self.auth, self.key_path = mid, target, auth, key_path
        self.label = label or str(target)
        self.settings = settings
        self.state = "idle"             # idle | testing | needs_trust | starting | running | stopping | error
        self.error: str | None = None
        self.info: dict = {}
        self.pending: tuple[str, str] | None = None        # (key type, fingerprint) waiting for the user
        self.started_at: float | None = None
        self.counts: dict = {}
        self.mb = 0.0
        self.log: deque[str] = deque(maxlen=LOG_LINES)
        self.creds = Credentials(key_path=key_path)
        self.thread: threading.Thread | None = None
        self.stream = None
        self.transport: Transport | None = None
        self.platform: Platform | None = None
        self.lock = threading.RLock()
        self.stopping = False

    @property
    def running(self) -> bool:
        return self.state in ("starting", "running", "stopping")

    def add_log(self, line: str) -> None:
        self.log.append(_scrub(line, self.creds.secrets()))


# ── all machines ────────────────────────────────────────────────────────────
class RemoteManager:
    def __init__(self, log: EventLog, pools: Callable[[random.Random, str], dict] | None = None,
                 transport_factory: Callable[..., Transport] | None = None, path: Path | None = None,
                 store: HostKeyStore | None = None, agent_source: Callable[[], bytes] | None = None):
        self.log = log
        self._pools = pools or (lambda rng, os_name: {})
        self._factory = transport_factory or make_transport
        self.path = Path(path) if path else app_dir() / "remote_machines.json"
        self.store = store or HostKeyStore()
        self._agent_source = agent_source or (lambda: Path(remoteagent.__file__).read_bytes())
        self.machines: dict[str, RemoteMachine] = {}
        self._lock = threading.RLock()
        self._registered = False
        self._load()

    # -- persistence (no secrets, ever)
    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for d in raw if isinstance(raw, list) else []:
            try:
                tg = parse_target(d["target"])
                m = RemoteMachine(str(d["id"])[:16], tg, "key" if d.get("auth") == "key" else "password",
                                  d.get("key_path") or None, str(d.get("label") or "")[:60],
                                  RemoteSettings.from_dict(d.get("settings")))
                self.machines[m.id] = m
            except (KeyError, TypeError, TargetError, SSHError):
                continue

    def _save(self) -> None:
        rows = [{"id": m.id, "target": str(m.target), "auth": m.auth, "key_path": m.key_path, "label": m.label,
                 "settings": asdict(m.settings)} for m in self.machines.values()]
        try:
            write_private(self.path, json.dumps(rows, indent=1))
        except OSError:
            self.log.warn("remote", "Could not save the list of remote machines.")

    # -- lookups
    def get(self, mid: str) -> RemoteMachine:
        m = self.machines.get(str(mid))
        if m is None:
            raise RemoteConfigError("That remote machine is not in the list (it may have been removed).")
        return m

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"available": paramiko_available(), "authorised_note": AUTHORISED_NOTE, "secret_note": SECRET_NOTE,
                    "machines": [self._snap(m) for m in self.machines.values()]}

    def _snap(self, m: RemoteMachine) -> dict:
        with m.lock:
            stored = self.store.get(m.target)
            up = int(time.time() - m.started_at) if m.started_at and m.state == "running" else 0
            return {
                "id": m.id, "label": m.label, "target": str(m.target), "user": m.target.user, "host": m.target.host,
                "port": m.target.port, "auth": m.auth, "key_path": m.key_path, "has_secret": m.creds.usable(),
                "state": m.state, "error": m.error, "uptime": up, "counts": dict(m.counts), "mb": m.mb,
                "os": m.info.get("os"), "python": m.info.get("python_path"), "browser": m.info.get("browser"),
                "host_key": stored.get("fingerprint") if stored else None,
                "pending_key": ({"type": m.pending[0], "fingerprint": m.pending[1],
                                 "check": host_key_check_command(m.pending[0])} if m.pending else None),
                "settings": asdict(m.settings), "log": list(m.log)[-SNAPSHOT_LOG:],
            }

    # -- add / remove
    def add(self, target: str, auth: str = "password", password: str | None = None, key_path: str | None = None,
            passphrase: str | None = None, label: str = "", authorised: bool = False,
            settings: dict | None = None) -> dict:
        if not authorised:
            raise RemoteConfigError("Tick the box to confirm this machine is yours or that you are authorised to use it.")
        try:
            tg = parse_target(target)
        except TargetError as exc:
            raise RemoteConfigError(str(exc)) from None
        if auth not in ("password", "key"):
            raise RemoteConfigError("Choose password or private key.")
        key_path = (key_path or "").strip() or None
        if auth == "key" and not key_path:
            raise RemoteConfigError("Enter the path to your private key file.")
        if auth == "password" and not password:
            raise RemoteConfigError("Enter the password (it is kept in memory only, never saved).")
        with self._lock:
            if any(m.target == tg for m in self.machines.values()):
                raise RemoteConfigError(f"{tg} is already in the list.")
            m = RemoteMachine(uuid.uuid4().hex[:8], tg, auth, key_path if auth == "key" else None, label.strip()[:60],
                              RemoteSettings.from_dict(settings))
            m.creds = Credentials(password=password if auth == "password" else None,
                                  key_path=m.key_path, passphrase=passphrase or None)
            self.machines[m.id] = m
            self._save()
        self.log.info("remote", f"Added {m.label} ({tg}).")
        return self._snap(m)

    def set_secret(self, m: RemoteMachine, password: str | None = None, passphrase: str | None = None) -> None:
        with m.lock:
            if password:
                m.creds.password = password
            if passphrase:
                m.creds.passphrase = passphrase

    def configure(self, mid: str, settings: dict) -> dict:
        m = self.get(mid)
        with m.lock:
            if m.running:
                raise RemoteConfigError("Stop the machine first to change its settings.")
            m.settings = RemoteSettings.from_dict({**asdict(m.settings), **(settings or {})})
        with self._lock:
            self._save()
        return self._snap(m)

    def remove(self, mid: str, wipe: bool = True, password: str | None = None, passphrase: str | None = None) -> dict:
        m = self.get(mid)
        self.set_secret(m, password, passphrase)
        self.stop(mid)
        wiped: bool | None = None
        note = ""
        if wipe:
            wiped, note = self._wipe(m)
        with self._lock:
            self.machines.pop(m.id, None)
            self._save()
            if not any(o.target.key == m.target.key for o in self.machines.values()):
                self.store.forget(m.target)
        self.log.info("remote", f"Removed {m.label}. {note}".strip())
        return {"removed": True, "wiped": wiped, "note": note}

    def _wipe(self, m: RemoteMachine) -> tuple[bool, str]:
        if not m.creds.usable():
            return False, ("The folder on the machine was NOT deleted (no password in memory). Delete "
                           f"{m.platform.folder if m.platform else '~/.cache/legalprivacy'} there yourself.")
        t = None
        try:
            t = self._connect(m)
            plat, _info = detect(t)
            code, out, _e = t.run(plat.wipe(), timeout=30)
            if code == 0 and "removed" in out:
                return True, "Its folder on the machine was deleted."
            return False, f"The folder was not deleted; delete {plat.folder} on the machine yourself."
        except SSHError as exc:
            return False, f"The folder on the machine was NOT deleted ({exc}). Delete ~/.cache/legalprivacy there yourself."
        finally:
            if t is not None:
                t.close()

    # -- connect (every path goes through here so the host key is always checked first)
    def _connect(self, m: RemoteMachine, trusted_fp: str | None = None) -> Transport:
        t = self._factory(m.target, m.creds, self.store, trusted_fp)
        try:
            t.connect()
        except HostKeyUnknown as exc:
            with m.lock:
                m.pending = (exc.key_type, exc.fingerprint)
            raise
        except HostKeyChanged:
            with m.lock:
                m.pending = None
            raise
        with m.lock:
            m.pending = None
        return t

    # -- test
    def test(self, mid: str, password: str | None = None, passphrase: str | None = None) -> dict:
        m = self.get(mid)
        if m.running:
            raise RemoteConfigError("That machine is running. Stop it to test the connection again.")
        self.set_secret(m, password, passphrase)
        with m.lock:
            m.state, m.error = "testing", None
        t = None
        try:
            if not m.creds.usable():
                raise SSHError("Enter the password again; it is only kept in memory while the app runs.")
            t = self._connect(m)
            plat, info = detect(t)
            with m.lock:
                m.info, m.platform, m.state = info, plat, "idle"
            m.add_log(f"Test OK: {info['os']}, python {info['python_path']}, "
                      f"browser {info['browser'] or 'none (plain HTTP lane)'}")
            return {"ok": True, "status": "ok", **info, "message": "Connected, and the machine can run the noise."}
        except HostKeyUnknown as exc:
            with m.lock:
                m.state = "needs_trust"
            return {"ok": False, "status": "untrusted", "fingerprint": exc.fingerprint, "key_type": exc.key_type,
                    "message": str(exc)}
        except HostKeyChanged as exc:
            with m.lock:
                m.state, m.error = "error", str(exc)
            self.log.warn("remote", f"{m.label}: host key changed; nothing was sent.")
            return {"ok": False, "status": "changed", "stored": exc.stored, "fingerprint": exc.offered,
                    "message": str(exc)}
        except SSHError as exc:
            with m.lock:
                m.state, m.error = "error", _scrub(str(exc), m.creds.secrets())
            return {"ok": False, "status": "error", "message": m.error}
        finally:
            if t is not None:
                t.close()

    def trust(self, mid: str, fingerprint: str) -> dict:
        """The user has seen the fingerprint and confirms it. It must be the one the machine just offered."""
        m = self.get(mid)
        with m.lock:
            if not m.pending or m.pending[1] != fingerprint:
                raise RemoteConfigError("That fingerprint is not the one the machine is offering right now. "
                                        "Test the connection again and compare it.")
            ktype, fp = m.pending
            if self.store.get(m.target) is not None:
                raise RemoteConfigError("This machine already has a trusted key. Forget it first if you mean to replace it.")
        self.store.trust(m.target, ktype, fp)
        with m.lock:
            m.pending, m.state = None, "idle"
        self.log.info("remote", f"Trusted the host key of {m.label} ({fp}).")
        return self._snap(m)

    def forget_key(self, mid: str) -> dict:
        m = self.get(mid)
        if m.running:
            raise RemoteConfigError("Stop the machine before forgetting its host key.")
        self.store.forget(m.target)
        with m.lock:
            m.pending, m.error = None, None
            m.state = "idle"
        self.log.info("remote", f"Forgot the host key of {m.label}; it will be asked about again.")
        return self._snap(m)

    # -- settings file for one start: this machine's own random draw
    def build_settings(self, m: RemoteMachine, rng: random.Random | None = None) -> dict:
        rng = rng or random.Random(int.from_bytes(os.urandom(16), "big"))
        s = m.settings
        pools = self._pools(rng, str(m.info.get("os") or "Linux")) or {}
        domains = list(pools.get("domains") or [])
        queries = list(pools.get("queries") or [])
        uas = list(pools.get("user_agents") or [])
        rng.shuffle(domains)
        rng.shuffle(queries)
        take = lambda xs, lo, hi: xs[:rng.randint(lo, hi)]      # noqa: E731  each machine gets its own slice size
        return {
            "version": remoteagent.VERSION, "dry_run": s.dry_run,
            "actions_per_hour": INTENSITY[s.intensity] * rng.uniform(0.7, 1.4),
            "lanes": {"visit": s.visits, "search": s.searches, "dns": s.dns, "download": s.downloads},
            "browser": s.browser, "max_mb_per_day": s.max_mb_per_day, "max_download_mb": s.max_download_mb,
            "download_urls": s.download_urls,
            "domains": take(domains, 120, 260), "queries": take(queries, 60, 140),
            "user_agents": rng.sample(uas, min(len(uas), rng.randint(2, 4))),
        }

    # -- start / stop
    def start(self, mid: str, password: str | None = None, passphrase: str | None = None,
              trusted_fingerprint: str | None = None) -> dict:
        m = self.get(mid)
        self.set_secret(m, password, passphrase)
        with m.lock:
            if m.running:
                raise RemoteConfigError("That machine is already running.")
            if not m.creds.usable():
                raise RemoteConfigError("Enter the password again; it is only kept in memory while the app runs.")
            if not paramiko_available() and self._factory is make_transport:
                raise SSHError("Remote machines need the 'paramiko' package. Install it with: pip install \"paramiko>=3.4\"")
            m.state, m.error, m.stopping = "starting", None, False
            m.counts, m.mb = {}, 0.0
            m.log.clear()
            m.thread = threading.Thread(target=self._run, args=(m, trusted_fingerprint), daemon=True,
                                        name=f"remote-{m.id}")
            m.thread.start()
        if not self._registered:
            self._registered = True
            atexit.register(self.stop_all)
        return self._snap(m)

    def _run(self, m: RemoteMachine, trusted_fp: str | None) -> None:
        t = None
        try:
            t = self._connect(m, trusted_fp)
            plat, info = detect(t)
            with m.lock:
                m.transport, m.platform, m.info = t, plat, info
            settings = self.build_settings(m)
            t.run(plat.make_folder(), timeout=20)
            t.put(self._agent_source(), plat.sftp(plat.join(plat.folder, AGENT_FILE)), 0o600)
            t.put(json.dumps(settings).encode("utf-8"), plat.sftp(plat.join(plat.folder, SETTINGS_FILE)), 0o600)
            m.add_log(f"Copied the runner to {plat.folder} on the machine.")
            stream = t.open_stream(plat.start())
            with m.lock:
                m.stream, m.state, m.started_at = stream, "running", time.time()
            self.log.info("remote", f"{m.label}: noise started ({m.settings.intensity}"
                                    f"{', dry run' if m.settings.dry_run else ''}).")
            for line in stream.lines():
                self._line(m, line)
            code = stream.exit_status
            with m.lock:
                if not m.stopping:
                    m.state = "error"
                    m.error = (f"The runner on the machine stopped on its own (exit code {code}). "
                               "Read the log below.")
                    self.log.warn("remote", f"{m.label}: {m.error}")
        except HostKeyUnknown as exc:
            with m.lock:
                m.state = "needs_trust"
                m.error = "Confirm this machine's fingerprint first: " + exc.fingerprint
        except SSHError as exc:
            with m.lock:
                m.state, m.error = "error", _scrub(str(exc), m.creds.secrets())
            self.log.warn("remote", f"{m.label}: {m.error}")
        except Exception as exc:                       # never lose a worker silently
            with m.lock:
                m.state, m.error = "error", f"Unexpected {type(exc).__name__}; see the App log."
            self.log.error("remote", f"{m.label}: unexpected {type(exc).__name__}")
        finally:
            with m.lock:
                m.stream, m.started_at = None, None
                if m.stopping and m.state != "error":
                    m.state = "idle"
                m.transport = None
            if t is not None:
                t.close()

    def _line(self, m: RemoteMachine, line: str) -> None:
        line = _scrub(line.rstrip(), m.creds.secrets())
        if not line:
            return
        try:
            rec = json.loads(line)
            if not isinstance(rec, dict) or "kind" not in rec:
                raise ValueError
        except ValueError:
            m.add_log(f"! {line[:300]}")                 # a shell message, e.g. python not found
            return
        stamp = time.strftime("%H:%M:%S", time.localtime(float(rec.get("t") or time.time())))
        kind = rec["kind"]
        if kind == "stats":
            with m.lock:
                m.counts = rec.get("counts") or m.counts
                m.mb = rec.get("mb", m.mb)
            if rec.get("msg") == "final":
                m.add_log(f"{stamp} totals: {m.counts}")
            return
        mark = {"warn": "! ", "error": "!! "}.get(rec.get("lvl", ""), "")
        m.add_log(f"{stamp} {mark}{kind}: {rec.get('msg', '')}")

    def stop(self, mid: str) -> dict:
        m = self.get(mid)
        with m.lock:
            if not m.running:
                return self._snap(m)
            m.stopping, m.state = True, "stopping"
            stream, t, plat, th = m.stream, m.transport, m.platform, m.thread
        if stream is not None:
            stream.write("stop\n")
        if th is not None and th is not threading.current_thread():
            th.join(timeout=8)
            if th.is_alive():                           # it did not hear us: ask the machine to stop it
                try:
                    if t is not None and plat is not None:
                        t.run(plat.stop(), timeout=15)
                except SSHError:
                    pass
                if stream is not None:
                    stream.close()
                th.join(timeout=5)
        with m.lock:
            if m.state != "error":
                m.state = "idle"
        self.log.info("remote", f"{m.label}: noise stopped.")
        return self._snap(m)

    def stop_all(self) -> None:
        for mid in list(self.machines):
            try:
                self.stop(mid)
            except Exception:
                pass


def host_key_check_command(key_type: str) -> str:
    """The command that prints a machine's own host key fingerprint, so you can compare it with the one offered."""
    kind = "ed25519" if "ed25519" in key_type else "ecdsa" if "ecdsa" in key_type else "rsa" if "rsa" in key_type else "ed25519"
    return f"ssh-keygen -lf /etc/ssh/ssh_host_{kind}_key.pub"


def facts_text(m: dict) -> str:
    """One line about a machine (from RemoteManager.snapshot()['machines'][i])."""
    bits = []
    if m.get("os"):
        bits.append(str(m["os"]))
    if m.get("python"):
        bits.append("python: " + str(m["python"]))
    if m.get("os"):
        bits.append("browser: " + (m.get("browser") or "none (plain HTTP)"))
    bits.append("host key: " + (m["host_key"] if m.get("host_key") else "not trusted yet"))
    bits.append(("key: " + (m.get("key_path") or "")) if m.get("auth") == "key" else "password login")
    if m.get("uptime"):
        bits.append(f"up {m['uptime'] // 60} min")
    return " · ".join(bits)


def counts_text(m: dict) -> str:
    c = m.get("counts") or {}
    if not c:
        return ""
    return (f"visits {c.get('visit', 0)} · searches {c.get('search', 0)} · DNS {c.get('dns', 0)} · "
            f"downloads {c.get('download', 0)} · errors {c.get('error', 0)} · {m.get('mb', 0)} MB")
