"""Optional, offline-first antivirus manager: runs the user's own ClamAV, and proves it never phones home.

What this module does, and does not do
  * It only EXECUTES binaries the user installed (clamscan, freshclam, sigtool). ClamAV is GPL and is never
    bundled. It makes no network calls of its own.
  * The only ClamAV component documented as contacting the internet is `freshclam`, the signature updater
    (a DNS TXT lookup of current.cvd.clamav.net, then an HTTPS download from database.clamav.net). It is
    run ONLY from `AvManager.update()`, which needs an explicit confirmation. Never on a schedule, never as a
    daemon, never from a scan, a detect, a state call or an import (the tests assert this).
  * Scans always use `clamscan --database=<app folder>/av/db`, so the system's ClamAV configuration and
    signature folder are never read or changed. `clamdscan` is detected but never used (it talks to a daemon
    configured by the system).
  * Offline is enforced and checked, not assumed: on Linux the scanner runs with its network removed
    (`unshare --net`, `unshare -rn`, or `firejail --net=none`, whichever a one-time probe shows really works),
    and on every OS the scanner's process tree is watched (psutil, ~100 ms) for any non-loopback connection or
    DNS helper. Any hit marks the scan NOT OFFLINE and kills the scanner.
  * Nothing is ever deleted, moved or changed automatically. Quarantine is an explicit, reversible action.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from pathlib import Path

try:
    import psutil
except ImportError:            # pragma: no cover - psutil is a declared dependency
    psutil = None

from .paths import app_dir, write_private

TOOLS = ("clamscan", "clamdscan", "freshclam", "sigtool")
DOCS_URL = "https://docs.clamav.net/"
UPDATE_HOSTS = ("current.cvd.clamav.net (DNS TXT lookup)", "database.clamav.net (HTTPS download)")

# Places the installers put the programs when they are not on PATH.
EXTRA_DIRS: list[str] = [
    "/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/usr/local/clamav/bin", "/usr/bin", "/usr/sbin",
    r"C:\Program Files\ClamAV", r"C:\Program Files (x86)\ClamAV", r"C:\ClamAV", r"C:\Program Files\ClamAV-x64",
]
DB_EXTS = (".cvd", ".cld", ".cud", ".hdb", ".hsb", ".mdb", ".msb", ".ndb", ".ldb", ".ftm", ".fp", ".cbc", ".ign2", ".pdb")
IMPORT_NAMES = re.compile(r"^(main|daily|bytecode)\.(cvd|cld)$", re.I)
DNS_HELPERS = frozenset({"dig", "nslookup", "host", "drill", "resolvectl", "systemd-resolve", "getent", "kdig", "unbound-host"})
MAX_PATHS, MAX_INFECTED_KEPT, MAX_ERRORS_KEPT = 50, 20000, 500
POLL_SECONDS = 0.1


class AvError(Exception):
    """A deliberate, plain-language message for the person using the app."""


# ── folders ────────────────────────────────────────────────────────────────
def av_dir() -> Path:
    d = app_dir() / "av"
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def _sub(name: str) -> Path:
    d = av_dir() / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def db_dir() -> Path:
    return _sub("db")


def quarantine_dir() -> Path:
    return _sub("quarantine")


# ── running programs (argument lists only, never a shell) ──────────────────
def _kw() -> dict:
    kw: dict = {"stdin": subprocess.DEVNULL}
    if sys.platform == "win32":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return kw


def run_cmd(cmd: list[str], timeout: float) -> tuple[int, str]:
    """Run a helper with a time limit; (exit code, combined output). -1 means it could not run, -9 timed out."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, **_kw())
    except subprocess.TimeoutExpired:
        return -9, "timed out"
    except OSError as exc:
        return -1, str(exc)
    return p.returncode, p.stdout.decode("utf-8", "replace")


# ── detection ──────────────────────────────────────────────────────────────
def find_tool(name: str) -> str | None:
    hit = shutil.which(name)
    if hit:
        return hit
    exts = ("", ".exe") if sys.platform == "win32" else ("",)
    for d in EXTRA_DIRS:
        for ext in exts:
            cand = os.path.join(d, name + ext)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


def tool_version(path: str) -> str | None:
    rc, out = run_cmd([path, "--version"], 10)
    line = (out.strip().splitlines() or [""])[0].strip()
    return line[:120] if rc == 0 and line else None


_DETECT: dict = {"ts": 0.0, "val": None}


def detect(force: bool = False) -> dict:
    """{'clamscan': {'path', 'version'}, ...}; cached for a minute (a version check starts the program, except
    freshclam, which is never started here)."""
    if not force and _DETECT["val"] is not None and time.time() - _DETECT["ts"] < 60:
        return _DETECT["val"]
    out = {}
    for t in TOOLS:
        p = find_tool(t)
        # freshclam is never started just to ask its version: only the Update button ever runs it
        out[t] = {"path": p, "version": tool_version(p) if p and t != "freshclam" else None}
    _DETECT.update(ts=time.time(), val=out)
    return out


def install_hint(platform: str | None = None) -> dict:
    plat = platform or sys.platform
    if plat.startswith("linux"):
        lines = ["Debian / Ubuntu:  sudo apt install clamav", "Fedora / RHEL:  sudo dnf install clamav clamav-update",
                 "Note: the Debian/Ubuntu package may also set up a background service (clamav-freshclam) that "
                 "updates signatures by itself. legalPrivacy never starts or stops it; if you want a fully offline "
                 "install, that is yours to disable."]
    elif plat == "darwin":
        lines = ["Homebrew:  brew install clamav", "Homebrew installs the programs but no signatures: use Import "
                                                    "(offline) or the Update button here."]
    elif plat == "win32":
        lines = ["Download the Windows installer from docs.clamav.net (Installing, then Windows), run it, and keep "
                 "its folder (for example C:\\Program Files\\ClamAV) or add it to PATH.",
                 "Or: winget / Chocolatey packages exist; check the docs for the current name."]
    else:
        lines = ["See docs.clamav.net for installation steps on this system."]
    return {"lines": lines, "url": DOCS_URL}


# ── the app-owned signature folder ─────────────────────────────────────────
_INFO_CACHE: dict = {}


def _sigtool_info(sigtool: str | None, f: Path) -> dict:
    if not sigtool:
        return {}
    st = f.stat()
    key = (f.name, st.st_size, int(st.st_mtime))
    if key in _INFO_CACHE:
        return _INFO_CACHE[key]
    rc, out = run_cmd([sigtool, f"--info={f}"], 30)
    info = parse_sigtool_info(out) if rc == 0 else {}
    _INFO_CACHE[key] = info
    return info


def parse_sigtool_info(text: str) -> dict:
    info: dict = {"verified": "Verification OK" in text}
    for line in text.splitlines():
        k, _, v = line.partition(":")
        k = k.strip().lower()
        if k == "version":
            info["version"] = v.strip()
        elif k == "signatures":
            info["signatures"] = v.strip()
        elif k == "build time":
            info["built"] = v.strip()
    return info


def db_files(sigtool: str | None = None) -> list[dict]:
    d, now, out = db_dir(), time.time(), []
    for f in sorted(d.iterdir(), key=lambda p: p.name):
        if f.is_file() and f.suffix.lower() in DB_EXTS:
            st = f.stat()
            row = {"name": f.name, "size": st.st_size, "mtime": st.st_mtime,
                   "age_days": max(0.0, round((now - st.st_mtime) / 86400, 1))}
            if f.suffix.lower() in (".cvd", ".cld"):
                row.update({k: v for k, v in _sigtool_info(sigtool, f).items() if k in ("version", "signatures", "built")})
            out.append(row)
    return out


def human_size(n: int | None) -> str:
    if n is None:
        return ""
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


# ── the EICAR test string: built at runtime so the literal is never in any file of this project ──────────
def eicar_text() -> str:
    """The standard, harmless EICAR antivirus test string, assembled from parts. It must never appear in one
    piece in any source or doc file (antivirus tools would flag the repository); a test enforces that."""
    parts = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}", "$EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!", "$H+H*")
    return "".join(parts)


# ── parsing clamscan output ────────────────────────────────────────────────
SUMMARY_KEYS = {"known viruses": "known_signatures", "engine version": "engine", "scanned directories": "dirs",
                "scanned files": "scanned", "infected files": "infected_count", "data scanned": "data_scanned",
                "data read": "data_read", "time": "time"}


def parse_line(line: str) -> tuple:
    """One line of clamscan output -> ('found', path, signature) | ('error', None, text) | ('warn', None, text)
    | ('summary', key, value) | ('ok',) | ('blank',) | ('other', text).
    A path may contain spaces and colons ('C:\\x\\a: b.exe: Win.Test FOUND'): the signature is whatever follows
    the LAST ': '."""
    s = line.rstrip("\r\n")
    if not s.strip():
        return ("blank",)
    if s.endswith(" FOUND"):
        rest = s[:-6]
        i = rest.rfind(": ")
        if i > 0:
            return ("found", rest[:i], rest[i + 2:].strip())
    if s.endswith(" ERROR") or s.startswith(("ERROR:", "LibClamAV Error:")):
        return ("error", None, s)
    if s.startswith(("WARNING:", "LibClamAV Warning:")):
        return ("warn", None, s)
    if s.endswith(": OK") or s.endswith(" Empty file"):
        return ("ok",)
    k, sep, v = s.partition(":")
    if sep and k.strip().lower() in SUMMARY_KEYS:
        return ("summary", SUMMARY_KEYS[k.strip().lower()], v.strip())
    return ("other", s)


def parse_scan_output(text: str) -> dict:
    """Whole output -> {'infected': [(path, sig)], 'errors': [...], 'warnings': [...], 'summary': {...}}."""
    res: dict = {"infected": [], "errors": [], "warnings": [], "summary": {}}
    for line in text.splitlines():
        t = parse_line(line)
        if t[0] == "found":
            res["infected"].append((t[1], t[2]))
        elif t[0] == "error":
            res["errors"].append(t[2])
        elif t[0] == "warn":
            res["warnings"].append(t[2])
        elif t[0] == "summary":
            res["summary"][t[1]] = t[2]
    return res


def validate_paths(paths) -> list[str]:
    """User-chosen files and folders -> absolute, existing paths (always absolute, so a name starting with '-'
    can never be taken for an option)."""
    if isinstance(paths, str):
        paths = [paths]
    if not isinstance(paths, (list, tuple)) or not paths:
        raise AvError("Choose at least one folder or file to scan.")
    if len(paths) > MAX_PATHS:
        raise AvError(f"Choose at most {MAX_PATHS} folders or files at a time.")
    out = []
    for p in paths:
        if not isinstance(p, str) or not p.strip() or "\0" in p or len(p) > 4096:
            raise AvError("One of the paths is not valid.")
        a = os.path.abspath(os.path.expanduser(p.strip()))
        if not os.path.exists(a):
            raise AvError(f"Not found: {a}")
        if a not in out:
            out.append(a)
    return out


def build_scan_cmd(clamscan: str, db: str | Path, paths: list[str], prefix: list[str] | None = None) -> list[str]:
    """`clamscan --database=<app db> --recursive --infected <paths>` (the summary is kept: it carries the counts)."""
    return list(prefix or []) + [clamscan, f"--database={db}", "--recursive", "--infected"] + list(paths)


def freshclam_conf(db: str | Path, root: bool | None = None) -> str:
    """The minimal config freshclam is given. Nothing from the system's own freshclam.conf is used."""
    lines = [f"DatabaseDirectory {db}", "DatabaseMirror database.clamav.net", "DNSDatabaseInfo current.cvd.clamav.net",
             "MaxAttempts 3", "ConnectTimeout 30", "ReceiveTimeout 60"]
    if root if root is not None else (hasattr(os, "geteuid") and os.geteuid() == 0):
        lines.append("DatabaseOwner root")
    return "\n".join(lines) + "\n"


# ── isolation: remove the scanner's network where the OS allows it ─────────
def _candidates(which=shutil.which, platform: str | None = None) -> list[tuple[str, list[str], str]]:
    if not (platform or sys.platform).startswith("linux"):
        return []
    c = []
    un = which("unshare")
    if un:
        c.append(("unshare-net", [un, "--net"], "its own empty network namespace (unshare --net)"))
        c.append(("unshare-user-net", [un, "-rn"], "its own empty network namespace (unshare -rn, no root needed)"))
    fj = which("firejail")
    if fj:
        c.append(("firejail", [fj, "--quiet", "--noprofile", "--net=none"], "no network (firejail --net=none)"))
    return c


def _only_loopback(proc_net_dev: str) -> bool:
    ifaces = [ln.split(":")[0].strip() for ln in proc_net_dev.splitlines()[2:] if ":" in ln]
    return all(i == "lo" for i in ifaces)


def probe_isolation(which=shutil.which, run=run_cmd, platform: str | None = None) -> dict:
    """Try each method once and keep the first that REALLY removes the network: inside it, /proc/net/dev may
    list only the loopback interface. Returns {'method', 'prefix', 'isolated', 'label'}."""
    plat = platform or sys.platform
    cat = which("cat")
    for method, prefix, what in _candidates(which, plat):
        if not cat:
            break
        rc, out = run(prefix + [cat, "/proc/net/dev"], 10)
        if rc == 0 and "Inter-" in out and _only_loopback(out):
            return {"method": method, "prefix": prefix, "isolated": True,
                    "label": f"Network removed: the scanner runs in {what}. It cannot reach the internet at all."}
    if plat.startswith("linux"):
        why = "neither 'unshare' with a network namespace nor 'firejail' worked here"
    elif plat == "darwin":
        why = "macOS has no built-in way to remove a program's network without admin rights"
    else:
        why = "Windows has no built-in way to remove a program's network without admin rights"
    return {"method": "none", "prefix": [], "isolated": False,
            "label": f"Detection only: {why}. The scanner's connections are watched (and it is stopped if it "
                     "connects), but a very short connection between two looks could be missed. For a hard "
                     "guarantee, block clamscan in your firewall."}


_ISO: dict = {"val": None}
_ISO_LOCK = threading.Lock()


def get_isolation(force: bool = False) -> dict:
    with _ISO_LOCK:
        if force or _ISO["val"] is None:
            _ISO["val"] = probe_isolation()
        return _ISO["val"]


# ── watching the scanner for any connection ────────────────────────────────
def _is_loopback(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_loopback


class ConnWatch:
    """Polls the scanner's whole process tree (about every 100 ms) for any non-loopback connection, or any
    DNS lookup helper. `poll_once()` is the unit; `start()` runs it on a thread until `stop()`."""

    def __init__(self, pid: int, on_violation=None, ps=None, interval: float = POLL_SECONDS):
        self.pid, self.on_violation, self.interval = pid, on_violation, interval
        self.ps = ps if ps is not None else psutil
        self.available = self.ps is not None
        self.violations: list[str] = []
        self.polls = 0
        self.limited = False                 # the OS refused per-process connection lists; a system-wide list was used
        self._seen: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _exc(self, name: str):
        return getattr(self.ps, name, None) or Exception

    def _tree(self) -> list:
        root = self.ps.Process(self.pid)
        try:
            kids = root.children(recursive=True)
        except Exception:
            kids = []
        return [root] + list(kids)

    def _conns(self, proc, pids: set[int]) -> list:
        fn = getattr(proc, "net_connections", None) or getattr(proc, "connections", None)
        try:
            return list(fn(kind="inet"))
        except self._exc("AccessDenied"):
            self.limited = True
        except self._exc("NoSuchProcess"):
            return []
        sysfn = getattr(self.ps, "net_connections", None) or getattr(self.ps, "connections", None)
        try:
            return [c for c in sysfn(kind="inet") if getattr(c, "pid", None) in pids]
        except Exception:
            return []

    def poll_once(self) -> list[str]:
        """One look. Returns the NEW violations found (also remembered in self.violations)."""
        if not self.available:
            return []
        self.polls += 1
        new: list[str] = []
        try:
            procs = self._tree()
        except Exception:
            return []
        pids = set()
        for p in procs:
            try:
                pids.add(p.pid)
            except Exception:
                pass
        for p in procs:
            try:
                name = (p.name() or "").lower()
                if name.endswith(".exe"):
                    name = name[:-4]
            except Exception:
                name = ""
            if name in DNS_HELPERS:
                new.append(self._note(f"DNS helper started: {name}"))
            for c in self._conns(p, pids):
                r = getattr(c, "raddr", None)
                if not r:
                    continue                                  # listening or unconnected: nothing leaves
                ip, port = (getattr(r, "ip", None), getattr(r, "port", None)) if hasattr(r, "ip") else (r[0], r[1])
                if not ip or _is_loopback(str(ip)):
                    continue
                new.append(self._note(f"connection to {ip}:{port}"))
        new = [n for n in new if n]
        if new and self.on_violation:
            self.on_violation(new)
        return new

    def _note(self, text: str) -> str | None:
        if text in self._seen:
            return None
        self._seen.add(text)
        self.violations.append(text)
        return text

    @property
    def count(self) -> int:
        return len(self.violations)

    def start(self) -> None:
        def loop():
            while not self._stop.is_set():
                self.poll_once()
                self._stop.wait(self.interval)
        self.poll_once()
        self._thread = threading.Thread(target=loop, daemon=True, name="av-watch")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.poll_once()                                       # one last look before we report


def kill_tree(pid: int, ps=None) -> None:
    ps = ps if ps is not None else psutil
    try:
        if ps is None:
            os.kill(pid, 9)
            return
        root = ps.Process(pid)
        for c in root.children(recursive=True):
            try:
                c.kill()
            except Exception:
                pass
        root.kill()
    except Exception:
        pass


def system_freshclam_running() -> bool:
    """Is some freshclam (not ours) running on this computer? For information only."""
    if psutil is None:
        return False
    try:
        return any((p.info.get("name") or "").lower().removesuffix(".exe") == "freshclam"
                   for p in psutil.process_iter(["name"]))
    except Exception:
        return False


# ── the manager ────────────────────────────────────────────────────────────
class AvManager:
    """Owns the db folder, scans, the optional update, imports, self-test and quarantine. One job at a time."""

    def __init__(self, log=None, ps=None):
        self.log, self.ps = log, ps
        self._lock = threading.RLock()
        self._busy: str | None = None
        self._proc: subprocess.Popen | None = None
        self._stop = threading.Event()
        self._violated = threading.Event()
        self._lines: deque = deque(maxlen=2000)
        self._seq = 0
        self.scan: dict = {}              # live progress of the running / last scan
        self.last_scan: dict | None = self._load_last()
        self.proof: dict | None = None    # {'connections', 'isolation', 'when', 'kind'} of the latest scan or self-test
        self.update_info: dict = {}
        self.import_info: dict = {}
        self.selftest_info: dict = {}
        if self.last_scan:
            self.proof = {k: self.last_scan.get(k) for k in ("connections", "isolation", "when", "kind", "isolated")}

    # -- log
    def _say(self, text: str, level: str = "info", mirror: bool = True) -> None:
        with self._lock:
            self._seq += 1
            self._lines.append((self._seq, time.strftime("%H:%M:%S"), level, text))
        if self.log and mirror:
            getattr(self.log, level if level in ("info", "warn", "error", "debug") else "info")("av", text)

    # -- persistence of the latest scan (paths of your own files: deleted by Panic)
    def _results_path(self) -> Path:
        return av_dir() / "last_scan.json"

    def _load_last(self) -> dict | None:
        try:
            return json.loads(self._results_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _save_last(self) -> None:
        try:
            write_private(self._results_path(), json.dumps(self.last_scan))
        except OSError:
            pass

    # -- state for the front ends
    def state(self, redetect: bool = False) -> dict:
        tools = detect(redetect)
        iso = get_isolation()
        have = bool(tools["clamscan"]["path"])
        files = db_files(tools["sigtool"]["path"])
        notes = []
        if tools["clamdscan"]["path"]:
            notes.append("clamdscan was found but is never used: it talks to a clamd daemon set up by the system. "
                         "legalPrivacy scans with clamscan and its own signature folder only.")
        if system_freshclam_running():
            notes.append("A freshclam process is running on this computer. It was not started by legalPrivacy "
                         "and will contact ClamAV's servers on its own schedule; stopping it is up to you.")
        with self._lock:
            st = {
                "platform": sys.platform, "tools": tools, "found": have,
                "can_scan": have and bool(files), "can_update": bool(tools["freshclam"]["path"]),
                "install": None if have else install_hint(), "notes": notes, "docs_url": DOCS_URL,
                "db": {"dir": str(db_dir()), "files": files, "ready": bool(files),
                       "oldest_days": max((f["age_days"] for f in files), default=None)},
                "isolation": {k: iso[k] for k in ("method", "isolated", "label")},
                "watch": {"available": (self.ps or psutil) is not None, "interval_ms": int(POLL_SECONDS * 1000)},
                "update_hosts": list(UPDATE_HOSTS),
                "busy": self._busy, "scan": dict(self.scan), "last_scan": self.last_scan, "proof": self.proof,
                "update": dict(self.update_info), "import": dict(self.import_info), "selftest": dict(self.selftest_info),
                "quarantine": self.quarantine_list(),
                "log": [{"seq": s, "t": t, "level": lv, "text": x} for s, t, lv, x in list(self._lines)[-300:]],
                "log_seq": self._seq,
            }
        return st

    def proof_fact(self) -> dict | None:
        """For the Proof tab's 'Is it working?' list: None when the person has never used this feature."""
        if self.proof:
            return dict(self.proof)
        try:
            if any(f.suffix.lower() in DB_EXTS for f in db_dir().iterdir()):
                return {"connections": None}
        except OSError:
            pass
        return None

    # -- job plumbing
    def _begin(self, kind: str) -> None:
        with self._lock:
            if self._busy:
                raise AvError(f"Please wait: {self._busy} is still running.")
            self._busy = kind
            self._stop.clear()
            self._violated.clear()

    def _end(self) -> None:
        with self._lock:
            self._busy, self._proc = None, None
            if self.scan.get("running"):
                self.scan = {**self.scan, "running": False, "verdict": self.scan.get("verdict") or "Could not run"}
            if self.update_info.get("running"):
                self.update_info = {**self.update_info, "running": False, "ok": False, "text": "Could not run freshclam."}
            if self.import_info.get("running"):
                self.import_info = {**self.import_info, "running": False}

    def _spawn(self, name: str, fn) -> None:
        def go():
            try:
                fn()
            except AvError as exc:
                self._say(str(exc), "error")
            except Exception as exc:                          # noqa: BLE001 - shown in the log, never raised into the UI
                self._say(f"{name} failed: {type(exc).__name__}", "error")
            finally:
                self._end()
        threading.Thread(target=go, daemon=True, name=f"av-{name}").start()

    def stop(self) -> None:
        self._stop.set()
        p = self._proc
        if p is not None:
            kill_tree(p.pid, self.ps)

    def wait(self, timeout: float = 30) -> bool:
        """Block until no job is running (tests, and callers that want a synchronous result)."""
        end = time.time() + timeout
        while self._busy and time.time() < end:
            time.sleep(0.02)
        return not self._busy

    # -- scanning
    def _need_scanner(self) -> str:
        cs = detect()["clamscan"]["path"]
        if not cs:
            raise AvError("clamscan is not installed. See the install hints on this tab.")
        if not any(f.suffix.lower() in DB_EXTS for f in db_dir().iterdir()):
            raise AvError("There are no signatures yet. Use 'Import signature files' (offline), or the Update button "
                          "(contacts ClamAV's servers), first.")
        return cs

    def start_scan(self, paths) -> None:
        paths = validate_paths(paths)
        cs = self._need_scanner()
        self._begin("scan")
        self.scan = {"running": True, "paths": paths, "started": time.time(), "found": 0, "kind": "scan"}
        self._spawn("scan", lambda: self._execute(cs, paths, "scan"))

    def start_selftest(self) -> None:
        cs = self._need_scanner()
        self._begin("selftest")
        self.scan = {"running": True, "paths": [], "started": time.time(), "found": 0, "kind": "selftest"}
        self._spawn("selftest", lambda: self._selftest(cs))

    def _selftest(self, cs: str) -> None:
        tmpd = _sub("tmp")
        fd, name = tempfile.mkstemp(prefix="selftest-", suffix=".txt", dir=str(tmpd))
        try:
            with os.fdopen(fd, "w", encoding="ascii", newline="") as fh:
                fh.write(eicar_text())
            self._say("Self-test: scanning a harmless EICAR test file with this app's signatures. Your own antivirus "
                      "may react to that file.")
            res = self._execute(cs, [name], "selftest", save=False)
            hit = bool(res["infected"])
            self.selftest_info = {"detected": hit, "signature": (res["infected"][0]["signature"] if res["infected"] else None),
                                  "connections": res["connections"], "isolation": res["isolation"], "when": time.time(),
                                  "text": ("Detected: " + res["infected"][0]["signature"] if hit else
                                           "NOT detected. The signatures in the app's folder do not include a rule for the "
                                           "test file (or are not loading); see the log.")
                                  + ("" if res["connections"] == 0 else f"  NOT OFFLINE: {res['connections']} connection(s).")}
            self._say("Self-test: " + self.selftest_info["text"], "info" if hit else "warn")
        finally:
            try:
                os.unlink(name)                                 # the test file never outlives the test
            except OSError:
                pass

    def _execute(self, cs: str, paths: list[str], kind: str, save: bool = True) -> dict:
        iso = get_isolation()
        cmd = build_scan_cmd(cs, db_dir(), paths, iso["prefix"])
        self._say(f"Scanning {len(paths)} item(s) with clamscan and the app's own signature folder. "
                  + iso["label"])
        t0 = time.time()
        infected, errors, warns, summary, extra_err = [], [], [], {}, 0
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **_kw())
        self._proc = proc
        watch = ConnWatch(proc.pid, ps=self.ps)

        def violation(items):
            self._violated.set()
            for it in items:
                self._say(f"WARNING: the scanner tried to reach the network ({it}). Scan marked NOT OFFLINE; "
                          "stopping the scanner.", "warn")
            kill_tree(proc.pid, self.ps)
        watch.on_violation = violation
        watch.start()
        try:
            for raw in iter(proc.stdout.readline, b""):
                t = parse_line(raw.decode("utf-8", "replace"))
                if t[0] == "found":
                    if len(infected) < MAX_INFECTED_KEPT:
                        try:
                            size = os.stat(t[1]).st_size
                        except OSError:
                            size = None
                        infected.append({"path": t[1], "signature": t[2], "size": size})
                        self._say(f"FOUND: {t[1]}: {t[2]}", "warn", mirror=kind == "scan")
                        self.scan["found"] = len(infected)
                elif t[0] == "error":
                    if len(errors) < MAX_ERRORS_KEPT:
                        errors.append(t[2])
                    else:
                        extra_err += 1
                elif t[0] == "warn":
                    if len(warns) < 100:
                        warns.append(t[2])
                elif t[0] == "summary":
                    summary[t[1]] = t[2]
                self.scan["elapsed"] = round(time.time() - t0, 1)
            rc = proc.wait()
        finally:
            watch.stop()
            try:
                proc.stdout.close()
            except OSError:
                pass
        stopped = self._stop.is_set() and not self._violated.is_set()
        not_offline = watch.count > 0
        if rc == 0 or rc == 1:
            verdict = "Finished"
        elif stopped:
            verdict = "Stopped by you"
        elif not_offline:
            verdict = "Stopped: it tried to connect"
        else:
            verdict = "The scanner reported an error"
        res = {"kind": kind, "when": time.time(), "started": t0, "elapsed": round(time.time() - t0, 1), "paths": paths,
               "exit_code": rc, "infected": infected, "errors": errors, "more_errors": extra_err, "warnings": warns,
               "summary": summary, "stopped": stopped, "verdict": verdict, "connections": watch.count,
               "connection_details": watch.violations[:20], "not_offline": not_offline,
               "isolation": iso["method"], "isolated": iso["isolated"], "isolation_label": iso["label"],
               "watch_polls": watch.polls, "watch_limited": watch.limited, "watch_available": watch.available}
        self.proof = {k: res[k] for k in ("connections", "isolation", "when", "kind", "isolated")}
        if save:
            self.last_scan = res
            self._save_last()
        self.scan = {**res, "running": False}
        self._say(f"{verdict}: {len(infected)} infected, scanner connections: {watch.count}"
                  + (" -- NOT OFFLINE" if not_offline else " (stayed offline)"), "warn" if not_offline else "info")
        return res

    # -- updating (the ONLY place freshclam is ever run)
    def start_update(self, confirmed: bool = False) -> None:
        if not confirmed:
            raise AvError("Updating contacts ClamAV's servers, so it needs your confirmation first.")
        fc = detect()["freshclam"]["path"]
        if not fc:
            raise AvError("freshclam is not installed. You can still use 'Import signature files' with .cvd/.cld "
                          "files you downloaded yourself.")
        self._begin("update")
        self.update_info = {"running": True, "started": time.time()}
        self._spawn("update", lambda: self._update(fc))

    def _update(self, fc: str) -> None:
        conf = av_dir() / "freshclam.conf"
        db = db_dir()
        write_private(conf, freshclam_conf(db))
        cmd = [fc, f"--config-file={conf}", f"--datadir={db}", "--stdout"]
        self._say("Update: contacting ClamAV's servers (DNS TXT lookup of current.cvd.clamav.net, then an HTTPS "
                  "download from database.clamav.net). This is the only time anything connects.")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **_kw())
        self._proc = proc
        timer = threading.Timer(900, lambda: kill_tree(proc.pid, self.ps))
        timer.daemon = True
        timer.start()
        try:
            for raw in iter(proc.stdout.readline, b""):
                line = raw.decode("utf-8", "replace").rstrip()
                if line:
                    self._say("freshclam: " + line[:300])
            rc = proc.wait()
        finally:
            timer.cancel()
        ok = rc == 0
        self.update_info = {"running": False, "ok": ok, "exit_code": rc, "when": time.time(),
                            "text": "Signatures are up to date." if ok else f"freshclam stopped with exit code {rc}; see the log."}
        self._say("Update finished: " + self.update_info["text"], "info" if ok else "error")

    # -- offline import
    def start_import(self, paths) -> None:
        if isinstance(paths, str):
            paths = [paths]
        if not paths:
            raise AvError("Choose the .cvd or .cld files to import.")
        self._begin("import")
        self.import_info = {"running": True, "started": time.time()}
        self._spawn("import", lambda: self.import_files(list(paths)))

    def import_files(self, paths: list[str]) -> dict:
        """Verify each file in a private staging copy and only then put it into the db folder."""
        tools = detect()
        imported, rejected = [], []
        stage = _sub("staging")
        iso = get_isolation()
        for raw in paths:
            name = os.path.basename(str(raw))
            try:
                self._verify_and_install(str(raw), tools, stage, iso)
                imported.append(name)
                self._say(f"Import: {name} verified and added.")
            except AvError as exc:
                rejected.append({"path": str(raw), "reason": str(exc)})
                self._say(f"Import: {name} rejected: {exc}", "warn")
        shutil.rmtree(stage, ignore_errors=True)
        self.import_info = {"running": False, "imported": imported, "rejected": rejected, "when": time.time()}
        return self.import_info

    def _verify_and_install(self, raw: str, tools: dict, stage: Path, iso: dict) -> None:
        src = Path(os.path.abspath(os.path.expanduser(raw)))
        if not IMPORT_NAMES.match(src.name):
            raise AvError("only main, daily and bytecode files (.cvd or .cld) can be imported")
        if src.is_symlink() or not src.is_file():
            raise AvError("not a regular file")
        size = src.stat().st_size
        if size < 512 or size > 1 << 30:
            raise AvError("the file is too small or too large to be a ClamAV database")
        with open(src, "rb") as fh:
            if not fh.read(12).startswith(b"ClamAV-VDB:"):
                raise AvError("not a ClamAV database (missing the ClamAV-VDB header)")
        staged = stage / src.name.lower()
        shutil.copyfile(src, staged)                              # verify our own copy, not a file that can change
        sigtool, cs = tools["sigtool"]["path"], tools["clamscan"]["path"]
        if not cs:
            raise AvError("clamscan is needed to check the file but is not installed")
        if sigtool:
            rc, out = run_cmd([sigtool, f"--info={staged}"], 60)
            if rc != 0 or "Verification OK" not in out:
                raise AvError("sigtool could not verify its digital signature")
        eic = stage / "eicar-check.txt"
        eic.write_text(eicar_text(), encoding="ascii")
        try:
            rc, out = run_cmd(build_scan_cmd(cs, staged, [str(eic)], iso["prefix"]), 600)
        finally:
            try:
                eic.unlink()
            except OSError:
                pass
        if rc not in (0, 1):
            first = next((ln.strip() for ln in out.splitlines() if ln.strip()), "clamscan could not load it")
            raise AvError("clamscan could not load it: " + first[:160])
        dest = db_dir() / src.name.lower()
        other = db_dir() / (src.stem.lower() + (".cld" if src.suffix.lower() == ".cvd" else ".cvd"))
        os.replace(staged, dest)
        try:
            other.unlink()                                         # an older copy of the same database in the other form
        except OSError:
            pass

    # -- quarantine (explicit and reversible)
    def quarantine_list(self) -> list[dict]:
        out = []
        try:
            kids = sorted(quarantine_dir().iterdir())
        except OSError:
            return out
        for d in kids:
            try:
                meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
                meta["id"] = d.name
                out.append(meta)
            except (OSError, ValueError):
                continue
        return out

    def quarantine(self, path: str) -> dict:
        """Move one file that the latest scan flagged into the app folder. Needs an explicit call per file."""
        if self._busy == "scan":
            raise AvError("Wait for the scan to finish first.")
        flagged = {i["path"]: i for i in (self.last_scan or {}).get("infected", [])}
        item = flagged.get(path)
        if item is None:
            raise AvError("That file is not in the latest scan's results.")
        src = Path(path)
        if src.is_symlink() or not src.is_file():
            raise AvError("It is no longer a regular file at that place.")
        qid = secrets.token_hex(6)
        d = quarantine_dir() / qid
        d.mkdir(mode=0o700)
        blob = d / "file.bin"
        try:
            h = hashlib.sha256()
            with open(src, "rb") as a, open(blob, "wb") as b:
                for chunk in iter(lambda: a.read(1 << 20), b""):
                    h.update(chunk)
                    b.write(chunk)
            mode = src.stat().st_mode & 0o777
            if blob.stat().st_size != src.stat().st_size:
                raise AvError("The copy did not match the original; nothing was moved.")
            meta = {"original": str(src), "signature": item["signature"], "size": blob.stat().st_size, "mode": mode,
                    "sha256": h.hexdigest(), "when": time.time()}
            write_private(d / "meta.json", json.dumps(meta))
            try:
                blob.chmod(0o600)                                   # no execute bit while it sits here
            except OSError:
                pass
            src.unlink()                                            # only after the copy is complete and checked
        except Exception:
            shutil.rmtree(d, ignore_errors=True)
            raise
        self._say(f"Quarantined {src} ({item['signature']}). It can be restored from the Quarantine list.")
        return {**meta, "id": qid}

    @staticmethod
    def _qdir(qid: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{12}", str(qid)):
            raise AvError("Unknown quarantine entry.")
        d = quarantine_dir() / qid
        if not d.is_dir():
            raise AvError("Unknown quarantine entry.")
        return d

    def restore(self, qid: str) -> str:
        d = self._qdir(qid)
        meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
        dest = Path(meta["original"])
        if dest.exists():
            raise AvError(f"Something already exists at {dest}; nothing was overwritten.")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(d / "file.bin", dest)
        try:
            dest.chmod(int(meta.get("mode", 0o644)))
        except OSError:
            pass
        shutil.rmtree(d, ignore_errors=True)
        self._say(f"Restored {dest} from quarantine.")
        return str(dest)

    def delete_quarantined(self, qid: str) -> None:
        d = self._qdir(qid)
        shutil.rmtree(d, ignore_errors=True)
        self._say("Permanently deleted one quarantined file.")

    # -- Panic (hard): forget what the scans found; the signature files and your own files stay
    def wipe(self) -> list[str]:
        self.stop()
        self.wait(5)
        done = []
        for sub in ("quarantine", "staging", "tmp"):
            if (av_dir() / sub).exists():
                shutil.rmtree(av_dir() / sub, ignore_errors=True)
                done.append(sub)
        for name in ("last_scan.json", "freshclam.conf"):
            try:
                (av_dir() / name).unlink()
                done.append(name)
            except OSError:
                pass
        self.last_scan, self.proof, self.scan, self.selftest_info = None, None, {}, {}
        with self._lock:
            self._lines.clear()
        return done
