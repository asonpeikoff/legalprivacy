"""Tor Browser for your own private browsing: download, verify, keep up to date, launch.

This is separate from the Tor that makes noise: its own folder, its own profile, its own Tor inside.
Nothing the noise does touches it.

Safety, in order:
  * Only dist.torproject.org (HTTPS) for the download and keys.openpgp.org for the signing key.
  * The download must carry a valid OpenPGP signature from the Tor Browser Developers signing key,
    checked with GnuPG in a throw-away key folder against the fingerprint pinned below. No gpg, a bad
    signature, an expired key or a different signer: nothing is installed.
  * A size cap, a strict version-number pattern and a path-safe unpacker (no links, no escaping the folder).
  * Before every launch the programs on disk are compared with the fingerprints taken right after the
    signature passed; any difference means it is reinstalled (and verified again), never run.
  * A newer release is installed automatically, checked the same way, but never while it is open.
  * It is never started as the administrator (root), and a new copy is only swapped in after it passed.
  * Linux is installed and launched by the app. On Windows and macOS the app sends you to the official
    download page instead (it never runs a downloaded installer by itself).
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

from .paths import app_dir

DIST_BASE = "https://dist.torproject.org/torbrowser/"
KEY_FPR = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"      # Tor Browser Developers (signing key)
KEY_URL = "https://keys.openpgp.org/vks/v1/by-fingerprint/" + KEY_FPR
DOWNLOAD_PAGE = "https://www.torproject.org/download/"
MAX_BYTES = 600_000_000
_VERSION = re.compile(r"\d+(?:\.\d+){1,3}")
_BAD_SIG = ("BADSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "ERRSIG", "NO_PUBKEY")


class TorBrowserError(RuntimeError):
    pass


def tb_dir() -> Path:
    return app_dir() / "torbrowser"


def _http_get(url: str, timeout: float = 30.0, limit: int = 5_000_000) -> bytes:
    if not url.startswith("https://"):
        raise TorBrowserError("refusing a non-HTTPS address")
    req = urllib.request.Request(url, headers={"User-Agent": "legalPrivacy-torbrowser"})
    with urllib.request.urlopen(req, timeout=timeout) as r:             # nosec - fixed https hosts
        data = r.read(limit + 1)
    if len(data) > limit:
        raise TorBrowserError("a download was bigger than expected")
    return data


def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def archive_name(version: str) -> str | None:
    """The official file for this computer, or None where the app does not install it itself."""
    if not sys.platform.startswith("linux") or platform.machine().lower() not in ("x86_64", "amd64"):
        return None
    if not _VERSION.fullmatch(version):
        raise TorBrowserError("unexpected version number")
    return f"tor-browser-linux-x86_64-{version}.tar.xz"


def supported() -> bool:
    return archive_name("1.0") is not None


def latest_version(http: Callable[[str], bytes] = _http_get) -> str:
    """The newest stable release that has a file for this computer (newest first, skipping any that don't)."""
    index = http(DIST_BASE).decode("utf-8", "ignore")
    versions = sorted({v for v in re.findall(r'href="(\d+(?:\.\d+)+)/"', index) if _VERSION.fullmatch(v)},
                      key=_vkey, reverse=True)
    for ver in versions[:6]:
        name = archive_name(ver)
        if name is None:
            raise TorBrowserError("Tor Browser is not installed by the app on this system")
        if name in http(f"{DIST_BASE}{ver}/").decode("utf-8", "ignore"):
            return ver
    raise TorBrowserError("couldn't find a Tor Browser release for this computer")


def installed_version() -> str | None:
    try:
        v = (tb_dir() / "VERSION").read_text().strip()
        return v if _VERSION.fullmatch(v) and (tb_dir() / "tor-browser").is_dir() else None
    except OSError:
        return None


def verify_signature(archive: Path, sig: Path, key_bytes: bytes, gpg: str | None = None) -> None:
    """Raise TorBrowserError unless `sig` is a valid signature of `archive` by the pinned signing key."""
    gpg = gpg or shutil.which("gpg")
    if not gpg:
        raise TorBrowserError("GnuPG (gpg) is needed to check Tor Browser's signature and isn't installed. "
                              "Install it (for example: sudo apt install gnupg), or download Tor Browser "
                              "yourself from torproject.org")
    with tempfile.TemporaryDirectory(prefix="lp-gpg-") as home:
        os.chmod(home, 0o700)
        keyfile = Path(home) / "key.asc"
        keyfile.write_bytes(key_bytes)
        base = [gpg, "--homedir", home, "--batch", "--no-tty"]
        imp = subprocess.run(base + ["--import", str(keyfile)], capture_output=True, text=True, timeout=60)
        if imp.returncode != 0:
            raise TorBrowserError("couldn't read the Tor Browser signing key")
        ver = subprocess.run(base + ["--status-fd", "1", "--verify", str(sig), str(archive)],
                             capture_output=True, text=True, timeout=120)
        status = [ln.split() for ln in ver.stdout.splitlines() if ln.startswith("[GNUPG:]")]
        if ver.returncode != 0 or any(len(s) > 1 and s[1] in _BAD_SIG for s in status):
            raise TorBrowserError("the Tor Browser signature is NOT valid; nothing was installed")
        good = [s for s in status if len(s) > 1 and s[1] == "VALIDSIG"]
        if not good or KEY_FPR not in (good[0][2], good[0][-1]):
            raise TorBrowserError("the download was not signed by the Tor Browser Developers key; "
                                  "nothing was installed")


_WATCHED = ("Browser/start-tor-browser", "Browser/firefox.real", "Browser/firefox",
            "Browser/TorBrowser/Tor/tor", "Browser/TorBrowser/Tor/libevent-2.1.so.7")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest(tree: Path) -> dict[str, str]:
    """Fingerprints of the programs that matter (the launcher, Firefox, Tor), taken right after the signature passed."""
    return {rel: _sha256(tree / rel) for rel in _WATCHED if (tree / rel).is_file() and not (tree / rel).is_symlink()}


def signature_info() -> dict | None:
    """What the app recorded when it verified the installed copy (None if nothing is installed or recorded)."""
    try:
        d = json.loads((tb_dir() / "SIGNED.json").read_text())
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def verify_install() -> None:
    """Re-check, before every launch, that the installed programs are still the ones whose signature was verified."""
    info = signature_info()
    if not info or info.get("version") != installed_version() or info.get("fingerprint") != KEY_FPR:
        raise TorBrowserError("the installed Tor Browser has no record of a verified signature")
    tree = tb_dir() / "tor-browser"
    for rel, want in (info.get("files") or {}).items():
        p = tree / rel
        if not p.is_file() or _sha256(p) != want:
            raise TorBrowserError(f"{rel} is not the file whose signature was verified")


def running() -> bool:
    """Is this copy of Tor Browser open right now? (Linux: looks at the program paths of running processes.)"""
    marker = str(tb_dir() / "tor-browser").encode()
    try:
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    if marker in Path(f"/proc/{pid}/cmdline").read_bytes():
                        return True
                except OSError:
                    continue
    except OSError:
        pass
    return False


def _extract(archive: Path, target: Path) -> None:
    from .tormanager import _safe_extract
    _safe_extract(archive, target)


def install(progress: Callable[[float], None] | None = None, http: Callable[..., bytes] = _http_get,
            gpg: str | None = None) -> str:
    """Download, verify and install the newest Tor Browser. Returns its version. Nothing is replaced
    unless every check passed."""
    progress = progress or (lambda f: None)
    ver = latest_version(http)
    name = archive_name(ver)
    if installed_version() == ver:
        try:
            verify_install()
            return ver
        except TorBrowserError:                                  # changed since it was checked: replace it
            pass
    progress(0.03)
    root = tb_dir()
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="dl-", dir=str(root)))
    try:
        archive, sig = work / name, work / (name + ".asc")
        sig.write_bytes(http(f"{DIST_BASE}{ver}/{name}.asc", limit=100_000))
        key = http(KEY_URL, limit=300_000)
        req = urllib.request.Request(f"{DIST_BASE}{ver}/{name}", headers={"User-Agent": "legalPrivacy-torbrowser"})
        got = 0
        with urllib.request.urlopen(req, timeout=60) as r, open(archive, "wb") as out:    # nosec - fixed https host
            total = int(r.headers.get("Content-Length") or 0)
            if total > MAX_BYTES:
                raise TorBrowserError("the download is bigger than expected")
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                got += len(chunk)
                if got > MAX_BYTES:
                    raise TorBrowserError("the download is bigger than expected")
                out.write(chunk)
                if total:
                    progress(0.05 + 0.8 * got / total)
        verify_signature(archive, sig, key, gpg)
        archive_sha = _sha256(archive)
        progress(0.9)
        new = work / "unpacked"
        new.mkdir()
        _extract(archive, new)
        if not (new / "tor-browser" / "Browser" / "start-tor-browser").exists():
            raise TorBrowserError("the download did not contain Tor Browser's start program")
        for old in (root / "tor-browser",):
            shutil.rmtree(old, ignore_errors=True)
        shutil.move(str(new / "tor-browser"), str(root / "tor-browser"))
        (root / "SIGNED.json").write_text(json.dumps({
            "version": ver, "fingerprint": KEY_FPR, "verified_at": time.time(), "archive": name,
            "archive_sha256": archive_sha, "files": _manifest(root / "tor-browser")}))
        (root / "VERSION").write_text(ver)
        progress(1.0)
        return ver
    finally:
        shutil.rmtree(work, ignore_errors=True)               # the download is never kept


def shared_env(socks: str, control: str | None, cookie: str | None) -> dict[str, str]:
    """Environment that makes Tor Browser use the app's Tor instead of starting its own."""
    sh, _, sp = socks.rpartition(":")
    env = {"TOR_SKIP_LAUNCH": "1", "TOR_SOCKS_HOST": sh or "127.0.0.1", "TOR_SOCKS_PORT": sp,
           "TOR_TRANSPROXY": "0"}
    if control:
        ch, _, cp = control.rpartition(":")
        env.update({"TOR_CONTROL_HOST": ch or "127.0.0.1", "TOR_CONTROL_PORT": cp})
        if cookie:
            env["TOR_CONTROL_COOKIE_AUTH_FILE"] = cookie
    return env


def clean_env() -> dict[str, str]:
    """The environment to start Tor Browser with. In the packaged app, PyInstaller points LD_LIBRARY_PATH (macOS:
    DYLD_LIBRARY_PATH) at its own bundled libraries and keeps the original in <name>_ORIG. Every program we start
    inherits that, and Tor Browser (and the tor inside it) then loads the wrong copies of shared libraries and cannot
    connect. Hand it the original values back."""
    env = dict(os.environ)
    if getattr(sys, "frozen", False) or getattr(sys, "_MEIPASS", None):
        for var in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH"):
            orig = env.pop(var + "_ORIG", None)
            if orig is not None:
                env[var] = orig
            else:
                env.pop(var, None)
    return env


def socks_answers(host: str, port: int, timeout: float = 3.0) -> str | None:
    """None when something at host:port speaks SOCKS5 (what Tor Browser needs there), else why not."""
    import socket
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")                 # SOCKS5, one method offered: none
            reply = s.recv(2)
    except OSError as exc:
        return f"nothing is listening at {host}:{port} ({exc})"
    if len(reply) < 2 or reply[0] != 5:
        return f"{host}:{port} answered, but not like a SOCKS5 proxy"
    return None


def launch_log() -> Path:
    return app_dir() / "torbrowser.log"


def launch(shared: dict[str, str] | None = None) -> None:
    if not supported():
        raise TorBrowserError("On this system, get Tor Browser from " + DOWNLOAD_PAGE)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise TorBrowserError("Tor Browser must not be run as the administrator (root). Open legalPrivacy as "
                              "your normal user.")
    start = tb_dir() / "tor-browser" / "Browser" / "start-tor-browser"
    if not start.exists():
        raise TorBrowserError("Tor Browser isn't installed yet")
    verify_install()
    env = {**clean_env(), **(shared or {})}
    try:                                    # keep what it prints: when it cannot connect, the reason is usually here
        log = open(launch_log(), "ab")  # noqa: SIM115 (handed to the child process, which keeps it)
        log.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} start-tor-browser "
                  f"({'shared Tor' if shared else 'its own Tor'}) ---\n".encode())
        log.flush()
    except OSError:
        log = subprocess.DEVNULL
    subprocess.Popen([str(start), "--detach"], cwd=str(start.parent), stdin=subprocess.DEVNULL, env=env,
                     stdout=log, stderr=log, start_new_session=True)


class TorBrowserManager:
    """Background install/update with a status the dashboard can show."""

    def __init__(self, log=None, install_fn=install, latest_fn=latest_version, launch_fn=launch):
        self.log = log
        self._install, self._latest, self._launch = install_fn, latest_fn, launch_fn
        self.state, self.error, self.progress = "idle", None, 0.0
        self.latest: str | None = None
        self.checked_at = 0.0
        self.shared_fn: Callable[[], dict[str, str] | None] = lambda: None   # set by the app when sharing is on
        self._lock = threading.Lock()

    def _say(self, level: str, msg: str) -> None:
        if self.log is not None:
            self.log.add(level, "tor", msg)

    def snapshot(self) -> dict[str, Any]:
        inst = installed_version()
        return {"supported": supported(), "state": self.state, "error": self.error, "progress": self.progress,
                "installed": inst, "latest": self.latest, "download_page": DOWNLOAD_PAGE,
                "signature": (lambda i: {"ok": True, "fingerprint": i["fingerprint"], "at": i["verified_at"]}
                              if i and i.get("version") == inst else None)(signature_info()),
                "update_available": bool(inst and self.latest and _vkey(self.latest) > _vkey(inst))}

    def check(self) -> None:
        """Ask which version is newest (quietly; never installs)."""
        try:
            self.latest = self._latest()
            self.checked_at = time.time()
        except Exception as exc:                                 # offline is fine
            self._say("info", f"Couldn't check for a newer Tor Browser: {exc}")

    def install_async(self, then_launch: bool = False) -> None:
        with self._lock:
            if self.state == "installing":
                return
            self.state, self.error, self.progress = "installing", None, 0.0
        threading.Thread(target=self._run_install, args=(then_launch,), daemon=True, name="torbrowser").start()

    def _run_install(self, then_launch: bool) -> None:
        try:
            ver = self._install(progress=lambda f: setattr(self, "progress", f))
            self.latest, self.checked_at = ver, time.time()
            self.state = "idle"
            self._say("info", f"Tor Browser {ver} is installed and up to date.")
            if then_launch:
                self._launch_now()
        except Exception as exc:
            self.state, self.error = "error", str(exc)
            self._say("warn", f"Tor Browser: {exc}")

    def _launch_now(self) -> None:
        shared = self.shared_fn()                       # raises if sharing is on but the app's Tor isn't ready
        self._launch(shared) if shared else self._launch()

    def auto_update(self) -> None:
        """Install a newer release in the background, but never while Tor Browser is open."""
        self.check()
        snap = self.snapshot()
        if snap["update_available"] and self.state != "installing" and not running():
            self._say("info", f"Updating Tor Browser {snap['installed']} to {snap['latest']} (signature is checked).")
            self.install_async()

    def open(self) -> dict:
        """Launch it, installing or updating first when needed. Never launches a copy that is out of date
        or one whose files no longer match the signature that was checked."""
        self.check()
        inst = installed_version()
        try:
            if inst:
                verify_install()
        except TorBrowserError as exc:
            self._say("warn", f"Tor Browser will be reinstalled: {exc}")
            inst = None
        if inst is None or (self.latest and _vkey(self.latest) > _vkey(inst)):
            self.install_async(then_launch=True)
        else:
            self._launch_now()
        return self.snapshot()
