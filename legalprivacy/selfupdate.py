"""Keep legalPrivacy itself on the newest release, by itself.

Only for the downloaded Linux program (the file from the GitHub release; a pip or git copy keeps using the update notice).
Every six hours it asks GitHub for the newest release; if that is newer than this copy it

  * downloads the release file (HTTPS, from this project's own releases; a size cap),
  * checks its SHA-256 against the digest GitHub publishes for that file (no digest, or a different one: nothing is installed),
  * writes it next to the running program and swaps it in with one rename (the old one is kept as <name>.previous),
  * and starts the new program in place of the old one (stopping Tor and the relay first; under a service manager the process
    id stays the same, so it keeps being supervised).

At most one update a day. Turn it off in Settings ("Keep legalPrivacy up to date").
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import time
import urllib.request
from pathlib import Path

REPO = "asonpeikoff/legalprivacy"
API = f"https://api.github.com/repos/{REPO}/releases/latest"
ASSET = "legalprivacy-launch-linux"
MAX_BYTES = 400_000_000
CHECK_EVERY = 6 * 3600
MIN_GAP = 24 * 3600


def _get(url: str, limit: int = 3_000_000) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("refusing a non-HTTPS address")
    req = urllib.request.Request(url, headers={"User-Agent": "legalPrivacy-selfupdate", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as r:               # nosec - fixed https hosts
        return r.read(limit)


def vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def can_self_update() -> bool:
    """Only the downloaded Linux program, in a folder we may write to."""
    exe = Path(sys.executable)
    return bool(getattr(sys, "frozen", False) and sys.platform.startswith("linux") and exe.name.startswith("legalprivacy")
                and os.access(exe.parent, os.W_OK))


def newest(current: str, http=_get) -> dict | None:
    """The newest release's file if it is newer than `current`: {version, url, size, sha256}; else None."""
    rel = json.loads(http(API))
    if rel.get("draft") or rel.get("prerelease"):
        return None
    tag = str(rel.get("tag_name", "")).lstrip("v")
    if not re.fullmatch(r"\d+(?:\.\d+){1,3}", tag) or vkey(tag) <= vkey(current):
        return None
    for a in rel.get("assets", []):
        if a.get("name") == ASSET:
            url, digest = str(a.get("browser_download_url", "")), str(a.get("digest", ""))
            if not url.startswith(f"https://github.com/{REPO}/releases/download/") or not digest.startswith("sha256:"):
                return None                                                # no published digest: refuse
            return {"version": tag, "url": url, "size": int(a.get("size") or 0), "sha256": digest.split(":", 1)[1].lower()}
    return None


def download_and_swap(rel: dict, exe: Path, opener=urllib.request.urlopen, log=None) -> Path:
    """Download, verify, and swap the new program in. Returns the path of the kept previous copy."""
    if rel["size"] <= 0 or rel["size"] > MAX_BYTES:
        raise RuntimeError("the release file has an unexpected size")
    tmp = exe.with_name(exe.name + ".new")
    h, got = hashlib.sha256(), 0
    req = urllib.request.Request(rel["url"], headers={"User-Agent": "legalPrivacy-selfupdate"})
    try:
        with opener(req, timeout=120) as r, open(tmp, "wb") as out:      # nosec - fixed https host
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                got += len(chunk)
                if got > MAX_BYTES:
                    raise RuntimeError("the download is larger than allowed")
                out.write(chunk)
                h.update(chunk)
        if h.hexdigest() != rel["sha256"]:
            raise RuntimeError("the download does not match the checksum GitHub publishes for it; nothing was installed")
        tmp.chmod(tmp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        prev = exe.with_name(exe.name + ".previous")
        if exe.exists():
            os.replace(exe, prev)
        os.replace(tmp, exe)
        return prev
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def run_once(ctl, current: str, http=_get, apply=download_and_swap, restart=None) -> str | None:
    """One round: returns the new version if one was installed (and the program restarted), else None."""
    if not ctl.app.get("auto_update", True) or not can_self_update():
        return None
    stamp = Path(ctl.profile_path).with_name("selfupdate.stamp")
    try:
        if time.time() - float(stamp.read_text()) < MIN_GAP:
            return None
    except (OSError, ValueError):
        pass
    try:
        rel = newest(current, http)
    except Exception as exc:
        ctl.log.info("app", f"Could not check for a newer legalPrivacy ({exc}).")
        return None
    if rel is None:
        return None
    ctl.log.info("app", f"legalPrivacy {rel['version']} is out (this is {current}). Downloading it and checking its checksum…")
    try:
        apply(rel, Path(sys.executable), log=ctl.log)
    except Exception as exc:
        ctl.log.warn("app", f"Could not update to {rel['version']}: {exc}")
        return None
    try:
        stamp.write_text(str(time.time()))
    except OSError:
        pass
    ctl.log.info("app", f"Updated to legalPrivacy {rel['version']}. Restarting on it now.")
    (restart or _restart)(ctl)
    return rel["version"]


def _restart(ctl) -> None:
    try:
        ctl.stop(stop_tor=True)
    except Exception:
        pass
    os.execv(sys.executable, [sys.executable, *sys.argv[1:]])
