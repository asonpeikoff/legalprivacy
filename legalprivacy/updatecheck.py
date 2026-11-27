"""Is this copy of legalPrivacy behind the one on GitHub? Only asks; never downloads or installs anything.

One HTTPS request (two at most) to api.github.com for the newest commit on the main branch, compared with the
commit this copy was checked out at (when it is a git checkout) or with its version number (when it is not).
Nothing about you is sent. It can be turned off in Settings.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable

REPO = "asonpeikoff/legalprivacy"
BRANCH = "master"
API = f"https://api.github.com/repos/{REPO}/"
RAW_INIT = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/legalprivacy/__init__.py"
_SHA = re.compile(r"[0-9a-f]{40}")


def _get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("refusing a non-HTTPS address")
    req = urllib.request.Request(url, headers={"User-Agent": "legalPrivacy-updatecheck",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=15) as r:                  # nosec - fixed https hosts
        return r.read(2_000_000)


def local_commit(root: Path | None = None) -> str | None:
    """The commit this copy is at, if it is a git checkout."""
    root = root or Path(__file__).resolve().parent.parent
    if not (root / ".git").exists():
        return None
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True,
                             timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return out if _SHA.fullmatch(out) else None


def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def check(version: str, http: Callable[[str], bytes] = _get, commit: str | None = None) -> dict[str, Any]:
    """Returns {status: current|behind|unknown, behind_by, latest, ...}. Raises on network trouble."""
    commit = commit if commit is not None else local_commit()
    head = json.loads(http(API + f"commits/{BRANCH}"))
    latest = head["sha"]
    info = {"status": "unknown", "behind_by": 0, "local": commit, "latest": latest,
            "latest_message": (head.get("commit", {}).get("message") or "").split("\n")[0][:140],
            "version": version, "how": "git pull" if commit else None, "at": time.time()}
    if commit:
        if commit == latest:
            info["status"] = "current"
            return info
        try:
            cmp_ = json.loads(http(API + f"compare/{commit}...{latest}"))
        except Exception:                                     # a commit GitHub doesn't know (your own work)
            return info
        if cmp_.get("status") == "ahead":
            info.update(status="behind", behind_by=int(cmp_.get("ahead_by") or 0))
        elif cmp_.get("status") in ("identical", "behind"):   # yours is the same or newer than GitHub's
            info["status"] = "current"
        return info
    ver = None
    try:                                                   # a downloaded copy follows RELEASES, not the newest commit
        rel = json.loads(http(API + "releases/latest"))
        tag = str(rel.get("tag_name", "")).lstrip("v")
        if not rel.get("draft") and not rel.get("prerelease") and re.fullmatch(r"\d+(?:\.\d+){1,3}", tag):
            ver = tag
            info["latest_message"] = str(rel.get("name") or f"legalPrivacy {tag}")[:140]
    except Exception:
        ver = None
    if ver is None:
        m = re.search(r'__version__\s*=\s*"([\d.]+)"', http(RAW_INIT).decode("utf-8", "ignore"))
        ver = m.group(1) if m else None
    if ver:
        info["latest_version"] = ver
        info["status"] = "behind" if _vkey(ver) > _vkey(version) else "current"
    return info
