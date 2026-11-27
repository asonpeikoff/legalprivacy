"""Stops Tor programs this app left behind, so a restart or update never fails on a conflicting process.

A Tor that an earlier run started (the app was killed, crashed, or an update restarted it before Tor had finished stopping)
keeps the data folder's lock and the local ports, and the new Tor then refuses to start. A process is treated as ours, and
stopped, only when ALL of these hold: it is a Tor program (name starts with "tor"), its command line names one of this
app's own Tor folders (the managed Tor's or the relay's), and it is not owned by a different, still running legalPrivacy
window. Your own system Tor, Tor Browser and another person's Tor are never touched (their command lines do not name these
folders). Same user only: no sudo is involved or needed.
"""
from __future__ import annotations

import os
import time


def _ours(cmd: str, folders: list[str]) -> bool:
    return any(f and f in cmd for f in folders)


def stale_tors(folders: list[str]) -> list:
    """Processes that are Tor, run from our folders, and are not owned by another live legalPrivacy window."""
    try:
        import psutil
    except Exception:
        return []
    me, found = os.getpid(), []
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if p.info["pid"] == me or not (p.info["name"] or "").lower().startswith("tor"):
                continue
            if not _ours(" ".join(p.info["cmdline"] or []), folders):
                continue
            parent = p.parent()
            if parent is not None and parent.pid != me:
                pcmd = " ".join(parent.cmdline()).lower()
                if "legalprivacy" in pcmd or "legalprivacy" in (parent.name() or "").lower():
                    continue                 # another running legalPrivacy owns it: not ours to stop
            found.append(p)
        except Exception:
            continue
    return found


def kill_stale_tors(log=None, folders: list[str] | None = None) -> int:
    """Stop them (politely, then for good). Returns how many were stopped."""
    if folders is None:
        from .paths import relay_dir, tor_dir
        folders = [str(tor_dir()), str(relay_dir())]
    procs = stale_tors(folders)
    for p in procs:
        try:
            if log:
                log.info("app", f"Stopping a Tor program left over from an earlier run (process {p.pid}).")
            p.terminate()
        except Exception:
            pass
    deadline = time.time() + 6
    for p in procs:
        try:
            p.wait(timeout=max(0.1, deadline - time.time()))
        except Exception:
            try:
                p.kill()
                p.wait(timeout=3)
            except Exception:
                if log:
                    log.warn("app", f"Could not stop the leftover Tor (process {p.pid}).")
    return len(procs)
