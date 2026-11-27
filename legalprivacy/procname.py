"""Name the running program "legalprivacy", so `killall legalprivacy` / `pkill -x legalprivacy` find it.

The system's process list shows a program's file name ("python3", or the downloaded file's name cut to 15 letters), not what
it is. On Linux the program can set its own process name; this does that and does nothing anywhere else or on any error.
"""
from __future__ import annotations

import sys

NAME = "legalprivacy"


def set_name(name: str = NAME) -> bool:
    if not sys.platform.startswith("linux"):
        return False
    try:
        import ctypes
        libc = ctypes.CDLL(None)
        PR_SET_NAME = 15
        return libc.prctl(PR_SET_NAME, name.encode("ascii")[:15], 0, 0, 0) == 0
    except Exception:
        return False
