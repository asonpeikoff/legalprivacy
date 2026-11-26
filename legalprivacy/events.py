"""In-memory event log shared by the scheduler, Tor manager and web UI.

Every subsystem writes here, so the UI can show one filterable, live view of
everything that is happening. It lives in memory only: nothing is written to
disk, and it is gone when the app stops (or when you clear it).
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from collections.abc import Callable

LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}


@dataclass
class Event:
    id: int
    ts: float
    level: str       # debug | info | warn | error
    source: str      # app | scheduler | tor | clearnet | onion | ui ...
    message: str
    data: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class EventLog:
    def __init__(self, capacity: int = 5000, file_path: Path | None = None,
                 max_file_bytes: int = 2_000_000):
        self._buf: deque[Event] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._next = 1
        self._file = file_path
        self._max_file_bytes = max_file_bytes
        self._listeners: list[Callable[[Event], None]] = []

    def add(self, level: str, source: str, message: str, data: dict | None = None) -> Event:
        with self._lock:
            ev = Event(self._next, time.time(), level, source, message, data)
            self._next += 1
            self._buf.append(ev)
        self._write_file(ev)
        for fn in list(self._listeners):
            try:
                fn(ev)
            except Exception:
                pass
        return ev

    # convenience
    def debug(self, source: str, msg: str, **data): return self.add("debug", source, msg, data or None)
    def info(self, source: str, msg: str, **data):  return self.add("info", source, msg, data or None)
    def warn(self, source: str, msg: str, **data):  return self.add("warn", source, msg, data or None)
    def error(self, source: str, msg: str, **data): return self.add("error", source, msg, data or None)

    def since(self, after_id: int = 0, min_level: str = "debug",
              sources: set[str] | None = None, limit: int = 1000) -> list[dict]:
        floor = LEVELS.get(min_level, 10)
        with self._lock:
            items = [e for e in self._buf if e.id > after_id]
        out = [e.to_dict() for e in items
               if LEVELS.get(e.level, 20) >= floor and (not sources or e.source in sources)]
        return out[-limit:]

    def clear_older(self, seconds: float) -> None:
        """Forget entries older than this many seconds; newer ones stay."""
        cut = time.time() - seconds
        with self._lock:
            keep = [e for e in self._buf if e.ts >= cut]
            self._buf.clear()
            self._buf.extend(keep)

    def clear(self) -> None:
        """Forget everything in the live log. Ids keep counting up so open UIs stay in sync."""
        with self._lock:
            self._buf.clear()

    def last_id(self) -> int:
        with self._lock:
            return self._next - 1

    def subscribe(self, fn: Callable[[Event], None]) -> None:
        self._listeners.append(fn)

    def _write_file(self, ev: Event) -> None:
        if not self._file:
            return
        try:
            if self._file.exists() and self._file.stat().st_size > self._max_file_bytes:
                self._file.replace(self._file.with_suffix(".log.1"))
            stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ev.ts))
            with open(self._file, "a", encoding="utf-8") as fh:
                fh.write(f"{stamp} {ev.level.upper():5s} [{ev.source}] {ev.message}\n")
        except OSError:
            pass
