"""Single-machine load generator and a dstat-style live graph, for load-testing infrastructure you run.

This is a LOAD TESTER, not an attack tool. By design it:
  * runs on this one computer only — there is no way to drive other machines from here (to load-test from several of your
    own boxes, run the app on each and point them at the same target);
  * refuses to start until you confirm you own the target or are authorised to test it;
  * is capped: at most MAX_RPS requests a second, MAX_CONN concurrent connections and MAX_SECONDS per run (raise the caps
    for your own heavier testing with the LEGALPRIVACY_LOADTEST_* environment variables);
  * never spoofs addresses or forges packets — L7 is ordinary HTTP requests, L4 is ordinary TCP connections;
  * will not aim at a government address range (the same ranges the rest of the app avoids).

What it records each second (the "dstat" series): requests sent, responses by result, bytes in/out, and latency. The graph
is of the load THIS tool generates and the answers it gets back; it does not read a remote machine's own interface counters.
"""
from __future__ import annotations

import socket
import ssl
import threading
import time
import urllib.parse
from collections import deque
from collections.abc import Callable

from .paths import getenv

MAX_RPS = int(getenv("LOADTEST_MAX_RPS") or 2000)          # ceiling on requests/connections per second
MAX_CONN = int(getenv("LOADTEST_MAX_CONN") or 256)         # ceiling on concurrent workers
MAX_SECONDS = int(getenv("LOADTEST_MAX_SECONDS") or 600)   # ceiling on how long one run may last
USER_AGENT = "legalPrivacy-loadtest/1.0 (+authorized load testing)"
HISTORY = 900                                              # seconds of per-second buckets kept for the graph


class LoadTestError(ValueError):
    """A bad or unauthorised load-test request."""


def _check_target(host: str) -> None:
    """Refuse the government ranges the rest of the app avoids (Virginia applies to Tor relays only). Resolution failures are left to the run."""
    try:
        from . import geoban
        import socket as _s
        for info in _s.getaddrinfo(host, None):
            why = geoban.shared().reason(info[4][0])
            if why:
                raise LoadTestError(f"That target resolves into {why}; this tool will not aim traffic there.")
    except LoadTestError:
        raise
    except Exception:
        return                                              # can't resolve now: the run will fail on its own, harmlessly


class LoadTest:
    """One capped load run against one target, on this machine only."""

    def __init__(self, target: str, mode: str = "http", rps: int = 50, concurrency: int = 10, duration: float = 30.0,
                 method: str = "GET", authorized: bool = False, body: str = "", timeout: float = 10.0,
                 clock: Callable[[], float] = time.monotonic, wallclock: Callable[[], float] = time.time):
        if not authorized:
            raise LoadTestError("Confirm you own this target or are authorised to test it before starting.")
        self.mode = mode if mode in ("http", "tcp") else "http"
        self.method = (method or "GET").upper()
        if self.method not in ("GET", "HEAD", "POST"):
            raise LoadTestError("HTTP method must be GET, HEAD or POST.")
        self.target = (target or "").strip()
        self.host, self.port, self.url, self.use_tls = self._parse(self.target, self.mode)
        _check_target(self.host)
        self.rps = max(1, min(int(rps), MAX_RPS))
        self.concurrency = max(1, min(int(concurrency), MAX_CONN))
        self.duration = max(1.0, min(float(duration), float(MAX_SECONDS)))
        self.body = (body or "").encode("utf-8", "replace")
        self.timeout = max(1.0, min(float(timeout), 60.0))
        self.clock, self.wallclock = clock, wallclock
        self.stop = threading.Event()
        self._lock = threading.Lock()
        self._buckets: dict[int, dict] = {}
        self._lat: deque[float] = deque(maxlen=5000)
        self.status = {"running": False, "done": False, "mode": self.mode, "target": self.target,
                       "host": self.host, "port": self.port, "rps": self.rps, "concurrency": self.concurrency,
                       "duration": self.duration, "capped": {"rps": self.rps == MAX_RPS, "conn": self.concurrency == MAX_CONN},
                       "sent": 0, "ok": 0, "failed": 0, "bytes_in": 0, "bytes_out": 0,
                       "errors": {}, "started_at": None, "elapsed": 0.0, "series": []}

    @staticmethod
    def _parse(target: str, mode: str) -> tuple[str, int, str, bool]:
        if mode == "http":
            if not urllib.parse.urlparse(target).scheme:
                target = "http://" + target
            u = urllib.parse.urlparse(target)
            if u.scheme not in ("http", "https") or not u.hostname:
                raise LoadTestError("For an HTTP load test, give a URL like https://host/path.")
            tls = u.scheme == "https"
            return u.hostname, u.port or (443 if tls else 80), target, tls
        host, _, port = target.partition(":")           # tcp: host:port
        if not host or not port.isdigit() or not (0 < int(port) < 65536):
            raise LoadTestError("For a TCP load test, give host:port (for example 10.0.0.5:8080).")
        return host, int(port), "", False

    # -- recording --------------------------------------------------------
    def _bucket(self) -> dict:
        t = int(self.wallclock())
        with self._lock:
            b = self._buckets.get(t)
            if b is None:
                b = self._buckets[t] = {"t": t, "sent": 0, "ok": 0, "failed": 0, "bytes_in": 0, "bytes_out": 0}
                for old in [k for k in self._buckets if k < t - HISTORY]:
                    del self._buckets[old]
            return b

    def _record(self, ok: bool, bin_: int, bout: int, err: str | None, latency: float | None) -> None:
        b = self._bucket()
        with self._lock:
            b["sent"] += 1
            b["ok" if ok else "failed"] += 1
            b["bytes_in"] += bin_
            b["bytes_out"] += bout
            self.status["sent"] += 1
            self.status["ok" if ok else "failed"] += 1
            self.status["bytes_in"] += bin_
            self.status["bytes_out"] += bout
            if err:
                self.status["errors"][err] = self.status["errors"].get(err, 0) + 1
            if latency is not None:
                self._lat.append(latency)

    # -- one request ------------------------------------------------------
    def _one_http(self) -> None:
        import requests
        t0 = self.clock()
        try:
            r = requests.request(self.method, self.url, data=self.body or None, timeout=self.timeout,
                                 headers={"User-Agent": USER_AGENT}, stream=True, allow_redirects=False)
            content = r.raw.read(65536, decode_content=False) or b""
            self._record(r.status_code < 500, len(content), len(self.body),
                         None if r.status_code < 500 else f"HTTP {r.status_code}", self.clock() - t0)
            r.close()
        except Exception as exc:
            self._record(False, 0, len(self.body), type(exc).__name__, self.clock() - t0)

    def _one_tcp(self) -> None:
        t0 = self.clock()
        s = None
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.port == 443:
                s = ssl.create_default_context().wrap_socket(s, server_hostname=self.host)
            self._record(True, 0, 0, None, self.clock() - t0)
        except Exception as exc:
            self._record(False, 0, 0, type(exc).__name__, self.clock() - t0)
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    # -- the run ----------------------------------------------------------
    def run(self) -> dict:
        self.status["running"], self.status["started_at"] = True, self.wallclock()
        start = self.clock()
        one = self._one_http if self.mode == "http" else self._one_tcp
        sem = threading.Semaphore(self.concurrency)
        threads: list[threading.Thread] = []

        def fire() -> None:
            try:
                one()
            finally:
                sem.release()

        tick = 0
        while not self.stop.is_set() and self.clock() - start < self.duration:
            tick_start = self.clock()
            for _ in range(self.rps):                       # up to rps launches this second, each bounded by the semaphore
                if self.stop.is_set() or self.clock() - start >= self.duration:
                    break
                if not sem.acquire(timeout=1.0):            # at the concurrency ceiling: skip, do not pile up
                    continue
                th = threading.Thread(target=fire, daemon=True)
                th.start()
                threads.append(th)
            threads = [t for t in threads if t.is_alive()]
            self.status["elapsed"] = round(self.clock() - start, 1)
            tick += 1
            rest = tick_start + 1.0 - self.clock()
            if rest > 0:
                self.stop.wait(rest)
        for t in threads:
            t.join(timeout=self.timeout + 1)
        self.status["running"], self.status["done"] = False, True
        self.status["elapsed"] = round(self.clock() - start, 1)
        self.snapshot()
        return self.status

    def snapshot(self) -> dict:
        with self._lock:
            series = [dict(b) for b in sorted(self._buckets.values(), key=lambda b: b["t"])][-HISTORY:]
            lat = sorted(self._lat)
        self.status["series"] = series

        def pct(p: float) -> float | None:
            return round(lat[min(len(lat) - 1, int(p * len(lat)))] * 1000, 1) if lat else None
        self.status["latency_ms"] = {"p50": pct(0.5), "p90": pct(0.9), "p99": pct(0.99),
                                     "max": round(lat[-1] * 1000, 1) if lat else None}
        cur = series[-1] if series else {}
        self.status["now"] = {"rps": cur.get("sent", 0), "ok": cur.get("ok", 0), "failed": cur.get("failed", 0)}
        return self.status
