"""Spray and Pray: an extra layer of fast DNS lookups for a lot of different domains.

Everything else stays the same. This only adds one more stream: bursts of DNS queries (names only, no page is ever loaded) for
hundreds to thousands of different domains a minute, so the list of names your computer looks up is buried in far more of them.
It leans hard on common sites (most queries are for the popular ones) with a long tail of random ones, from big public lists
(OpenDNS's top and random lists, a top-million list) that pass the same safety filter as the rest of the app (no adult,
gambling or hostile names).

How it sends: to the resolvers the DNS settings say (encrypted over TLS by default, a few queries sent back to back on one
connection; otherwise plain UDP to them or, in "your normal DNS" mode, to this computer's own resolver). It watches how many
answers come back and slows down when the resolver starts ignoring it (some resolvers rate-limit), and speeds up again when they
answer. It is off until you switch it on, runs only while the noise runs, and a pause you press pauses it too.
"""
from __future__ import annotations

import random
import socket
import time

LEVELS = {"low": 25.0, "medium": 120.0, "high": 400.0}        # queries a second on average, over a minute or so
COMMON_SHARE = 0.65                                           # most queries are for popular sites
TICK = (0.4, 1.2)                                             # seconds between bursts
FALLBACK = ["google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com", "reddit.com", "twitter.com",
            "instagram.com", "linkedin.com", "netflix.com", "microsoft.com", "apple.com", "github.com", "yahoo.com"]


class Spray:
    def __init__(self, feeds, cfg_fn, active_fn, resolvers_fn, log=None, rng=None, clock=time.time, sleep=time.sleep,
                 send_fn=None):
        self.feeds, self.cfg_fn, self.active_fn, self.resolvers_fn = feeds, cfg_fn, active_fn, resolvers_fn
        self.log, self.rng, self.clock, self.sleep = log, rng or random.Random(), clock, sleep
        self.send_fn = send_fn or self._send
        self.sent = self.answered = 0
        self.factor = 1.0                     # slowed when the resolver stops answering
        self.started = None
        self._common: list[str] = []
        self._tail: list[str] = []
        self._tls = {}                        # resolver -> an open TLS connection

    # -- domains -----------------------------------------------------------
    def load(self) -> None:
        items = self.feeds.items("spray") if self.feeds is not None else []
        self._common = [i[2:] for i in items if i.startswith("c|")]
        self._tail = [i[2:] for i in items if i.startswith("t|")]
        if not self._common and self.feeds is not None:
            self._common = list(self.feeds.items("tranco")) or []
        if not self._common:
            self._common = list(FALLBACK)

    def pick(self) -> str:
        pool = self._common if (not self._tail or self.rng.random() < COMMON_SHARE) else self._tail
        # popular names first within each pool: a power-law pick, not a flat one
        i = min(len(pool) - 1, int(len(pool) * self.rng.random() ** 2.2))
        return pool[i]

    # -- one burst ---------------------------------------------------------
    def burst_size(self, rate: float, dt: float) -> int:
        n = rate * self.factor * dt * self.rng.lognormvariate(0.0, 0.5)    # bursty, never a steady drip
        return max(1, int(round(n)))

    def tick(self) -> int:
        """One burst, if on. Returns how many queries were sent."""
        cfg = self.cfg_fn()
        if not cfg.get("on") or not self.active_fn():
            return 0
        if not self._common:
            self.load()
        from .engines import build_dns_query
        dt = self.rng.uniform(*TICK)
        n = self.burst_size(LEVELS.get(cfg.get("level"), LEVELS["medium"]), dt)
        names = [self.pick() for _ in range(n)]
        packets = [build_dns_query(d, self.rng.randrange(0, 0x10000)) for d in names]
        if self.started is None:
            self.started = self.clock()
        got = self.send_fn(packets)
        self.sent += len(packets)
        self.answered += got
        self._adapt(len(packets), got)
        self.sleep(dt)
        return len(packets)

    def _adapt(self, sent: int, got: int) -> None:
        if sent < 3:
            return
        ratio = got / sent
        if ratio < 0.3 and self.factor > 0.05:
            self.factor = max(0.05, self.factor * 0.6)
            self._say(f"Spray and Pray: the resolver is answering few of the queries; slowing to {self.factor:.0%}.")
        elif ratio > 0.8 and self.factor < 1.0:
            self.factor = min(1.0, self.factor * 1.25)

    def _say(self, text: str) -> None:
        if self.log is not None:
            try:
                self.log.info("dns", text)
            except Exception:
                pass

    # -- sending -----------------------------------------------------------
    def _send(self, packets: list[bytes]) -> int:
        servers = self.resolvers_fn() or []
        if not servers:
            return 0
        server = self.rng.choice(servers)
        from .engines import DNS_OPTIONS, DOT_HOSTS
        if DNS_OPTIONS["encrypted"] and server in DOT_HOSTS:
            return self._send_tls(server, packets)
        return self._send_udp(server, packets)

    @staticmethod
    def _send_udp(server: str, packets: list[bytes], wait: float = 0.6) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        got = 0
        try:
            s.setblocking(False)
            for p in packets:
                try:
                    s.sendto(p, (server, 53))
                except OSError:
                    break
            end = time.time() + wait
            while time.time() < end and got < len(packets):
                try:
                    s.settimeout(max(0.01, end - time.time()))
                    data, _ = s.recvfrom(1024)
                    got += 1 if len(data) >= 12 else 0
                except OSError:
                    break
        finally:
            s.close()
        return got

    def _send_tls(self, server: str, packets: list[bytes], wait: float = 1.5) -> int:
        """DNS over TLS: the queries go back to back on one open connection (RFC 7858 allows it) and the answers are counted."""
        import ssl

        from .engines import DOT_HOSTS
        conn = self._tls.get(server)
        try:
            if conn is None:
                raw = socket.create_connection((server, 853), timeout=3.0)
                conn = ssl.create_default_context().wrap_socket(raw, server_hostname=DOT_HOSTS[server])
                self._tls[server] = conn
            conn.settimeout(wait)
            conn.sendall(b"".join(len(p).to_bytes(2, "big") + p for p in packets))
            got, buf, end = 0, b"", time.time() + wait
            while got < len(packets) and time.time() < end:
                chunk = conn.recv(65536)
                if not chunk:
                    raise OSError("closed")
                buf += chunk
                while len(buf) >= 2 and len(buf) >= 2 + int.from_bytes(buf[:2], "big"):
                    n = int.from_bytes(buf[:2], "big")
                    got += 1 if n >= 12 else 0
                    buf = buf[2 + n:]
            return got
        except (OSError, ssl.SSLError):
            self._tls.pop(server, None)
            try:
                if conn is not None:
                    conn.close()
            except OSError:
                pass
            return 0

    # -- the loop and what it reports -------------------------------------
    def loop(self, stopped) -> None:
        while not stopped():
            try:
                if not self.tick():
                    self.sleep(1.0)
            except Exception as exc:                     # this layer must never take the app down
                self._say(f"Spray and Pray: {exc!r}")
                self.sleep(5.0)

    def state(self) -> dict:
        cfg = self.cfg_fn()
        secs = max(1.0, (self.clock() - self.started)) if self.started else 0.0
        return {"on": bool(cfg.get("on")), "level": cfg.get("level"), "sent": self.sent, "answered": self.answered,
                "per_second": round(self.sent / secs, 1) if secs else 0.0, "domains": len(self._common) + len(self._tail),
                "slowed": round(self.factor, 2)}
