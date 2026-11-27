"""Which DNS resolver each noise lookup goes to — and proof it went there.

  system  your computer's normal resolver: whatever your router, ISP, VPN or OS-level
          encrypted DNS already uses. Noise lands where your real lookups land.
  secure  the resolver table in Settings: "primary" rows normally (by default three
          OpenNIC servers in Germany); a "fallback" row (Quad9 9.9.9.9) only when no
          primary is answering quickly. Optional extras: the whole OpenNIC directory,
          Quad9's pair, and your own IPs.
  mix     (default) alternates between the two in randomly sized blocks (10-60 min by
          default), spending `system_share` of the time on your normal DNS.

Health checks: each resolver is asked for wikipedia.org and timed, and asked for
whoami.akamai.net, whose answer is the IP of the machine that really did the
resolving. If every address — your normal DNS included — is resolved by the same
machine, something on your network is intercepting DNS, and the UI says so.
"""
from __future__ import annotations

import ipaddress
import os
import platform
import random
import re
import socket
import struct
import subprocess
import threading
import time

PROBE_NAME = "wikipedia.org"
WHOAMI_NAME = "whoami.akamai.net"
QUAD9 = [("9.9.9.9", "Quad9"), ("149.112.112.112", "Quad9")]   # docs.quad9.net/services (Secure)


def _query(name: str, qid: int) -> bytes:
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + q + struct.pack(">HH", 1, 1)


def _last_a(resp: bytes) -> str | None:
    """IPv4 of the last A record in a simple response (enough for whoami.akamai.net)."""
    try:
        if struct.unpack(">H", resp[6:8])[0] == 0:
            return None
        i = 12
        while resp[i]:
            i += resp[i] + 1
        i += 5
        ip = None
        for _ in range(struct.unpack(">H", resp[6:8])[0]):
            i += 2 if resp[i] & 0xC0 == 0xC0 else 0
            if resp[i - 2] & 0xC0 != 0xC0:
                while resp[i]:
                    i += resp[i] + 1
                i += 1
            rtype, _, _, rdlen = struct.unpack(">HHIH", resp[i:i + 10])
            i += 10
            if rtype == 1 and rdlen == 4:
                ip = socket.inet_ntoa(resp[i:i + 4])
            i += rdlen
        return ip
    except (IndexError, struct.error, OSError):
        return None


CROSS_NAMES = ["wikipedia.org", "example.com", "www.iana.org"]     # stable, widely served names
HIJACK_NAME = "invalid"                                             # RFC 6761: must always be "does not exist"


def _skip_name(b: bytes, i: int) -> int:
    while True:
        n = b[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1


def answers_a(resp: bytes) -> list[str]:
    """Every IPv4 address in the answer section of a DNS response."""
    try:
        qd, an = struct.unpack(">HH", resp[4:8])
        i = 12
        for _ in range(qd):
            i = _skip_name(resp, i) + 4
        out = []
        for _ in range(an):
            i = _skip_name(resp, i)
            rtype, _, _, rdlen = struct.unpack(">HHIH", resp[i:i + 10])
            i += 10
            if rtype == 1 and rdlen == 4:
                out.append(socket.inet_ntoa(resp[i:i + 4]))
            i += rdlen
        return out
    except (IndexError, struct.error, OSError):
        return []


def _ask(ip: str, name: str, timeout: float = 2.0, port: int = 53) -> bytes | None:
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    qid = random.randint(0, 0xFFFF)
    try:
        s.sendto(_query(name, qid), (ip, port))
        while True:
            data, addr = s.recvfrom(1500)
            if addr[0] == ip and len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                return data
    except OSError:
        return None
    finally:
        s.close()


def canary(ip: str) -> str | None:
    """A made-up name under .invalid must not exist. A server that answers with an address is
    hijacking missing names (to an ad or phishing page). ok | hijack | None (no usable answer)."""
    data = _ask(ip, f"{random.getrandbits(48):x}.{HIJACK_NAME}")
    if data is None:
        return None
    if data[3] & 0x0F == 3:
        return "ok"
    return "hijack" if answers_a(data) else None


def prefixes(ip: str, name: str) -> set[str] | None:
    """The /16 networks a server says `name` lives in (a /16 tolerates normal CDN variety)."""
    data = _ask(ip, name)
    if data is None or data[3] & 0x0F != 0:
        return None
    return {".".join(a.split(".")[:2]) for a in answers_a(data)} or None


def consensus(results: dict[str, dict[str, set[str] | None]]) -> dict[str, str]:
    """Compare what each server said for the same names. A server agrees with another when their
    answers share a network. Per name, servers form agreement groups:
      * one biggest group  -> the others are outliers;
      * a tie for biggest  -> nobody can be told apart (exactly the "half are bad" case): disputed.
    A server is flagged only if it is an outlier / disputed on at least two names."""
    names = {n for r in results.values() for n in r}
    flags: dict[str, dict[str, int]] = {ip: {"outlier": 0, "disputed": 0} for ip in results}
    for n in names:
        have = {ip: r[n] for ip, r in results.items() if r.get(n)}
        if len(have) < 3:
            continue
        groups: list[set[str]] = []
        for ip, pre in have.items():
            hit = [g for g in groups if any(pre & have[m] for m in g)]
            merged = {ip}.union(*hit) if hit else {ip}
            groups = [g for g in groups if g not in hit] + [merged]
        biggest = max(len(g) for g in groups)
        if len(groups) == 1:
            continue
        top = [g for g in groups if len(g) == biggest]
        for g in groups:
            for ip in g:
                if len(top) > 1:
                    flags[ip]["disputed"] += 1
                elif g is not top[0]:
                    flags[ip]["outlier"] += 1
    out = {}
    for ip, f in flags.items():
        out[ip] = "outlier" if f["outlier"] >= 2 else "disputed" if f["disputed"] >= 2 else "ok"
    return out


def probe(ip: str, timeout: float = 2.0) -> dict:
    """Ask one resolver directly. Returns ok, rtt_ms, egress (who really resolved), error."""
    out = {"ip": ip, "ok": False, "rtt_ms": None, "egress": None, "error": None, "checked": time.time()}
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    for name, key in ((PROBE_NAME, "rtt"), (WHOAMI_NAME, "egress")):
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        qid = random.randint(0, 0xFFFF)
        try:
            t0 = time.monotonic()
            s.sendto(_query(name, qid), (ip, 53))
            while True:
                data, addr = s.recvfrom(1500)
                if addr[0] == ip and len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                    break                                  # ignore stray/forged packets
            if key == "rtt":
                if data[3] & 0x0F != 0:
                    out["error"] = f"answered with error code {data[3] & 0x0F}"
                    return out
                out["rtt_ms"] = round((time.monotonic() - t0) * 1000)
                out["ok"] = True
            else:
                out["egress"] = _last_a(data)
        except OSError as exc:
            if key == "rtt":
                out["error"] = "no answer" if isinstance(exc, socket.timeout) else str(exc)
                return out
        finally:
            s.close()
    return out


def system_resolvers() -> list[str]:
    """The resolver IPs this computer is configured to use (best effort, per OS)."""
    ips: list[str] = []
    try:
        if platform.system() == "Windows":
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "Get-DnsClientServerAddress -AddressFamily IPv4 | "
                                  "Select-Object -ExpandProperty ServerAddresses"],
                                 capture_output=True, text=True, timeout=8,
                                 creationflags=0x08000000).stdout
            ips = out.split()
        else:
            for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
                if os.path.exists(path):
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        ips = re.findall(r"^\s*nameserver\s+(\S+)", fh.read(), re.M)
                    if ips and not all(x.startswith("127.") for x in ips):
                        break
    except Exception:
        pass
    seen = []
    for x in ips:
        try:
            ipaddress.ip_address(x)
            if x not in seen:
                seen.append(x)
        except ValueError:
            pass
    return seen


KNOWN = {"1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "8.8.8.8": "Google", "8.8.4.4": "Google",
         "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
         "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard"}


def describe_ip(ip: str) -> str:
    """Plain-English hint for an IP shown in the UI."""
    if ip in KNOWN:
        return KNOWN[ip]
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if a.is_loopback:
        return "a resolver running on this computer, which forwards to the next one"
    if a.is_private:
        return "your router or local network, which forwards to your ISP or VPN"
    return ""


class DnsPlan:
    def __init__(self, rng: random.Random, cfg, opennic: list[str] | None = None, clock=time.time):
        self.rng, self.cfg, self.clock = rng, cfg, clock
        self.directory = [x.split("|") for x in (opennic or [])]   # OpenNIC suggestions for the UI
        self.opennic = [(p[0], f"OpenNIC {p[1] if len(p) > 1 else ''}".strip()) for p in self.directory]
        # no-logs servers count 3x, anonymized-logs 1x (only matters when the whole directory is on)
        self._opennic_w = {p[0]: (3.0 if len(p) > 3 and p[3] == "none" else 1.0) for p in self.directory}
        self.health: dict[str, dict] = {}
        self.system: list[str] = []
        self.system_egress: str | None = None
        self.checking = False
        self._block_until = 0.0
        self._block_mode = "system"
        self.strikes: dict[str, int] = {}               # consecutive checks a server disagreed with the others
        self.disputed: set[str] = set()
        self._recent: list[str] = []                    # last lookups' servers, to cap any one server's share
        self._lock = threading.Lock()

    # ── which servers ─────────────────────────────────────────────────────
    def configured(self, role: str | None = None) -> list[dict]:
        """The resolver table, plus the optional extras (whole OpenNIC directory, Quad9, custom IPs)."""
        rows = [r for r in getattr(self.cfg, "resolvers", []) if r.get("enabled", True)]
        have = {r["ip"] for r in rows}
        extra = []
        if getattr(self.cfg, "opennic", False):
            extra += [{"ip": ip, "name": n, "role": "primary", "weight": self._opennic_w.get(ip, 1.0)}
                      for ip, n in self.opennic]
        if getattr(self.cfg, "quad9", False):
            extra += [{"ip": ip, "name": n, "role": "primary"} for ip, n in QUAD9]
        extra += [{"ip": ip.strip(), "name": "your server", "role": "primary"}
                  for ip in getattr(self.cfg, "custom", []) if ip.strip()]
        rows += [r for r in extra if r["ip"] not in have]
        return [r for r in rows if role is None or r["role"] == role]

    def secure_servers(self) -> list[tuple[str, str]]:
        return [(r["ip"], r["name"]) for r in self.configured()]

    def _usable(self, servers: list[dict], fast_only: bool) -> list[dict]:
        out = []
        for r in servers:
            if self.verdict(r["ip"]) in ("hijack", "disagrees"):
                continue                        # caught lying: out of rotation until it behaves
            h = self.health.get(r["ip"])
            if h is None:                       # not checked yet: usable until a check says otherwise
                if not fast_only or not self.health:
                    out.append(r)
                continue
            if h["ok"] and (not fast_only or (h["rtt_ms"] or 0) <= self.cfg.slow_ms):
                out.append(r)
        return out

    def secure_choice(self) -> dict | None:
        """Fast primaries; else fallbacks; else slow-but-answering primaries."""
        prim, fb = self.configured("primary"), self.configured("fallback")
        for pool in (self._usable(prim, True), self._usable(fb, False), self._usable(prim, False)):
            if pool:
                pool = self._cap_share(pool)
                w = [r.get("weight", 1.0) * (0.3 if r["ip"] in self.disputed else 1.0) for r in pool]
                pick = self.rng.choices(pool, weights=w)[0]
                self._recent = (self._recent + [pick["ip"]])[-40:]
                return pick
        return None

    def _cap_share(self, pool: list[dict]) -> list[dict]:
        """No single server answers more than about half of the lookups (when there are others to use),
        so a compromised server never sees more than a thin slice of what you look up."""
        if len(pool) < 3 or len(self._recent) < 10:
            return pool
        keep = [r for r in pool if self._recent.count(r["ip"]) / len(self._recent) <= 0.50]
        return keep or pool

    def current_mode(self) -> str:
        mode = self.cfg.mode
        if mode != "mix":
            return mode
        now = self.clock()
        if now >= self._block_until:
            lo, hi = (list(self.cfg.block_minutes) + [10, 60])[:2]
            self._block_until = now + self.rng.uniform(lo, max(lo, hi)) * 60
            self._block_mode = "system" if self.rng.random() < self.cfg.system_share else "secure"
        return self._block_mode

    def pick(self) -> tuple[str, str]:
        """(server, label). server == "system" means use the OS resolver."""
        if self.current_mode() == "secure":
            r = self.secure_choice()
            if r:
                role = " (fallback)" if r["role"] == "fallback" else ""
                return r["ip"], f"{r['name']}{role} {r['ip']}"
        return "system", "your normal DNS"

    def mark_failed(self, ip: str) -> None:
        h = self.health.setdefault(ip, {"ip": ip, "ok": False, "rtt_ms": None, "egress": None})
        h.update(ok=False, error="stopped answering", checked=time.time())

    # ── health / verification ─────────────────────────────────────────────
    def check(self) -> None:
        """Probe every configured resolver plus your normal DNS. Blocking; run in a thread."""
        with self._lock:
            self.checking = True
            try:
                self.system = system_resolvers()
                sysr = next((x for x in self.system if not x.startswith("127.")), None)
                self.system_egress = probe(sysr)["egress"] if sysr else None
                for r in self.configured():
                    self.health[r["ip"]] = probe(r["ip"])
                self._integrity_checks()
            finally:
                self.checking = False

    def _integrity_checks(self) -> None:
        """Are the servers honest? Missing names must not resolve, and servers must agree with each
        other about the same names. Uses only servers that already answered."""
        live = [r["ip"] for r in self.configured() if self.health.get(r["ip"], {}).get("ok")]
        for ip in live:
            self.health[ip]["canary"] = canary(ip)
        results = {ip: {n: prefixes(ip, n) for n in CROSS_NAMES} for ip in live}
        flags = consensus(results)
        self.disputed = {ip for ip, f in flags.items() if f == "disputed"}
        for ip, f in flags.items():
            self.strikes[ip] = self.strikes.get(ip, 0) + 1 if f == "outlier" else 0

    def check_async(self) -> None:
        if not self.checking:
            threading.Thread(target=self.check, daemon=True, name="dns-check").start()

    def verdict(self, ip: str) -> str:
        """ok | slow | down | intercepted | hijack | disagrees | disputed | unknown — for the UI."""
        h = self.health.get(ip)
        if not h:
            return "unknown"
        if not h["ok"]:
            return "down"
        if h.get("canary") == "hijack":
            return "hijack"
        if self.strikes.get(ip, 0) >= 2:
            return "disagrees"
        if ip in self.disputed:
            return "disputed"
        eg = h.get("egress")
        others = [x.get("egress") for k, x in self.health.items() if k != ip and x.get("egress")]
        if eg and ((self.system_egress and eg == self.system_egress) or (others and all(o == eg for o in others))):
            return "intercepted"
        return "slow" if (h["rtt_ms"] or 0) > self.cfg.slow_ms else "ok"

    def report(self) -> dict:
        rows = []
        for r in getattr(self.cfg, "resolvers", []):
            h = self.health.get(r["ip"], {})
            rows.append({**r, "rtt_ms": h.get("rtt_ms"), "egress": h.get("egress"), "error": h.get("error"),
                         "verdict": self.verdict(r["ip"])})
        return {"resolvers": rows, "system": [{"ip": x, "what": describe_ip(x)} for x in self.system],
                "system_egress": self.system_egress, "checking": self.checking,
                "intercepted": bool(rows) and all(x["verdict"] == "intercepted" for x in rows if x["enabled"]),
                "directory": self.directory}
