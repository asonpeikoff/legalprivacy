"""Transports: neutral targets dispatched over clearnet or Tor.

Engines emit Target objects; transports own connection handling, IP
diversity, and failure semantics. Tor and clearnet do NOT share code paths
beyond this interface — isolation semantics differ too much.
"""

from __future__ import annotations

import binascii
import os
import socket
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

try:
    import requests
except ImportError as exc:  # pragma: no cover
    raise ImportError("legalPrivacy v2 needs the 'requests' package (pip install requests)") from exc

from .identity import Identity
from .paths import getenv


@dataclass
class Target:
    url: str
    kind: str = "html"            # html | doh | dns | pkg
    timeout: float = 25.0
    referer: str | None = None    # set on click-through / link-follow hits
    note: str | None = None       # e.g. query origin ("trends", "dataset"…), shown in the log
    role: str = "page"            # search | result | page
    dwell: float | None = None    # seconds a person would spend on this page (sessions)

    @property
    def host(self) -> str:
        return urllib.parse.urlparse(self.url).netloc


class HitResult:
    def __init__(self, status: int | None, html: str = "", error: str | None = None):
        self.status = status
        self.html = html
        self.error = error
        self.latency_ms: float | None = None
        self.detail: str | None = None       # e.g. "click, 4 scrolls, 38% depth" from the browser
        self.bytes: int = 0                  # approximate data moved (0 = use len(html))

    @property
    def ok(self) -> bool:
        return self.status is not None and self.status < 400

    @property
    def dim_transport(self) -> bool:
        """429 or network error dims the lane (proxy dead / circuit burned)."""
        return self.status in (403, 429) or self.error is not None


class Transport:
    """Common interface: scheduler dispatches Targets; transports answer hits."""

    dimmed: bool = False

    def hit(self, identity, target: Target) -> HitResult:
        raise NotImplementedError


def test_proxy(proxy_url: str, test_url: str = "http://1.1.1.1", timeout: float = 2.5) -> float | None:
    """Test a proxy for connectivity and latency in milliseconds; returns None if bad/slow."""
    try:
        t0 = time.time()
        proxies = {"http": proxy_url, "https": proxy_url}
        resp = requests.head(test_url, proxies=proxies, timeout=timeout, allow_redirects=False)
        latency = (time.time() - t0) * 1000.0
        return latency if resp.status_code < 500 else None
    except Exception:
        return None


class ClearnetTransport(Transport):
    """Direct or proxied clearnet. Proxies are strictly optional and tested for health."""

    def __init__(self, proxy: str | None = None, proxy_pool: list[str] | None = None,
                 test_proxies: bool = False, max_latency: float = 3.0):
        self.proxy = proxy
        self.proxy_pool = list(proxy_pool) if proxy_pool else ([proxy] if proxy else [])
        self.max_latency = max_latency
        self.dimmed = False
        if test_proxies and self.proxy_pool:
            self.filter_healthy_proxies()

    def filter_healthy_proxies(self) -> list[str]:
        """Test and retain only fast, responsive proxies; discard slow or dead ones."""
        healthy = []
        for p in self.proxy_pool:
            lat = test_proxy(p, timeout=self.max_latency)
            if lat is not None:
                healthy.append(p)
        self.proxy_pool = healthy
        self.proxy = healthy[0] if healthy else None
        return healthy

    def hit(self, identity: Identity, target: Target) -> HitResult:
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        headers = _identity_headers(identity)
        if target.referer:
            headers["Referer"] = target.referer
        try:
            resp = requests.get(
                target.url,
                timeout=target.timeout,
                allow_redirects=True,
                proxies=proxies,
                # Identity headers injected here; requests also sets Host/Content-Length.
                headers=headers,
            )
            status = resp.status_code
            if status == 202 and "duckduckgo.com" in target.url:
                status = 429                       # DuckDuckGo's bot check: back off, don't count a visit
            return HitResult(status, resp.text[:2_000_000])
        except requests.RequestException as exc:
            return HitResult(None, error=str(exc))


class TorTransport(Transport):
    """Tor via a local SOCKS daemon.

    Circuit isolation: each identity gets a distinct SOCKS5 user:pass
    (user 'ident-<id>'), which the tor daemon maps to a distinct circuit.
    Local DNS resolution never happens — hostnames go to the circuit.
    """

    def __init__(self, socks: str = "127.0.0.1:9050", control: str | None = None,
                 identities_per_circuit: int = 8, control_password: str | None = None):
        host, _, port = socks.partition(":")
        self.socks_host = host or "127.0.0.1"
        self.socks_port = int(port) if port else 9050
        self.control = control
        self.identities_per_circuit = identities_per_circuit
        self.control_password = control_password or getenv("TOR_CONTROL_PW")
        self.circuit_seed = binascii.hexlify(os.urandom(8)).decode()
        self.cookie_path: str | None = None    # set when a managed Tor owns the control port
        self.dimmed = False

    def set_endpoint(self, socks: str, control: str | None, cookie_path: str | None = None) -> None:
        """Re-point at a (managed) Tor whose ports were chosen at launch time."""
        host, _, port = socks.partition(":")
        self.socks_host, self.socks_port = host or "127.0.0.1", int(port) if port else 9050
        self.control, self.cookie_path = control, cookie_path

    def _socks_proxies(self, identity: Identity) -> dict[str, str]:
        user = f"ident-{identity.id}-{self.circuit_seed}"
        uri = f"socks5h://{user}:{user}@{self.socks_host}:{self.socks_port}"
        return {"http": uri, "https": uri}

    def hit(self, identity: Identity, target: Target) -> HitResult:
        onion = is_onion_host(target.url)
        headers = dict(TOR_BROWSER_HEADERS) if onion else _identity_headers(identity)
        try:
            resp = requests.get(
                target.url,
                timeout=max(target.timeout, 60.0) if onion else target.timeout,
                allow_redirects=True,
                proxies=self._socks_proxies(identity),
                headers=headers,
            )
            return HitResult(resp.status_code, resp.text[:2_000_000])
        except requests.RequestException as exc:
            return HitResult(None, error=explain_tor_error(str(exc), f"{self.socks_host}:{self.socks_port}"))

    def renew_circuits(self) -> bool:
        """NEWNYM via the Tor control port, if configured. Best-effort."""
        if not self.control:
            return False
        from .torcontrol import TorControl, TorControlError, split_hostport
        host, port = split_hostport(self.control, 9051)
        try:
            with TorControl(host, port, self.control_password, self.cookie_path, timeout=5) as c:
                c.newnym()
            return True
        except (TorControlError, OSError):
            return False

    def check_status(self) -> dict[str, Any]:
        """Inspect Tor daemon reachability and bootstrap state."""
        from .torcontrol import TorControl, TorControlError, split_hostport
        res: dict[str, Any] = {
            "socks_host": self.socks_host, "socks_port": self.socks_port,
            "socks_ok": False, "control_ok": False,
            "bootstrap": None, "version": None, "error": None,
        }
        try:
            with socket.create_connection((self.socks_host, self.socks_port), timeout=2):
                res["socks_ok"] = True
        except OSError as exc:
            res["error"] = f"SOCKS port unreachable: {exc}"
        if self.control:
            host, port = split_hostport(self.control, 9051)
            try:
                with TorControl(host, port, self.control_password, self.cookie_path, timeout=2) as c:
                    res["control_ok"] = True
                    res["version"] = c.getinfo("version")
                    res["bootstrap"] = c.getinfo("status/bootstrap-phase")
            except (TorControlError, OSError):
                pass
        return res

    def reconnect(self) -> bool:
        """Reset circuit seed and request fresh circuits via NEWNYM."""
        self.circuit_seed = binascii.hexlify(os.urandom(8)).decode()
        self.dimmed = False
        return self.renew_circuits()


# Tor Browser (Firefox ESR based) presents one uniform fingerprint to everyone so users blend
# into a single large anonymity set. Onion traffic that wears a random Chrome UA would stand
# out, so the onion lane mimics Tor Browser's uniform headers instead of per-identity ones.
from .useragents import latest_firefox_esr  # noqa: E402

TOR_BROWSER_HEADERS = {
    "User-Agent": f"Mozilla/5.0 (Windows NT 10.0; rv:{latest_firefox_esr()}.0) "
                  f"Gecko/20100101 Firefox/{latest_firefox_esr()}.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
}


_TOR_ERRORS = [   # SOCKS5 reply codes from Tor, in plain English
    ("0xf0", "onion address not found — the site is offline or has moved"),
    ("0xf1", "onion address is invalid"), ("0xf2", "onion site didn't respond (introduction failed)"),
    ("0xf3", "onion site didn't respond (rendezvous failed)"), ("0xf4", "onion site requires client authorization"),
    ("0xf5", "onion address is malformed"), ("0xf6", "onion connection timed out — onion sites are often slow"),
    ("0x01", "Tor couldn't reach the site (it may be offline)"), ("0x02", "Tor's rules refused this connection"),
    ("0x03", "the network is unreachable through Tor"), ("0x04", "the site is unreachable through Tor"),
    ("0x05", "the site refused the connection"), ("0x06", "timed out inside Tor"),
]


def explain_tor_error(msg: str, socks: str) -> str:
    low = msg.lower()
    for code, text in _TOR_ERRORS:
        if code in low:
            return text
    if "connection refused" in low or "error connecting to socks" in low:
        return f"Tor isn't accepting connections on {socks} (is it still starting?)"
    if "timed out" in low:
        return "timed out — onion sites are often slow; will try again later"
    return msg.splitlines()[0][:160]


def is_onion_host(url: str) -> bool:
    try:
        return (urllib.parse.urlparse(url).hostname or "").endswith(".onion")
    except ValueError:
        return False


def _identity_headers(identity: Identity) -> dict[str, str]:
    from .identity import headers_for
    return headers_for(identity)
