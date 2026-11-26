"""legalPrivacy remote runner: ONE self-contained file, Python standard library only.

legalPrivacy copies this file (and a small JSON settings file) over SSH into a private folder on a machine you own,
runs it there, reads its log back, and deletes it when you remove the machine. It makes ordinary noise from THAT
machine: page visits, searches, DNS lookups and downloads, each with its own identity, rhythm and budgets.

  python3 agent.py run <settings.json>    run until stopped (stdin closing, "stop", SIGTERM, or `agent.py stop`)
  python3 agent.py stop <folder>          stop the runner whose pid file is in <folder>
  python3 agent.py probe                  print what this machine offers, as one JSON line

Rules it keeps:
  * No root, no display, no service, no cron: it is a plain process in your account. When the SSH connection that
    started it ends it stops too (it watches its standard input), so nothing is ever left running by accident.
  * Writes nothing but its pid file (and, with a headless browser, a throw-away profile it deletes straight away).
    Downloads are read and thrown away; they never touch the disk.
  * Never connects to a private, loopback or link-local address (also after a redirect): the noise only goes to the
    public internet, never to the machine's own network.
  * Every setting has a hard ceiling here, whatever the settings file says.
  * Output is JSON lines on stdout: {"t": unix time, "lvl": ..., "kind": ..., "msg": ...}. It holds no secrets.

Python 3.7 or newer. The same file runs on Linux, macOS and Windows.
"""
from __future__ import annotations

import ipaddress
import json
import os
import random
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from html.parser import HTMLParser

VERSION = 1
PID_FILE = "agent.pid"

# hard ceilings (the settings file can lower these, never raise them)
MAX_ACTIONS_PER_HOUR = 600
MAX_MB_PER_DAY = 2000
MAX_DOWNLOAD_MB = 50
MAX_PAGE_BYTES = 600_000
MIN_GAP_SECONDS = 1.0

BROWSER_NAMES = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome", "msedge",
                 "microsoft-edge", "firefox")

FALLBACK_DOMAINS = ["wikipedia.org", "mozilla.org", "python.org", "github.com", "stackoverflow.com", "bbc.com",
                    "nytimes.com", "theguardian.com", "reuters.com", "apnews.com", "npr.org", "weather.com",
                    "archive.org", "khanacademy.org", "coursera.org", "allrecipes.com", "mayoclinic.org",
                    "wikihow.com", "arstechnica.com", "wired.com"]
FALLBACK_QUERIES = ["python tutorial", "sourdough bread recipe", "weather this week", "linux commands cheat sheet",
                    "national park passes", "how to change a tire", "best hiking boots", "learn spanish online",
                    "indoor plants low light", "5k training plan", "home network setup", "open source maps"]
FALLBACK_UAS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
]
SEARCH_ENGINES = [("https://duckduckgo.com/html/?q=", 5.0), ("https://www.bing.com/search?q=", 3.0),
                  ("https://www.google.com/search?q=", 4.0), ("https://search.brave.com/search?q=", 1.5),
                  ("https://www.mojeek.com/search?q=", 1.0)]
LANGS = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.8", "en-CA,en;q=0.9,fr;q=0.5"]
ASSET_HOSTS = ["fonts.googleapis.com", "fonts.gstatic.com", "www.googletagmanager.com", "ajax.googleapis.com",
               "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "code.jquery.com", "www.gstatic.com", "unpkg.com"]
DOWNLOAD_EXT = (".pdf", ".zip", ".tar.gz", ".tgz", ".epub", ".csv", ".txt", ".xlsx", ".docx", ".mp3")


# ── output ──────────────────────────────────────────────────────────────────
_out_lock = threading.Lock()


def emit(kind: str, msg: str, lvl: str = "info", **extra) -> None:
    rec = {"t": round(time.time(), 1), "lvl": lvl, "kind": kind, "msg": str(msg)[:400]}
    rec.update(extra)
    with _out_lock:
        try:
            sys.stdout.write(json.dumps(rec, separators=(",", ":")) + "\n")
            sys.stdout.flush()
        except (OSError, ValueError):
            pass


# ── safety: public addresses only ───────────────────────────────────────────
def is_public_address(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_global and not (a.is_multicast or a.is_reserved or a.is_loopback or a.is_link_local
                                or a.is_private or a.is_unspecified)


def host_is_safe(host: str) -> bool:
    """True when every address the name resolves to is a public one."""
    host = (host or "").strip("[]").lower()
    if not host or host == "localhost" or host.endswith((".local", ".internal", ".localhost", ".lan", ".home")):
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    ips = {i[4][0] for i in infos}
    return bool(ips) and all(is_public_address(ip) for ip in ips)


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlparse(newurl)
        if u.scheme not in ("http", "https") or not host_is_safe(u.hostname or ""):
            raise urllib.error.URLError("redirect to a non-public address refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# ── pages ───────────────────────────────────────────────────────────────────
class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.assets: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "img") and a.get("src"):
            self.assets.append(a["src"])
        elif tag == "link" and a.get("href") and (a.get("rel") or "").lower() in ("stylesheet", "icon", "preload"):
            self.assets.append(a["href"])


def parse_page(html: str, base: str) -> tuple[list[str], list[str]]:
    p = _Links()
    try:
        p.feed(html[:MAX_PAGE_BYTES])
    except Exception:
        pass

    def fix(refs):
        out = []
        for r in refs:
            try:
                u = urllib.parse.urljoin(base, r.strip())
            except ValueError:
                continue
            if u.startswith(("http://", "https://")) and u not in out:
                out.append(u)
        return out
    return fix(p.links), fix(p.assets)


def unwrap_result_link(href: str) -> str:
    """A search result's real address (engines wrap it as /url?q=... or ?uddg=...)."""
    q = urllib.parse.parse_qs(urllib.parse.urlparse(href).query)
    for k in ("uddg", "q", "url"):
        if q.get(k) and q[k][0].startswith("http"):
            return q[k][0]
    return href


# ── what actually touches the network (replaced by a simulator in a dry run) ──
class Net:
    def __init__(self, user_agent_fn):
        self._ua = user_agent_fn
        self._ctx = ssl.create_default_context()
        self._opener = urllib.request.build_opener(_SafeRedirect, urllib.request.HTTPSHandler(context=self._ctx))
        self.bytes_total = 0

    def resolve(self, host: str) -> bool:
        try:
            return bool(socket.getaddrinfo(host, 443, 0, socket.SOCK_STREAM))
        except OSError:
            return False

    def fetch(self, url: str, ident: dict, referer: str | None = None, limit: int = MAX_PAGE_BYTES,
              timeout: float = 20.0) -> tuple[int, str, int]:
        """(status, text, bytes read). Only public addresses; the body is truncated at `limit`."""
        host = urllib.parse.urlparse(url).hostname or ""
        if not host_is_safe(host):
            raise urllib.error.URLError("not a public address")
        req = urllib.request.Request(url, headers=headers_for(ident, referer))
        try:
            resp = self._opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            return e.code, "", 0
        with resp:
            body = resp.read(limit)
            n = len(body)
            ctype = resp.headers.get("Content-Type", "")
            self.bytes_total += n
            text = body.decode("utf-8", "replace") if "text" in ctype or "html" in ctype or not ctype else ""
            return resp.status, text, n

    def download(self, url: str, ident: dict, cap: int, timeout: float = 30.0) -> tuple[int, int, bool]:
        """(status, bytes read, finished). Reads up to `cap` bytes and throws them away."""
        host = urllib.parse.urlparse(url).hostname or ""
        if not host_is_safe(host):
            raise urllib.error.URLError("not a public address")
        req = urllib.request.Request(url, headers=headers_for(ident, None))
        try:
            resp = self._opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            return e.code, 0, True
        n, finished = 0, True
        with resp:
            declared = resp.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > cap * 4:
                return resp.status, 0, False          # far too big: do not even start
            while n < cap:
                chunk = resp.read(min(65536, cap - n))
                if not chunk:
                    break
                n += len(chunk)
            else:
                finished = False
        self.bytes_total += n
        return resp.status, n, finished


class DryNet:
    """Pretends: no network at all. For checking a machine and for tests."""
    def __init__(self, rng: random.Random):
        self.rng, self.bytes_total = rng, 0

    def resolve(self, host: str) -> bool:
        return True

    def fetch(self, url, ident, referer=None, limit=MAX_PAGE_BYTES, timeout=20.0):
        n = self.rng.randint(5_000, 80_000)
        self.bytes_total += n
        host = urllib.parse.urlparse(url).hostname or "example.org"
        html = ('<a href="https://%s/a">a</a><a href="https://%s/b.pdf">b</a><img src="/i.png">' % (host, host))
        return 200, html, n

    def download(self, url, ident, cap, timeout=30.0):
        n = min(cap, self.rng.randint(10_000, 400_000))
        self.bytes_total += n
        return 200, n, True


def headers_for(ident: dict, referer: str | None) -> dict:
    h = {"User-Agent": ident["ua"], "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept-Language": ident["lang"], "Accept-Encoding": "identity", "Upgrade-Insecure-Requests": "1",
         "Connection": "close"}
    if referer:
        h["Referer"] = referer
    return h


# ── the browser lane (only when a headless browser is installed) ────────────
def find_browser(names=BROWSER_NAMES) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def browser_command(binary: str, url: str, profile: str, shot: str) -> list[str]:
    base = os.path.basename(binary).lower()
    if "firefox" in base:
        return [binary, "--headless", "--no-remote", "--profile", profile, "--screenshot", shot, url]
    return [binary, "--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
            "--user-data-dir=" + profile, "--virtual-time-budget=8000", "--dump-dom", url]


def browser_visit(binary: str, url: str, timeout: float = 45.0) -> tuple[bool, str]:
    """Open a page in a headless browser with a throw-away profile; True when it exited cleanly."""
    tmp = tempfile.mkdtemp(prefix="lp-browser-")
    try:
        cmd = browser_command(binary, url, os.path.join(tmp, "profile"), os.path.join(tmp, "shot.png"))
        os.makedirs(os.path.join(tmp, "profile"), exist_ok=True)
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=timeout, cwd=tmp)
        if r.returncode != 0:
            tail = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()[-1:] or ["exit %d" % r.returncode]
            return False, tail[0][:160]
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "browser timed out"
    except OSError as exc:
        return False, str(exc)[:160]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ── the runner ──────────────────────────────────────────────────────────────
def _clamp(x, lo, hi, default):
    try:
        return max(lo, min(hi, float(x)))
    except (TypeError, ValueError):
        return default


class Agent:
    def __init__(self, cfg: dict, net=None, rng: random.Random | None = None, browser: str | None = None,
                 sleep=None, now=time.time):
        self.cfg = cfg or {}
        self.dry = bool(self.cfg.get("dry_run"))
        # this machine's own randomness: fresh entropy from the OS, never a seed the controller could share
        self.rng = rng or random.Random(int.from_bytes(os.urandom(16), "big"))
        self.now = now
        self.stop = threading.Event()
        self._sleep = sleep
        self.scale = _clamp(self.cfg.get("time_scale"), 1, 10000, 1) if self.dry else 1.0
        r = self.rng
        # the pools: the controller sends a different random subset to every machine; shuffled again here
        self.domains = [d for d in (self.cfg.get("domains") or FALLBACK_DOMAINS) if isinstance(d, str)][:2000]
        self.queries = [q for q in (self.cfg.get("queries") or FALLBACK_QUERIES) if isinstance(q, str)][:2000]
        self.uas = [u for u in (self.cfg.get("user_agents") or FALLBACK_UAS) if isinstance(u, str)][:50] or FALLBACK_UAS
        self.extra_downloads = [u for u in (self.cfg.get("download_urls") or []) if isinstance(u, str)][:200]
        r.shuffle(self.domains)
        r.shuffle(self.queries)
        # this machine's rhythm and budgets (drawn once; every machine gets different ones)
        intensity = _clamp(self.cfg.get("actions_per_hour"), 1, MAX_ACTIONS_PER_HOUR, 30)
        self.rate = max(1.0, min(MAX_ACTIONS_PER_HOUR, intensity * r.lognormvariate(0, 0.25)))
        self.phase = r.uniform(0, 24)                     # where this machine's "day" peaks
        self.burst_mean = r.uniform(2.0, 6.0)             # actions in a burst, then a quiet gap
        self.gap_scale = r.uniform(0.6, 1.8)
        self.max_per_hour = int(min(MAX_ACTIONS_PER_HOUR, self.rate * r.uniform(1.6, 2.6)))
        self.max_mb_day = _clamp(self.cfg.get("max_mb_per_day"), 1, MAX_MB_PER_DAY, 200) * r.uniform(0.7, 1.0)
        self.max_download = int(min(MAX_DOWNLOAD_MB, _clamp(self.cfg.get("max_download_mb"), 0.1, MAX_DOWNLOAD_MB, 5))
                                * 1_000_000 * r.uniform(0.5, 1.0))
        self.lanes = {k: w for k, w in self._lane_weights().items() if w > 0}
        self.browser = browser if browser is not None else (
            find_browser() if (self.cfg.get("browser", "auto") != "off" and not self.dry) else None)
        self.browser_share = r.uniform(0.2, 0.5) if self.browser else 0.0
        self.net = net or (DryNet(r) if self.dry else Net(self._ua))
        self.ident = self._new_identity()
        self.visits_left = r.randint(15, 60)
        self.hour: deque[float] = deque()
        self.day_bytes = 0
        self.day_start = now()
        self.cool: dict[str, float] = {}
        self.counts = {"visit": 0, "search": 0, "dns": 0, "download": 0, "error": 0, "skipped": 0}
        self.recent_domains: deque[str] = deque(maxlen=40)
        self.found_downloads: deque[str] = deque(maxlen=60)

    # -- helpers
    def _ua(self) -> str:
        return self.ident["ua"]

    def _lane_weights(self) -> dict:
        c = self.cfg.get("lanes") or {}
        base = {"visit": 5.0, "search": 3.0, "dns": 4.0, "download": 1.0}
        out = {}
        for k, w in base.items():
            on = c.get(k, True)
            out[k] = (w * self.rng.uniform(0.5, 1.6)) if on else 0.0      # this machine's own lane mix
        return out

    def _new_identity(self) -> dict:
        return {"ua": self.rng.choice(self.uas), "lang": self.rng.choice(LANGS), "id": self.rng.randint(1000, 9999)}

    def wait(self, seconds: float) -> None:
        seconds = max(0.0, seconds / self.scale)
        if self._sleep:
            self._sleep(seconds)
        else:
            self.stop.wait(seconds)

    # -- budgets
    def _budget_ok(self) -> bool:
        t = self.now()
        while self.hour and t - self.hour[0] > 3600:
            self.hour.popleft()
        if t - self.day_start > 86400:
            self.day_start, self.day_bytes = t, 0
        if len(self.hour) >= self.max_per_hour:
            return False
        return self.day_bytes < self.max_mb_day * 1_000_000

    def _spent(self, n: int) -> None:
        self.hour.append(self.now())
        self.day_bytes += n

    # -- one action
    def step(self) -> bool:
        """Do one action. False when nothing could be done (budget spent or no lane is enabled)."""
        if not self.lanes:
            return False
        if not self._budget_ok():
            return False
        names = list(self.lanes)
        lane = self.rng.choices(names, weights=[self.lanes[n] for n in names])[0]
        if self.cool.get(lane, 0) > self.now():
            self.counts["skipped"] += 1
            return True
        try:
            getattr(self, "do_" + lane)()
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self.counts["error"] += 1
            emit(lane, "failed: %s" % (getattr(exc, "reason", None) or exc), "warn")
        return True

    def _site(self) -> str:
        for _ in range(8):
            d = self.rng.choice(self.domains)
            if d not in self.recent_domains:
                break
        self.recent_domains.append(d)
        return d

    def do_dns(self) -> None:
        site = self._site()
        names = [site, "www." + site] if self.rng.random() < 0.4 else [site]
        names += self.rng.sample(ASSET_HOSTS, self.rng.randint(0, 3))
        for n in names:
            ok = self.net.resolve(n)
            self.counts["dns"] += 1
            self._spent(200)
            emit("dns", "%s %s" % (n, "resolved" if ok else "no answer"))
            self.wait(self.rng.uniform(0.05, 0.6))

    def do_visit(self) -> None:
        site = self._site()
        url = "https://%s/" % (site if self.rng.random() < 0.5 else "www." + site)
        self._browse(url)

    def _browse(self, url: str, referer: str | None = None) -> None:
        if self.browser and self.rng.random() < self.browser_share:
            ok, why = browser_visit(self.browser, url)
            if ok:
                self.counts["visit"] += 1
                self._spent(300_000)
                emit("visit", "%s (headless browser)" % url)
                self._after_visit()
                return
            emit("visit", "browser lane failed (%s); using plain HTTP for this one" % why, "warn")
        status, html, n = self.net.fetch(url, self.ident, referer)
        self._spent(n)
        self.counts["visit"] += 1
        emit("visit", "%s -> %s (%d KB)" % (url, status, n // 1024))
        self._after_visit()
        if status >= 400 or not html:
            return
        links, assets = parse_page(html, url)
        host = urllib.parse.urlparse(url).hostname or ""
        for a in self.rng.sample(assets, min(len(assets), self.rng.randint(0, 4))):
            try:
                st, _t, nn = self.net.fetch(a, self.ident, url, limit=200_000)
                self._spent(nn)
            except (urllib.error.URLError, OSError, ValueError):
                break
        for link in links:
            if link.lower().split("?")[0].endswith(DOWNLOAD_EXT):
                self.found_downloads.append(link)
        same = [x for x in links if (urllib.parse.urlparse(x).hostname or "") .endswith(host.removeprefix("www."))
                and not x.lower().split("?")[0].endswith(DOWNLOAD_EXT)]
        depth = 0
        while same and depth < 3 and self.rng.random() < 0.55 and not self.stop.is_set():
            depth += 1
            self.wait(self.rng.lognormvariate(2.2, 0.7))           # reading the page
            nxt = same.pop(self.rng.randrange(len(same)))
            st, h2, n2 = self.net.fetch(nxt, self.ident, url)
            self._spent(n2)
            self.counts["visit"] += 1
            emit("visit", "%s -> %s (%d KB)" % (nxt, st, n2 // 1024))
            self._after_visit()
            url = nxt

    def _after_visit(self) -> None:
        self.visits_left -= 1
        if self.visits_left <= 0:                                  # a new "person": new browser identity
            self.ident = self._new_identity()
            self.visits_left = self.rng.randint(15, 60)
            emit("info", "new browser identity")

    def do_search(self) -> None:
        q = self.rng.choice(self.queries)
        engines = [(u, w) for u, w in SEARCH_ENGINES if self.cool.get(u, 0) <= self.now()] or SEARCH_ENGINES
        base = self.rng.choices([u for u, _ in engines], weights=[w for _, w in engines])[0]
        url = base + urllib.parse.quote_plus(q)
        status, html, n = self.net.fetch(url, self.ident)
        self._spent(n)
        self.counts["search"] += 1
        emit("search", "%s -> %s" % (urllib.parse.urlparse(base).hostname, status))
        if status in (403, 429, 503):
            self.cool[base] = self.now() + self.rng.uniform(1800, 5400)
            emit("info", "%s is limiting this machine; resting it for a while" % urllib.parse.urlparse(base).hostname)
            return
        if html and self.rng.random() < 0.5:
            links, _a = parse_page(html, url)
            eng_host = urllib.parse.urlparse(base).hostname or ""
            results = [unwrap_result_link(x) for x in links]
            results = [x for x in results if (urllib.parse.urlparse(x).hostname or "") and eng_host.split(".")[-2:]
                       != (urllib.parse.urlparse(x).hostname or "").split(".")[-2:]]
            if results:
                self.wait(self.rng.lognormvariate(1.5, 0.6))
                self._browse(self.rng.choice(results[:8]), referer=url)

    def do_download(self) -> None:
        pool = list(self.found_downloads) + self.extra_downloads
        if not pool or self.max_download < 50_000:
            self.counts["skipped"] += 1
            return self.do_visit() if "visit" in self.lanes else None
        url = self.rng.choice(pool)
        status, n, done = self.net.download(url, self.ident, self.max_download)
        self._spent(n)
        self.counts["download"] += 1
        emit("download", "%s -> %s (%d KB read%s; not saved)" % (url, status, n // 1024, "" if done else ", stopped at the cap"))

    # -- the main loop: bursts and quiet gaps around this machine's own daily rhythm
    def diurnal(self, hour_of_day: float) -> float:
        """0.25 (quiet) .. 1.0 (busy), peaking at this machine's own hour."""
        import math
        d = math.cos((hour_of_day - self.phase) / 24 * 2 * math.pi)
        return 0.625 + 0.375 * d

    def run(self, max_steps: int | None = None) -> None:
        emit("info", "runner started", version=VERSION, lanes=sorted(self.lanes), browser=bool(self.browser),
             dry_run=self.dry, actions_per_hour=round(self.rate, 1), max_mb_per_day=round(self.max_mb_day),
             max_download_mb=round(self.max_download / 1e6, 1))
        steps, last_stats = 0, self.now()
        while not self.stop.is_set() and (max_steps is None or steps < max_steps):
            n = max(1, int(self.rng.expovariate(1 / self.burst_mean)) + 1)
            for _ in range(n):
                if self.stop.is_set():
                    break
                if not self.step():
                    emit("info", "budget reached; resting", budget="spent")
                    self.wait(self.rng.uniform(120, 600))
                    break
                steps += 1
                self.wait(max(MIN_GAP_SECONDS, self.rng.lognormvariate(1.2, 0.8)))
                if max_steps is not None and steps >= max_steps:
                    break
            hour = time.localtime(self.now()).tm_hour + time.localtime(self.now()).tm_min / 60
            mean_gap = 3600 / max(1.0, self.rate * self.diurnal(hour)) * self.burst_mean * self.gap_scale
            self.wait(self.rng.expovariate(1 / max(5.0, mean_gap)))
            if self.now() - last_stats > 60:
                last_stats = self.now()
                emit("stats", "status", counts=self.counts, mb=round(self.net.bytes_total / 1e6, 2))
        emit("stats", "final", counts=self.counts, mb=round(self.net.bytes_total / 1e6, 2))
        emit("info", "runner stopped")


# ── command line ────────────────────────────────────────────────────────────
def probe() -> dict:
    py = sys.version.split()[0]
    b = find_browser()
    resolver = False
    try:
        resolver = bool(socket.getaddrinfo("wikipedia.org", 443))
    except OSError:
        pass
    return {"kind": "probe", "python": py, "platform": sys.platform, "browser": b, "dns": resolver,
            "home": os.path.expanduser("~"), "version": VERSION}


def _watch_stdin(agent: Agent) -> None:
    """The SSH connection ending (stdin closes) or the line 'stop' stops the runner."""
    try:
        for line in sys.stdin:
            if line.strip().lower() == "stop":
                break
    except (OSError, ValueError):
        pass
    agent.stop.set()


def _pid_path(folder: str) -> str:
    return os.path.join(folder, PID_FILE)


def cmd_run(cfg_path: str) -> int:
    folder = os.path.dirname(os.path.abspath(cfg_path))
    with open(cfg_path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    agent = Agent(cfg)
    pid_file = _pid_path(folder)
    try:
        with open(pid_file, "w", encoding="ascii") as fh:
            fh.write(str(os.getpid()))
    except OSError:
        pid_file = ""
    for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None), getattr(signal, "SIGHUP", None)):
        if sig is not None:
            try:
                signal.signal(sig, lambda *_a: agent.stop.set())
            except (ValueError, OSError):
                pass
    threading.Thread(target=_watch_stdin, args=(agent,), daemon=True).start()
    try:
        agent.run()
    finally:
        if pid_file:
            try:
                os.remove(pid_file)
            except OSError:
                pass
    return 0


def cmd_stop(folder: str) -> int:
    try:
        with open(_pid_path(folder), encoding="ascii") as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        print(json.dumps({"kind": "stop", "stopped": False, "msg": "no runner is recorded in that folder"}))
        return 0
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, timeout=15)
        else:
            os.kill(pid, signal.SIGTERM)
        print(json.dumps({"kind": "stop", "stopped": True, "msg": "stop signal sent"}))
    except (OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"kind": "stop", "stopped": False, "msg": str(exc)[:120]}))
    return 0


def main(argv: list[str] | None = None) -> int:
    a = list(sys.argv[1:] if argv is None else argv)
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if a[0] == "probe":
        print(json.dumps(probe()))
        return 0
    if a[0] == "run" and len(a) >= 2:
        return cmd_run(a[1])
    if a[0] == "stop" and len(a) >= 2:
        return cmd_stop(a[1])
    print("usage: agent.py run <settings.json> | stop <folder> | probe", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
