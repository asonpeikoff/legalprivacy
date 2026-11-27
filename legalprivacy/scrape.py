"""A polite spider for jobs the user starts: pull tables, images, video, audio, documents and archives from a site.

It is a normal crawler with good manners, and it can hide among noise:

  * it follows robots.txt (on by default), keeps to the start site, and waits a random few seconds between requests;
  * tables become CSV files; images, video, audio, documents and archives are saved to the job's folder, with a limit on
    each file and on the whole job;
  * "mix in noise": between its own requests it now and then visits an unrelated popular site, so the job's requests
    do not arrive as one unbroken run;
  * it can go through a proxy that passed the proxy tester (never for anything with a login: it does not log in).

It reads only what a visitor can see. It does not log in, solve challenges or get around blocks.
"""
from __future__ import annotations

import csv
import hashlib
import random
import re
import threading
import time
import urllib.parse
import urllib.robotparser
from collections import deque
from collections.abc import Callable
from html.parser import HTMLParser
from pathlib import Path

KINDS = {
    "images": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".avif"},
    "video": {".mp4", ".webm", ".mkv", ".mov", ".avi", ".m4v", ".ogv"},
    "audio": {".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac", ".opus"},
    "documents": {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".csv", ".txt", ".epub"},
    "archives": {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"},
}
ALL_KINDS = ["tables", *KINDS]
# Words in an image's file name, class, id or alt text that mark page furniture rather than content.
UI_WORDS = ("banner", "icon", "logo", "sprite", "favicon", "avatar", "button", "btn", "badge", "spinner", "loader",
            "loading", "spacer", "pixel", "blank", "placeholder", "arrow", "chevron", "caret", "emoji", "social",
            "share", "header", "footer", "navbar", "nav-", "menu", "bullet", "divider", "separator", "background",
            "bg-", "watermark", "tracking", "1x1", "transparent", "thumbnail-placeholder", "rating")
# whole words only (an "s" may follow): "icons.png" and "site-logo.svg" match, "closeup.jpg" and "starfish.png" do not
_UI_RE = re.compile(r"(?<![a-z])(" + "|".join(re.escape(w) for w in UI_WORDS) + r")s?(?![a-z])", re.I)


def looks_like_ui(url: str, hint: str = "") -> bool:
    """True for an image that is probably part of the page's look (a banner, icon, logo, sprite...), going by its file
    name and by the class, id and alt text of its tag."""
    name = Path(urllib.parse.urlparse(url).path).name
    return bool(_UI_RE.search(name) or (hint and _UI_RE.search(hint)))


def image_size(path: Path) -> tuple[int, int] | None:
    """Width and height of a PNG, GIF, JPEG or WebP file from its header, or None when it cannot tell."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(64 * 1024)
    except OSError:
        return None
    import struct
    if head[:8] == b"\x89PNG\r\n\x1a\n" and len(head) >= 24:
        return struct.unpack(">II", head[16:24])
    if head[:6] in (b"GIF87a", b"GIF89a") and len(head) >= 10:
        return struct.unpack("<HH", head[6:10])
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP" and len(head) >= 30:
        chunk = head[12:16]
        if chunk == b"VP8X":
            return 1 + int.from_bytes(head[24:27], "little"), 1 + int.from_bytes(head[27:30], "little")
        if chunk == b"VP8 " and len(head) >= 30:
            w, h = struct.unpack("<HH", head[26:30])
            return w & 0x3FFF, h & 0x3FFF
        if chunk == b"VP8L" and len(head) >= 25:
            b = head[21:25]
            return 1 + (((b[1] & 0x3F) << 8) | b[0]), 1 + (((b[3] & 0xF) << 10) | (b[2] << 2) | ((b[1] & 0xC0) >> 6))
    if head[:2] == b"\xff\xd8":
        i = 2
        while i + 9 < len(head):
            if head[i] != 0xFF:
                i += 1
                continue
            marker = head[i + 1]
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                h, w = struct.unpack(">HH", head[i + 5:i + 9])
                return w, h
            if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
                i += 2
                continue
            i += 2 + struct.unpack(">H", head[i + 2:i + 4])[0]
    return None


def _px(v) -> int:
    m = re.match(r"\s*(\d+)", str(v or ""))
    return int(m.group(1)) if m else 0
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.files: list[str] = []
        self.meta: dict[str, dict] = {}           # an image's declared width/height and its class, id and alt text
        self.tables: list[list[list[str]]] = []
        self.title = ""
        self._in_title = False
        self._table: list[list[str]] | None = None
        self._row: list[str] | None = None
        self._cell: list[str] | None = None
        self._depth = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("img", "source", "video", "audio", "embed", "track") and a.get("src"):
            self.files.append(a["src"])
            if tag == "img":
                self.meta[a["src"]] = {"w": _px(a.get("width")), "h": _px(a.get("height")),
                                       "hint": " ".join(str(a.get(k) or "") for k in ("class", "id", "alt"))}
        if tag in ("img", "source") and a.get("srcset"):
            self.files.extend(p.strip().split()[0] for p in a["srcset"].split(",") if p.strip())
        if tag == "video" and a.get("poster"):
            self.files.append(a["poster"])
        if tag == "table":
            self._depth += 1
            if self._depth == 1:
                self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None and self._table is not None:
            if any(self._row):
                self._table.append(self._row)
            self._row = None
        elif tag == "table":
            self._depth = max(0, self._depth - 1)
            if self._depth == 0 and self._table is not None:
                if len(self._table) >= 2:
                    self.tables.append(self._table)
                self._table = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._cell is not None:
            self._cell.append(data)


def extract(html: str, base: str) -> dict:
    """Links, file URLs, tables and the title of one page (all URLs made absolute, without fragments)."""
    p = _Page()
    try:
        p.feed(html or "")
        p.close()
    except Exception:
        pass

    def absolute(u: str) -> str | None:
        u = (u or "").strip()
        if not u or u.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return None
        full = urllib.parse.urljoin(base, u).split("#")[0]
        return full if full.startswith(("http://", "https://")) else None
    return {"title": " ".join(p.title.split())[:200],
            "links": list(dict.fromkeys(x for x in map(absolute, p.links) if x)),
            "files": list(dict.fromkeys(x for x in map(absolute, p.files + p.links) if x)),
            "tables": p.tables,
            "meta": {full: m for u, m in p.meta.items() if (full := absolute(u))}}


def kind_of(url: str) -> str | None:
    ext = Path(urllib.parse.urlparse(url).path).suffix.lower()
    for k, exts in KINDS.items():
        if ext in exts:
            return k
    return None


def _site(u: str) -> str:
    return (urllib.parse.urlparse(u).hostname or "").lower().removeprefix("www.")


def explain(exc: BaseException) -> str:
    """A short, plain reason for a failed request, naming the real cause (requests nests it several levels deep)."""
    name = type(exc).__name__
    inner, seen = exc, set()
    while True:                                    # the innermost cause usually says what actually happened
        nxt = getattr(inner, "reason", None) or inner.__cause__ or inner.__context__
        if nxt is None and inner.args and isinstance(inner.args[0], BaseException):
            nxt = inner.args[0]
        if not isinstance(nxt, BaseException) or id(nxt) in seen:
            break
        seen.add(id(nxt))
        inner = nxt
    detail = re.sub(r"\s+", " ", str(inner)).strip()
    detail = re.sub(r"^<[^>]+>:\s*", "", detail)
    plain = {"ProxyError": "the proxy refused or dropped the connection",
             "SSLError": "the secure connection failed (through a proxy this can mean it tampers with it, so it is not used)",
             "ConnectTimeout": "timed out connecting", "ReadTimeout": "the site took too long to answer",
             "ConnectionError": "could not connect", "TooManyRedirects": "too many redirects"}.get(name)
    text = f"{plain} ({detail[:140]})" if plain and detail else plain or detail or name
    return text[:220]


PROXY_TRIES = 5          # a proxy that fails in use is dropped and the next tested one is tried, up to this many


class NoProxyLeft(RuntimeError):
    """Every tested proxy tried failed: the job stops rather than going on without one (that would show your address)."""


class ScrapeJob:
    def __init__(self, url: str, out_dir: Path, kinds: list[str] | None = None, depth: int = 1, max_pages: int = 20,
                 delay: float = 2.0, max_mb: float = 200.0, file_mb: float = 50.0, same_site: bool = True,
                 respect_robots: bool = True, mix_noise: bool = True, proxy: str | None = None,
                 noise_fn: Callable[[], None] | None = None,
                 next_proxy: Callable[[str], str | None] | None = None,
                 get: Callable[..., tuple[int, str, dict]] | None = None, sleep: Callable[[float], None] = time.sleep,
                 rng: random.Random | None = None, skip_ui: bool = True, min_kb: float = 8.0, max_kb: float = 0.0,
                 min_px: int = 100, max_px: int = 0):
        if not re.match(r"^https?://[^\s/]+", url or ""):
            raise ValueError("The start address must begin with http:// or https://")
        self.url, self.out = url, Path(out_dir)
        self.kinds = [k for k in (kinds or ALL_KINDS) if k in ALL_KINDS]
        self.depth, self.max_pages = max(0, int(depth)), max(1, int(max_pages))
        self.delay, self.max_bytes, self.file_bytes = max(0.0, delay), int(max_mb * 1e6), int(file_mb * 1e6)
        self.same_site, self.respect_robots, self.mix_noise = same_site, respect_robots, mix_noise
        self.proxy, self.noise_fn, self.sleep = proxy, noise_fn, sleep
        self.next_proxy = next_proxy          # drops a proxy that failed and gives another tested one (None: none left)
        self.rng = rng or random.Random()
        # image filters: skip page furniture, tiny files and images outside a size range (0 = no limit)
        self.skip_ui, self.min_bytes, self.max_img_bytes = bool(skip_ui), int(max(0.0, min_kb) * 1000), int(max(0.0, max_kb) * 1000)
        self.min_px, self.max_px = max(0, int(min_px)), max(0, int(max_px))
        self._get = get or self._requests_get
        self.stop = threading.Event()
        self.status = {"running": False, "done": False, "pages": 0, "tables": 0, "files": 0, "bytes": 0, "noise": 0,
                       "errors": [], "current": "", "folder": str(self.out), "skipped_robots": 0,
                       "skipped_filter": 0}
        self._robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}
        self._seen_files: set[str] = set()

    # ── network ───────────────────────────────────────────────────────────
    def _requests_get(self, url: str, stream_to: Path | None = None, limit: int = 0):
        """One request. Through a proxy, a proxy-side failure drops that proxy and tries the next tested one."""
        import requests
        if not self.proxy:
            return self._one_get(url, stream_to, limit)
        tried: list[str] = []
        while True:
            try:
                return self._one_get(url, stream_to, limit)
            except (requests.exceptions.ProxyError, requests.exceptions.SSLError,
                    requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError) as exc:
                tried.append(f"{self.proxy.split('//')[-1]}: {explain(exc)}")
                nxt = self.next_proxy(self.proxy) if self.next_proxy and len(tried) < PROXY_TRIES else None
                if not nxt:
                    raise NoProxyLeft(f"no working proxy: tried {len(tried)} ({'; '.join(tried[-2:])}). Test proxies "
                                      "again on this tab, or turn the proxy off.") from exc
                self.status["proxy_switches"] = self.status.get("proxy_switches", 0) + 1
                self.proxy = nxt

    def _one_get(self, url: str, stream_to: Path | None = None, limit: int = 0):
        import requests
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        r = requests.get(url, headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}, timeout=25,
                         proxies=proxies, stream=True, allow_redirects=True)
        try:
            ctype = r.headers.get("Content-Type", "")
            if stream_to is None:
                if ctype and not any(t in ctype.lower() for t in ("html", "text/plain", "xml")):
                    return r.status_code, "", dict(r.headers)
                body = r.raw.read(3_000_000, decode_content=True)
                return r.status_code, body.decode(r.encoding or "utf-8", "replace"), dict(r.headers)
            size = int(r.headers.get("Content-Length") or 0)
            if r.status_code != 200 or (limit and size > limit):
                return r.status_code, "", {"skipped": "too large" if size > limit else "status"}
            total = 0
            stream_to.parent.mkdir(parents=True, exist_ok=True)
            with open(stream_to, "wb") as fh:
                for chunk in r.iter_content(65536):
                    total += len(chunk)
                    if limit and total > limit:
                        fh.close()
                        stream_to.unlink(missing_ok=True)
                        return 200, "", {"skipped": "too large"}
                    fh.write(chunk)
            return 200, "", {"bytes": total}
        finally:
            r.close()

    def _allowed(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        parts = urllib.parse.urlparse(url)
        root = f"{parts.scheme}://{parts.netloc}"
        if root not in self._robots:
            rp = urllib.robotparser.RobotFileParser()
            try:
                status, text, _h = self._get(root + "/robots.txt")
                rp.parse(text.splitlines() if status == 200 else [])
                self._robots[root] = rp if status == 200 else None
            except Exception:
                self._robots[root] = None
        rp = self._robots[root]
        return True if rp is None else rp.can_fetch(USER_AGENT, url)

    def _pause(self) -> None:
        if self.delay:
            self.sleep(self.rng.uniform(self.delay * 0.5, self.delay * 1.5))
        if self.mix_noise and self.noise_fn is not None and self.rng.random() < 0.35 and not self.stop.is_set():
            try:
                self.noise_fn()
                self.status["noise"] += 1
            except Exception:
                pass
            self.sleep(self.rng.uniform(0.5, max(1.0, self.delay)))

    # ── the job ───────────────────────────────────────────────────────────
    def run(self) -> dict:
        st = self.status
        st["running"], st["done"] = True, False
        self.out.mkdir(parents=True, exist_ok=True)
        queue: deque[tuple[str, int]] = deque([(self.url, 0)])
        seen = {self.url}
        home = _site(self.url)
        try:
            while queue and st["pages"] < self.max_pages and not self.stop.is_set():
                url, d = queue.popleft()
                st["current"] = url
                if not self._allowed(url):
                    st["skipped_robots"] += 1
                    continue
                try:
                    status, html, _h = self._get(url)
                except NoProxyLeft as exc:
                    st["errors"].append(f"{url}: {exc}")
                    break                                   # never carry on without the proxy you asked for
                except Exception as exc:
                    st["errors"].append(f"{url}: {explain(exc)}")
                    continue
                st["pages"] += 1
                if status != 200 or not html:
                    if status != 200:
                        st["errors"].append(f"{url}: HTTP {status}")
                    self._pause()
                    continue
                page = extract(html, url)
                if "tables" in self.kinds:
                    self._save_tables(page)
                self._download_files(page)
                if d < self.depth:
                    for link in page["links"]:
                        if link in seen or kind_of(link):
                            continue
                        if self.same_site and _site(link) != home:
                            continue
                        seen.add(link)
                        queue.append((link, d + 1))
                self._pause()
        finally:
            st["running"], st["done"], st["current"] = False, True, ""
        return st

    def _save_tables(self, page: dict) -> None:
        for i, t in enumerate(page["tables"]):
            name = f"{_slug(page['title'] or 'page')}-{hashlib.sha1(repr(t).encode()).hexdigest()[:6]}-{i + 1}.csv"
            p = self.out / "tables" / name
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerows(t)
            self.status["tables"] += 1

    def _download_files(self, page: dict) -> None:
        st = self.status
        for f in page["files"]:
            k = kind_of(f)
            if k is None or k not in self.kinds or f in self._seen_files:
                continue
            if st["bytes"] >= self.max_bytes or self.stop.is_set():
                return
            self._seen_files.add(f)
            meta = page.get("meta", {}).get(f, {})
            if k == "images" and not self._image_wanted_before(f, meta):
                st["skipped_filter"] += 1
                continue
            if not self._allowed(f):
                st["skipped_robots"] += 1
                continue
            name = _slug(Path(urllib.parse.urlparse(f).path).stem or "file")[:60] + \
                "-" + hashlib.sha1(f.encode()).hexdigest()[:6] + Path(urllib.parse.urlparse(f).path).suffix.lower()
            dest = self.out / k / name
            limit = min(self.file_bytes, self.max_bytes - st["bytes"])
            if k == "images" and self.max_img_bytes:
                limit = min(limit, self.max_img_bytes)
            try:
                status, _t, meta = self._get(f, stream_to=dest, limit=limit)
            except Exception as exc:
                st["errors"].append(f"{f}: {explain(exc)}")
                continue
            if k == "images" and (meta.get("skipped") == "too large" and self.max_img_bytes or
                                  status == 200 and meta.get("bytes") and not self._image_wanted_after(dest, int(meta["bytes"]))):
                dest.unlink(missing_ok=True)
                st["skipped_filter"] += 1
                continue
            if status == 200 and meta.get("bytes"):
                st["files"] += 1
                st["bytes"] += int(meta["bytes"])
            self.sleep(self.rng.uniform(0.1, 0.6) if self.delay else 0)


    def _image_wanted_before(self, url: str, meta: dict) -> bool:
        """Before downloading: no UI-looking names, and no declared size below the minimum."""
        if self.skip_ui and looks_like_ui(url, meta.get("hint", "")):
            return False
        w, h = meta.get("w") or 0, meta.get("h") or 0
        return not (self.min_px and ((w and w < self.min_px) or (h and h < self.min_px)))

    def _image_wanted_after(self, path: Path, size: int) -> bool:
        """After downloading: inside the file-size range, and (when the header tells) the pixel range."""
        if size < self.min_bytes or (self.max_img_bytes and size > self.max_img_bytes):
            return False
        dims = image_size(path) if (self.min_px or self.max_px) else None
        if dims:
            w, h = dims
            if self.min_px and min(w, h) < self.min_px:
                return False
            if self.max_px and max(w, h) > self.max_px:
                return False
        return True


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:40] or "x"
