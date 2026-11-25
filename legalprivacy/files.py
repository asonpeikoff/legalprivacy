"""File transfers as noise: downloads of images, video, archives, documents and audio, and uploads of random size.

People move files: a photo here, a video there, a zip now and then. A connection that only ever loads small pages looks
unlike that, so now and then the noise fetches a real file and throws the bytes away, and sometimes sends a random-sized
block of random bytes to a public speed-test endpoint (never anything of yours).

Where the files come from: the Internet Archive's public collections, found through its search API: Flickr Commons photos
(images), the Prelinger Archives films (video), Project Gutenberg books (zip archives and documents) and open-source audio.
All of it is public and free to download. Each download is capped (default 20 MB, and it stops reading at the cap), the
chosen size varies a lot (small photos most of the time, an occasional big one), and the mix leans the way real use does:
mostly images, some video and archives, a few documents and tracks.
"""
from __future__ import annotations

import math
import os
import random
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

from .transports import HitResult, Target

IA_SEARCH = "https://archive.org/advancedsearch.php"
IA_META = "https://archive.org/metadata/{id}"
IA_FILE = "https://archive.org/download/{id}/{name}"
UP_URL = "https://speed.cloudflare.com/__up"
USER_AGENT = "legalPrivacy file noise (+https://github.com/asonpeikoff/legalprivacy)"

# kind -> (collection, formats we take, relative weight)
KINDS: dict[str, tuple[str, tuple[str, ...], int]] = {
    "image": ("flickrcommons", ("JPEG",), 55),
    "video": ("prelinger", ("512Kb MPEG4", "h.264", "Ogg Video"), 14),
    "archive": ("gutenberg", ("ZIP",), 14),
    "document": ("gutenberg", ("PDF", "EPUB", "Text"), 9),
    "audio": ("opensource_audio", ("VBR MP3",), 8),
}
DEFAULT_CAP = 20_000_000
UPLOAD_SHARE = 0.14


@dataclass
class Pick:
    url: str
    kind: str
    size: int
    name: str


def _get_json(url: str, params: dict | None = None, timeout: float = 20.0) -> dict:
    import requests
    r = requests.get(url, params=params, timeout=timeout, headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    return r.json()


def wanted_size(rng: random.Random, cap: int) -> int:
    """A size a person might move: mostly small, sometimes large (log-normal, median about 1.5 MB), never over `cap`."""
    return int(min(cap, max(30_000, rng.lognormvariate(math.log(1_500_000), 1.3))))


class FileCatalog:
    def __init__(self, rng: random.Random | None = None, get_json: Callable[..., dict] = _get_json):
        self.rng = rng or random.Random()
        self.get_json = get_json
        self.pools: dict[str, list[str]] = {}

    def _refill(self, kind: str) -> None:
        coll, formats, _w = KINDS[kind]
        fmt = " OR ".join(f'format:"{f}"' for f in formats)
        data = self.get_json(IA_SEARCH, {"q": f"collection:{coll} AND ({fmt})", "fl[]": "identifier", "rows": 40,
                                         "output": "json", "sort[]": "random"})
        self.pools[kind] = [d["identifier"] for d in data.get("response", {}).get("docs", []) if d.get("identifier")]

    def pick(self, cap: int = DEFAULT_CAP, kind: str | None = None) -> Pick | None:
        """One file to download: a kind chosen by weight, an item of that kind, and the file of it closest to a size drawn at
        random (within `cap`). None when nothing fit after a few tries (the caller does something else)."""
        kinds = list(KINDS)
        kind = kind or self.rng.choices(kinds, weights=[KINDS[k][2] for k in kinds])[0]
        want = wanted_size(self.rng, cap)
        for _ in range(4):
            try:
                if not self.pools.get(kind):
                    self._refill(kind)
                ident = (self.pools.get(kind) or [None]).pop()
                if ident is None:
                    return None
                meta = self.get_json(IA_META.format(id=urllib.parse.quote(ident)))
            except Exception:
                return None
            formats = KINDS[kind][1]
            files = [f for f in meta.get("files", []) if f.get("format") in formats and "/" not in f.get("name", "/")
                     and str(f.get("size", "")).isdigit() and 5_000 <= int(f["size"]) <= cap]
            if not files:
                continue
            f = min(files, key=lambda x: abs(math.log(int(x["size"])) - math.log(want)) + self.rng.random() * 0.3)
            return Pick(IA_FILE.format(id=urllib.parse.quote(ident), name=urllib.parse.quote(f["name"])), kind,
                        int(f["size"]), f["name"])
        return None


def human(n: float) -> str:
    return f"{n / 1e6:.1f} MB" if n >= 1e6 else f"{n / 1e3:.0f} KB"


def upload_size(rng: random.Random, cap: int = 3_000_000) -> int:
    return int(min(cap, max(10_000, rng.lognormvariate(math.log(150_000), 1.2))))


def transfer(target: Target, proxies: dict | None, headers: dict | None, timeout: float | None = None) -> HitResult:
    """Do one download (read it all, keep nothing) or one upload (random bytes). The result counts the bytes moved."""
    import requests
    t0 = time.time()
    try:
        if target.kind == "download":
            cap = target.size or DEFAULT_CAP
            got = 0
            with requests.get(target.url, stream=True, timeout=timeout or max(target.timeout, 30.0), proxies=proxies,
                              headers=headers or {"User-Agent": USER_AGENT}, allow_redirects=True) as r:
                for chunk in r.iter_content(65536):
                    got += len(chunk)
                    if got >= cap:
                        break
                status = r.status_code
            res = HitResult(status, "")
            res.bytes = got
            res.detail = f"downloaded {human(got)} in {time.time() - t0:.1f} s"
        else:
            n = target.size or 100_000

            r = requests.post(target.url, data=os.urandom(n), timeout=timeout or max(target.timeout, 30.0), proxies=proxies,
                              headers={"User-Agent": USER_AGENT, "Content-Type": "application/octet-stream"})
            res = HitResult(r.status_code, "")
            res.bytes = n
            res.detail = f"uploaded {human(n)} in {time.time() - t0:.1f} s"
        return res
    except requests.RequestException as exc:
        return HitResult(None, error=str(exc).splitlines()[0][:160])
