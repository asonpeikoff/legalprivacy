"""Live data sources for realistic noise, cached on disk, refreshed in the background.

  trends   Google Trends daily-search RSS        (what people are searching today)
  wiki     Wikipedia most-viewed articles        (what people are reading today)
  news     BBC News RSS headlines                (what is in the news today)
  dataset  real search queries: MS MARCO (Bing) and GooAQ (Google autocomplete),
           sampled at random over the Hugging Face datasets-server — fetched at
           runtime for personal use, never bundled or redistributed
  tranco   Tranco top-sites ranking              (real, popular domains)
  deny     StevenBlack adult/gambling/fake-news host list (used only as a filter)

Everything is best-effort: any failure leaves the previous cache (or the small
built-in fallbacks) in place and is reported through the event log.
"""
from __future__ import annotations

import csv
import html
import io
import json
import random
import re
import threading
import time
import zipfile
from datetime import date, timedelta
from collections.abc import Callable

import requests

from .events import EventLog
from .paths import app_dir
from .safety import safe_domain, safe_query

UA = "legalPrivacy/2.4 (privacy noise generator; +https://github.com/asonpeikoff/legalPrivacy)"
TRENDS_URL = "https://trends.google.com/trending/rss?geo={geo}"
WIKI_URL = "https://wikimedia.org/api/rest_v1/metrics/pageviews/top/en.wikipedia/all-access/{d}"
NEWS_FEEDS = [f"https://feeds.bbci.co.uk/news/{p}rss.xml" for p in
              ("", "world/", "technology/", "science_and_environment/", "health/", "business/",
               "entertainment_and_arts/")]
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
DENY_URL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts"
CRUX_URL = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz"
SPRAY_URLS = {   # big public lists of domains (checked to exist): OpenDNS top and random 10,000, and a top-million list
    "opendns_top": "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt",
    "opendns_random": "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-random-domains.txt",
    "top_million": "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains",
}
OPENNIC_URL = "https://servers.opennic.org/"     # the public server table (features + Pass/Fail)
DS_ROWS = "https://datasets-server.huggingface.co/rows"
DATASETS = [  # (dataset, config, split, field, conservative max row index)
    ("microsoft/ms_marco", "v2.1", "train", "query", 800_000),
    ("sentence-transformers/gooaq", "pair", "train", "question", 3_000_000),
]
# A shipped snapshot (data/feeds/snapshot.json.gz) means users never need to fetch these.
# If they opt in to auto-refresh, sources are re-fetched only this rarely.
TTL = {k: 90 * 86400 for k in ("trends", "wiki", "news", "dataset", "tranco", "deny", "opennic", "crux", "spray")}
_SKIP_WIKI = re.compile(r"^(Main_Page|Special:|Wikipedia:|Portal:|File:|Help:|Category:|Template:|Talk:|User:|-$)")


def _load_bundled() -> dict:
    import gzip
    from .paths import resource_root
    p = resource_root() / "data" / "feeds" / "snapshot.json.gz"
    try:
        with gzip.open(p, "rt", encoding="utf-8") as fh:
            d = json.load(fh)
        d.pop("built", None)
        return d
    except (OSError, ValueError):
        return {}


def _get(url: str, **kw) -> requests.Response:
    r = requests.get(url, headers={"User-Agent": UA}, timeout=kw.pop("timeout", 25), **kw)
    r.raise_for_status()
    return r


class FeedStore:
    """Disk-cached feed data + background refresh. Thread-safe reads."""

    def __init__(self, log: EventLog | None = None, path=None, fetchers: dict | None = None,
                 bundled: bool = True):
        self.log = log
        self.path = path or (app_dir() / "feeds.json")
        self.bundled = _load_bundled() if bundled else {}
        self._lock = threading.Lock()
        self.data: dict[str, dict] = {}
        self.errors: dict[str, str] = {}
        self.fetchers: dict[str, Callable[[], list]] = fetchers or {
            "deny": self._fetch_deny, "trends": self._fetch_trends, "wiki": self._fetch_wiki,
            "news": self._fetch_news, "dataset": self._fetch_dataset, "tranco": self._fetch_tranco,
            "opennic": self._fetch_opennic, "crux": self._fetch_crux, "spray": self._fetch_spray}
        self.refreshing = False
        self._load()

    # -- persistence -------------------------------------------------------
    def _load(self) -> None:
        try:
            self.data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}

    def _save(self) -> None:
        try:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass

    def _entry(self, name: str) -> dict:
        """User's own refreshed copy if any, else the snapshot shipped with the app."""
        own = self.data.get(name)
        if name == "opennic" and own and not all(str(x).count("|") >= 4 for x in own.get("items", [])):
            own = None          # an older copy without the logging/encryption checks: don't trust it
        return own or self.bundled.get(name) or {}

    def items(self, name: str) -> list:
        with self._lock:
            return list(self._entry(name).get("items", []))

    def denylist(self) -> set[str]:
        ent = self._entry("deny")
        key = (id(ent), ent.get("ts"))
        if getattr(self, "_deny_key", None) != key:          # building a 160k-entry set is not free
            self._deny_set, self._deny_key = set(ent.get("items", [])) | getattr(self, "user_block", set()), key
        return self._deny_set

    def set_user_block(self, hosts: set[str]) -> None:
        """Sites the user told the app to leave alone (from the network map): added to the deny list."""
        self.user_block = set(hosts)
        self._deny_key = None

    def status(self) -> list[dict]:
        out = []
        for name in self.fetchers:
            ent = self._entry(name)
            out.append({"name": name, "count": len(ent.get("items", [])), "updated": ent.get("ts"),
                        "stale": (time.time() - ent.get("ts", 0)) > TTL[name] if ent else True,
                        "origin": "your refresh" if name in self.data else ("shipped snapshot" if ent else "none"),
                        "error": self.errors.get(name)})
        return out

    # -- refresh -----------------------------------------------------------
    def refresh(self, force: bool = False, only: list[str] | None = None) -> None:
        """Blocking refresh of stale sources (call from a background thread)."""
        self.refreshing = True
        changed = False
        try:
            for name, fn in self.fetchers.items():
                if only and name not in only:
                    continue
                ent = self._entry(name)
                if not force and ent and time.time() - ent.get("ts", 0) < TTL[name]:
                    continue
                try:
                    items = fn()
                    if not items:
                        raise RuntimeError("source returned nothing")
                    with self._lock:
                        self.data[name] = {"ts": time.time(), "items": items}
                    self.errors.pop(name, None)
                    changed = True
                    self._log("info", f"Feed '{name}' refreshed: {len(items):,} items")
                except Exception as exc:
                    self.errors[name] = str(exc)[:200]
                    self._log("warn", f"Feed '{name}' unavailable ({str(exc)[:120]}); using "
                                      f"{'cached data' if ent else 'built-in fallback'}")
            if changed:
                self._save()
        finally:
            self.refreshing = False

    def refresh_async(self, force: bool = False) -> None:
        if self.refreshing:
            return
        threading.Thread(target=self.refresh, args=(force,), daemon=True, name="feeds").start()

    def _log(self, level: str, msg: str) -> None:
        if self.log:
            self.log.add(level, "feeds", msg)

    # -- fetchers ----------------------------------------------------------
    def _fetch_trends(self) -> list[str]:
        txt = _get(TRENDS_URL.format(geo="US")).text
        titles = [html.unescape(t) for block in txt.split("<item>")[1:]
                  for t in re.findall(r"<title>(.*?)</title>", block, re.S)[:1]]
        return [t.strip().lower() for t in titles if safe_query(t)]

    def _fetch_wiki(self) -> list[str]:
        d = date.today() - timedelta(days=2)
        j = _get(WIKI_URL.format(d=d.strftime("%Y/%m/%d"))).json()
        arts = j["items"][0]["articles"]
        out = []
        for a in arts[:400]:
            name = a["article"]
            if _SKIP_WIKI.match(name):
                continue
            q = name.replace("_", " ")
            if safe_query(q):
                out.append(q)
        return out[:200]

    def _fetch_news(self) -> list[str]:
        out: list[str] = []
        for url in NEWS_FEEDS:
            try:
                txt = _get(url, timeout=15).text
            except requests.RequestException:
                continue
            for block in txt.split("<item>")[1:]:
                m = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", block, re.S)
                if m:
                    t = html.unescape(m.group(1)).strip()
                    t = re.sub(r"[‘’]", "'", t)
                    if safe_query(t):
                        out.append(t.lower())
        return list(dict.fromkeys(out))

    def _fetch_dataset(self, per_source: int = 1200) -> list[str]:
        rng = random.Random()
        out: list[str] = []
        for ds, cfg, split, field, max_row in DATASETS:
            got, tries = 0, 0
            while got < per_source and tries < 40:
                tries += 1
                try:
                    r = _get(DS_ROWS, params={"dataset": ds, "config": cfg, "split": split,
                                               "offset": rng.randrange(0, max_row - 100), "length": 100},
                             timeout=30)
                    for row in r.json().get("rows", []):
                        q = str(row["row"].get(field, "")).strip()
                        if safe_query(q) and len(q.split()) >= 2:
                            out.append(q.lower() if not q.isupper() else q)
                            got += 1
                except (requests.RequestException, ValueError, KeyError):
                    time.sleep(0.5)
        return list(dict.fromkeys(out))

    def _fetch_tranco(self, keep: int = 4000) -> list[str]:
        raw = _get(TRANCO_URL, timeout=90).content
        deny = self.denylist()
        out: list[str] = []
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            with z.open(z.namelist()[0]) as fh:
                for row in csv.reader(io.TextIOWrapper(fh, encoding="utf-8")):
                    if len(row) == 2 and safe_domain(row[1], deny):
                        out.append(row[1].lower())
                        if len(out) >= keep:
                            break
                    if row and row[0].isdigit() and int(row[0]) > 25_000:
                        break
        return out

    def _fetch_crux(self) -> list[str]:
        """Chrome's own top sites (CrUX): sites real Chrome users load most, top-1,000 bucket first.
        Each item is 'host|bucket'. Safety-filtered like every other list."""
        import gzip as _gz
        raw = _gz.decompress(_get(CRUX_URL, timeout=120).content).decode("utf-8", "replace")
        return parse_crux(raw, self.denylist())

    def _fetch_spray(self, tail_keep: int = 90_000, common_top: int = 30_000) -> list[str]:
        """Domains for Spray and Pray: 'c|name' (common: OpenDNS top 10,000 and the first 30,000 of a top-million list) and
        't|name' (a long tail: OpenDNS random 10,000 and a random sample of the rest of the million). Same safety filter as
        every other list."""
        import random as _r
        deny = self.denylist()

        def lines(key: str, timeout: int = 120) -> list[str]:
            return [ln.strip().lower() for ln in _get(SPRAY_URLS[key], timeout=timeout).text.splitlines() if ln.strip()]
        common = [d for d in lines("opendns_top") if safe_domain(d, deny)]
        million = lines("top_million")
        common += [d for d in million[:common_top] if safe_domain(d, deny)]
        tail = [d for d in lines("opendns_random") if safe_domain(d, deny)]
        rest = million[common_top:]
        _r.Random().shuffle(rest)
        tail += [d for d in rest[: tail_keep * 2] if safe_domain(d, deny)][:tail_keep]
        seen: set[str] = set()
        out: list[str] = []
        for tag, pool in (("c", common), ("t", tail)):
            for d in pool:
                if d not in seen:
                    seen.add(d)
                    out.append(f"{tag}|{d}")
        return out

    def _fetch_opennic(self) -> list[str]:
        return parse_opennic_servers(_get(OPENNIC_URL, timeout=40).text)

    def _fetch_deny(self) -> list[str]:
        txt = _get(DENY_URL, timeout=60).text
        out = []
        for ln in txt.splitlines():
            if ln.startswith("0.0.0.0 "):
                host = ln.split()[1].lower()
                if host not in ("0.0.0.0", "localhost"):
                    out.append(host)
        return out


def parse_opennic_servers(html: str) -> list[str]:
    """OpenNIC servers from servers.opennic.org that pass every requirement:

      * status Pass (the table's own reachability/correctness check),
      * no logs kept, or logs anonymized,
      * at least one encrypted protocol: DNSCrypt, DNS over HTTPS or DNS over TLS.

    Returns 'ip|host|location|logs|protocols', no-logs servers first.
    logs is "none" or "anonymized"; protocols is e.g. "DoH+DoT".
    """
    import ipaddress as _ip
    out = []
    for group, body in re.findall(r"<div name='ccg\[([A-Z]+)\]'[^>]*>(.*?)</div>", html, re.S):
        for row in re.findall(r"<p><span>(.*?)</p>", body, re.S):
            feats = set(re.findall(r"title='([^']+)'", row.split("</span>")[0]))
            status = re.search(r"class='stat' title='([^']+)'", row)
            host = re.search(r"<a id='([^']+)'", row)
            ipv4 = re.search(r"class='mono ipv4'[^>]*>([^<&]+)", row)
            place = re.search(r'class=\'host\' title="\(([^)]*)\)', row)
            if not (status and host and ipv4) or status.group(1) != "Passing":
                continue
            logs = "none" if "No logs kept" in feats else "anonymized" if "Logs are anonymized" in feats else ""
            protos = [name for label, name in (("DNScrypt", "DNSCrypt"), ("DNS over HTTP", "DoH"),
                                              ("DNS over TLS", "DoT")) if label in feats]
            if not logs or not protos:
                continue
            ip = ipv4.group(1).strip()
            try:
                _ip.IPv4Address(ip)
            except ValueError:
                continue
            short = host.group(1).replace(".dns.opennic.glue", "")
            loc = place.group(1).strip() if place and place.group(1).strip() else group
            out.append((0 if logs == "none" else 1, f"{ip}|{short}|{loc}|{logs}|{'+'.join(protos)}"))
    return [x for _, x in sorted(out, key=lambda t: t[0])]


def parse_crux(csv_text: str, deny: set[str] | None = None, max_rank: int = 10_000) -> list[str]:
    """'origin,rank' rows -> 'host|rank' for safe sites up to max_rank (1000 = top bucket)."""
    out, seen = [], set()
    for line in csv_text.splitlines()[1:]:
        origin, _, rank = line.rpartition(",")
        if not rank.isdigit() or int(rank) > max_rank or not origin.startswith("https://"):
            continue
        host = origin[len("https://"):].split("/")[0].split(":")[0].lower()
        if host in seen or not safe_domain(host, deny):
            continue
        seen.add(host)
        out.append(f"{host}|{rank}")
    return out
