"""Query/domain source tests — offline, with canned feed data."""
import os
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

from legalprivacy.domains import FALLBACK_DOMAINS, DomainPool, looks_browsable  # noqa: E402
from legalprivacy.engines import CrawlTargetFactory, extract_result_links  # noqa: E402
from legalprivacy.feeds import FeedStore  # noqa: E402
from legalprivacy.queries import QuerySource, headline_to_query  # noqa: E402
from legalprivacy.safety import safe_domain, safe_query  # noqa: E402

CANNED = {
    "deny": lambda: ["badsite.example", "pornhub.com"],
    "trends": lambda: ["supreme court", "estonia vs bulgaria"],
    "wiki": lambda: ["Ansel Adams", "Jensen Huang (executive)"],
    "news": lambda: ["Uk lost more than it gained from Brexit, Burnham to say"],
    "dataset": lambda: ["how long does a wire transfer take", "is temecula ca a good place to live?"]
    + [f"what is topic number {i}" for i in range(300)],
    "tranco": lambda: ["google.com", "akamaiedge.net", "pornhub.com", "wikipedia.org", "x7f3kq9z-a.com",
                       "bbc.co.uk", "example.gov"],
}


def _store():
    return FeedStore(None, path=Path(tempfile.mkdtemp()) / "f.json", fetchers=dict(CANNED), bundled=False)


def test_feed_store_refresh_caches_and_reports_status():
    st = _store()
    st.refresh()
    assert st.items("trends") == ["supreme court", "estonia vs bulgaria"]
    assert all(s["count"] and not s["stale"] and not s["error"] for s in st.status())
    st2 = FeedStore(None, path=st.path, fetchers=dict(CANNED), bundled=False)   # loads from disk
    assert st2.items("dataset")


def test_feed_failure_keeps_cache_and_reports_error():
    st = _store()
    st.refresh()
    st.fetchers["news"] = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    st.refresh(force=True, only=["news"])
    assert st.items("news") and "boom" in [s for s in st.status() if s["name"] == "news"][0]["error"]


def test_query_mix_uses_all_sources_and_never_repeats_quickly():
    st = _store()
    st.refresh()
    q = QuerySource(random.Random(1), st, words=["apple", "cobalt", "zz"])
    seen, origins = [], set()
    for _ in range(300):
        s, o = q.next()
        seen.append(s)
        origins.add(o)
    assert {"live", "dataset", "builtin"} <= origins
    assert all(safe_query(s) or o == "refine" for s, o in [(x, "x") for x in seen])
    window = seen[-50:]
    assert len(set(window)) > 30


def test_builtin_list_is_a_minority():
    st = _store()
    st.refresh()
    q = QuerySource(random.Random(2), st)
    n = sum(q.next()[1] == "builtin" for _ in range(2000))
    assert n < 2000 * 0.2


def test_headline_becomes_keyword_query():
    assert headline_to_query("Uk lost more than it gained from Brexit, Burnham to say") \
        == "Uk lost gained Brexit Burnham"


def test_unsafe_queries_and_domains_rejected():
    for bad in ("how to make a bomb", "free porn", "buy cocaine online", "best online casino"):
        assert not safe_query(bad)
    assert safe_query("sourdough bread recipe")
    assert not safe_domain("example.gov") and not safe_domain("akamaiedge.net")
    assert not safe_domain("sub.badsite.example", {"badsite.example"})


def test_domain_pool_real_domains_only_and_browsable_filter():
    st = _store()
    st.refresh()
    d = DomainPool(random.Random(3), st)
    picks = {d.pick() for _ in range(200)}
    assert picks <= {"google.com", "wikipedia.org", "x7f3kq9z-a.com", "bbc.co.uk"}
    assert not looks_browsable("x7f3kq9z-a.com") and looks_browsable("wikipedia.org")
    assert all(looks_browsable(d.pick(browsable=True)) for _ in range(50))
    assert DomainPool(random.Random(1)).pick() in FALLBACK_DOMAINS


def test_serp_result_extraction_unwraps_redirects():
    html = ('<a href="/l/?uddg=https%3A%2F%2Fwww.example.org%2Fa">How to grow tomatoes indoors</a>'
            '<a href="https://duckduckgo.com/settings">Settings and privacy</a>'
            '<a href="https://www.instagram.com/duckduckgo/">Follow us on Instagram</a>'
            '<a href="/url?q=https://news.example.com/story&sa=U">Local news story about gardens</a>'
            '<a href="https://www.example.org/b">Another page on the same site</a>'
            '<a href="https://short.example.net/">Next</a>')
    assert extract_result_links(html, "https://html.duckduckgo.com/html/?q=x") == [
        "https://www.example.org/a", "https://news.example.com/story"]


def test_crawler_skips_anchors_assets_and_account_pages():
    f = CrawlTargetFactory(rng=random.Random(1), seeds=[])
    html = ('<a href="#cite-1">a</a><a href="/logo.png">b</a><a href="/login">c</a>'
            '<a href="/wiki/Real_Page">d</a>')
    for _ in range(10):
        assert f.next_from(html, "https://x.example/wiki/Start").url == "https://x.example/wiki/Real_Page"


def test_shipped_snapshot_works_offline_without_fetching():
    calls = []
    st = FeedStore(None, path=Path(tempfile.mkdtemp()) / "f.json",
                   fetchers={k: (lambda k=k: calls.append(k) or []) for k in CANNED})
    assert st.items("dataset") and st.items("tranco") and len(st.denylist()) > 1000
    st.refresh()                                  # not forced: snapshot is fresh, nothing fetched
    assert calls == [] and not st.path.exists()
    assert all(s["origin"] == "shipped snapshot" for s in st.status())


def test_the_header_logo_is_a_plain_wordmark_and_the_character_art_is_not_shipped():
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    web = root / "legalprivacy" / "web"
    html = (web / "index.html").read_text(encoding="utf-8")
    box = html.split('class="logos"', 1)[1].split("</span>", 1)[0]
    assert len(re.findall(r"<img[^>]*>", box)) == 1 and (web / "logo_trad.png").exists()
    assert not (web / "logos" / "egg").exists() and not list(web.glob("logo_v*.png")) and not (root / "docs/logo/variants").exists()
    assert "Konami" not in html and "ArrowUp" not in html


def test_nudges_keep_the_mix_at_100_and_never_go_negative():
    from legalprivacy.mixnudge import nudge_phones, nudge_shares
    w = {"browser": 100.0, "plain": 0.0, "onion": 40.0}
    up = nudge_shares(w, "onion", 1)
    assert abs(sum(up.values()) - 100) < 0.11 and up["onion"] > 28.6 and up["browser"] < 71.4
    s = {"browser": 100.0, "plain": 0.0, "onion": 0.0}
    for _ in range(12):
        s = nudge_shares(s, "browser", -1)
        assert all(v >= 0 for v in s.values()) and abs(sum(s.values()) - 100) < 0.11
    assert s["browser"] == 0.0
    for _ in range(12):
        s = nudge_shares(s, "plain", 1)
    assert s["plain"] == 100.0
    assert nudge_phones(0.95, 1) == 1.0 and nudge_phones(0.05, -1) == 0.0


def test_nudge_mix_saves_and_refuses_onion_without_tor(tmp_path, monkeypatch):
    import pytest
    from legalprivacy.config import ConfigError
    from legalprivacy.controller import Controller
    monkeypatch.setenv("HOME", str(tmp_path))
    c = Controller(str(tmp_path / "p.yaml"))
    m = c.nudge_mix("browser", -1)
    assert m["shares"]["browser"] == 90.0 and c.profile.traffic.plain == 10.0
    with pytest.raises(ConfigError):
        c.nudge_mix("onion", 1)
    with pytest.raises(ConfigError):
        c.nudge_mix("bogus", 1)
