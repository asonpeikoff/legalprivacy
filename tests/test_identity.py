"""Identity and config tests (offline, seeded)."""

try:
    import pytest
except ImportError:
    class _RaisesContext:
        def __init__(self, exc): self.exc = exc
        def __enter__(self): return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is None: raise AssertionError(f"DID NOT RAISE {self.exc}")
            return issubclass(exc_type, self.exc)
    import types
    pytest = types.ModuleType("pytest")
    pytest.raises = _RaisesContext

from pathlib import Path

from legalprivacy.config import ConfigError, load_profile

PROFILE = str(Path(__file__).resolve().parents[1] / "profiles" / "example.yaml")
from legalprivacy.identity import headers_for, make_identity, UA_POOL
from random import Random

WORDS = ["weather", "news", "books", "travel", "history", "recipes",
         "fitness", "music", "movies", "coffee", "art", "jobs"]


def test_identity_pins_fingerprint():
    rng = Random(42)
    ident = make_identity(rng, 3, WORDS)
    assert ident.user_agent in [e["ua"] for e in UA_POOL[ident.persona]]
    assert ident.query_taste and set(ident.query_taste) <= set(WORDS)
    # headers must be *the same every time* for one identity — no per-hit rotation
    h1, h2 = headers_for(ident), headers_for(ident)
    assert h1 == h2 and h1["User-Agent"] == ident.user_agent


def test_identities_diverge():
    rng = Random(9)
    personas = {make_identity(rng, i, WORDS).persona for i in range(20)}
    assert len(personas) > 1


def test_search_profile_parses():
    profile = load_profile(PROFILE)
    assert profile.name == "example"
    assert profile.transports["tor"].socks == "127.0.0.1:9050"
    assert profile.engines["search"].budget_per_day == 120
    # clearnet engines never include onion; example profile keeps Tor on for onion only
    assert profile.active_engines("clearnet") == ["search", "crawl", "dns", "packages", "files"]   # default persona: Data scientist
    assert profile.active_engines("tor") == ["onion"]


def test_missing_profile_is_error():
    with pytest.raises(ConfigError):
        load_profile("/nonexistent/profile.yaml")


def test_relay_defaults_never_exit():
    p = load_profile(PROFILE)
    assert p.relay.enabled is False
    assert p.relay.mode == "middle"


# --- 2026 fingerprint rules ---

from legalprivacy.identity import Identity  # noqa: E402
import re  # noqa: E402


def test_no_dnt_header():
    ident = make_identity(Random(3), 7, WORDS)
    h = headers_for(ident)
    assert "DNT" not in h  # DNT was removed from browsers; sending it is a tell


def test_client_hints_only_for_chromium_and_match_version():
    chrome = Identity(id=1, persona="desktop-chrome", user_agent=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"),
        accept_language="en-US,en;q=0.9", pace="normal", query_taste=WORDS,
        chromium=True, platform="Windows")
    h = headers_for(chrome)
    assert 'Chromium";v="156"' in h["Sec-CH-UA"]
    assert '"Google Chrome";v="156"' in h["Sec-CH-UA"]
    assert h["Sec-CH-UA-Mobile"] == "?0"
    assert h["Sec-CH-UA-Platform"] == '"Windows"'

    firefox = Identity(id=2, persona="desktop-firefox", user_agent=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) "
        "Gecko/20100101 Firefox/158.0"),
        accept_language="en-US,en;q=0.9", pace="normal", query_taste=WORDS)
    assert "Sec-CH-UA" not in headers_for(firefox)

    ios = Identity(id=3, persona="mobile", user_agent=(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0.1 "
        "Mobile/15E148 Safari/604.1"),
        accept_language="en-US,en;q=0.9", pace="normal", query_taste=WORDS,
        mobile=True, platform="iOS")
    assert "Sec-CH-UA" not in headers_for(ios)  # Safari never sends hints

    android = Identity(id=4, persona="mobile", user_agent=(
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36"),
        accept_language="en-US,en;q=0.9", pace="normal", query_taste=WORDS,
        chromium=True, mobile=True, platform="Android")
    h = headers_for(android)
    assert h["Sec-CH-UA-Mobile"] == "?1" and h["Sec-CH-UA-Platform"] == '"Android"'
    assert re.search(r"Chrome/(\d+)", android.user_agent).group(1) == "157"


def test_fetch_metadata_headers_present():
    ident = make_identity(Random(11), 8, WORDS)
    h = headers_for(ident)
    assert h["Sec-Fetch-Dest"] == "document"
    assert h["Sec-Fetch-Mode"] == "navigate"
    assert h["Upgrade-Insecure-Requests"] == "1"


def test_gpc_is_pinned_per_identity():
    ident = make_identity(Random(21), 9, WORDS)
    assert headers_for(ident).get("Sec-GPC") == headers_for(ident).get("Sec-GPC")


def test_profile_merges_extra_yaml_keys_gracefully(tmp_path=None):
    import tempfile
    import os
    yaml_content = """
profile:
  name: extra-keys
  engines:
    search:
      budget_per_day: 80
      custom_unsupported_key: "hello"
  transports:
    clearnet:
      extra_junk: 123
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write(yaml_content)
        path = fh.name
    try:
        p = load_profile(path)
        assert p.name == "extra-keys"
        assert p.engines["search"].budget_per_day == 80
    finally:
        os.remove(path)


def test_ua_pool_is_built_from_the_last_two_years_of_releases():
    import datetime as dt
    from legalprivacy import ua_catalog
    from legalprivacy.useragents import build_pool
    # at least two years back (the builder keeps a 60-day margin on top)
    cutoff = (dt.date.today() - dt.timedelta(days=730)).isoformat()
    for table in (ua_catalog.CHROME, ua_catalog.CHROMIUM, ua_catalog.FIREFOX):
        assert len(table) >= 25
        assert min(d for _, d, _ in table) <= cutoff
    pool = build_pool()
    assert set(pool) == {"desktop-chrome", "desktop-firefox", "desktop-chromium", "mobile-chrome", "mobile-iphone"}
    assert not any("Edg/" in e["ua"] for ps in pool.values() for e in ps)
    assert all("iPhone" in e["ua"] and not e["chromium"] for e in pool["mobile-iphone"])   # Safari: no client hints
    assert all(e["ua"].startswith("Mozilla/5.0 (") for ps in pool.values() for e in ps)   # browsers only


def test_most_common_versions_dominate_but_old_ones_stay_possible():
    from legalprivacy import ua_catalog
    w = sorted((x[2] for x in ua_catalog.FIREFOX), reverse=True)
    top3 = sum(w[:3]) / sum(w)
    assert 0.5 < top3 < 0.9
    assert all(x > 0 for x in w)


def test_client_hints_match_chrome_chromium_and_are_absent_for_firefox_and_tools():
    from legalprivacy.identity import Identity, _client_hints
    from legalprivacy.useragents import build_pool
    pool = build_pool()
    chrome = next(e for e in pool["desktop-chrome"] if e["ua"].startswith("Mozilla/5.0 (Windows"))
    ch = Identity(id=1, persona="desktop-chrome", user_agent=chrome["ua"], accept_language="en-US",
                  pace="normal", query_taste=[], chromium=True)
    assert '"Google Chrome"' in _client_hints(ch)["Sec-CH-UA"]
    cr = pool["desktop-chromium"][0]
    chromium = Identity(id=2, persona="desktop-chromium", user_agent=cr["ua"], accept_language="en-US",
                        pace="normal", query_taste=[], chromium=True)
    hints = _client_hints(chromium)["Sec-CH-UA"]
    assert '"Chromium"' in hints and "Google Chrome" not in hints
    ff = Identity(id=3, persona="desktop-firefox", user_agent=pool["desktop-firefox"][0]["ua"],
                  accept_language="en-US", pace="normal", query_taste=[])
    assert _client_hints(ff) == {}


def test_chooser_rotates_per_hour_or_day_and_pins_on_request():
    import random
    from legalprivacy.config import IdentityConfig
    from legalprivacy.useragents import UaChooser, library
    clock = {"t": 1_800_000_000.0}
    cfg = IdentityConfig(ua_mode="rotate", rotate_every="hour")
    ch = UaChooser(random.Random(1), cfg, clock=lambda: clock["t"])
    first = ch.choose()
    assert ch.choose() is first                      # same hour: same browser
    clock["t"] += 3700
    assert ch.choose() is not None                   # next hour: a fresh draw
    own = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
    pin_own = UaChooser(random.Random(2), IdentityConfig(ua_mode="pin", ua_pin="own", own_ua=own))
    assert pin_own.choose()["ua"] == own
    lib_id = library()[0]["id"]
    pin_lib = UaChooser(random.Random(3), IdentityConfig(ua_mode="pin", ua_pin=lib_id))
    assert pin_lib.choose()["id"] == lib_id


def test_identity_settings_round_trip_and_validate():
    from legalprivacy.config import Profile, apply_overrides, profile_to_dict
    p = Profile(name="t")
    apply_overrides(p, {"identity": {"ua_mode": "pin", "ua_pin": "own", "own_ua": "Mozilla/5.0 X"}})
    assert p.identity.ua_mode == "pin" and profile_to_dict(p)["profile"]["identity"]["own_ua"] == "Mozilla/5.0 X"


# ── plain-HTTP lane: the request looks like a browser's on the wire (measured against Chromium 153) ──────────────────
CHROMIUM_NAV_ORDER = ["Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                      "Upgrade-Insecure-Requests", "User-Agent", "Accept-Language", "Accept", "Sec-Fetch-Site",
                      "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding"]


def _raw_request(identity, path="/", referer=None):
    """Make the plain lane fetch a local server and return the raw request head it sent (as header lines)."""
    import socket
    import threading
    from legalprivacy.transports import ClearnetTransport, Target
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got = []

    def serve():
        c, _ = srv.accept()
        c.settimeout(2)
        data = b""
        while b"\r\n\r\n" not in data:
            data += c.recv(4096)
        got.append(data.decode("latin1"))
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        c.close()
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    url = f"http://127.0.0.1:{srv.getsockname()[1]}{path}"
    res = ClearnetTransport().hit(identity, Target(url=url, referer=referer, timeout=5.0))
    t.join(3)
    srv.close()
    assert res.status == 200
    return got[0].split("\r\n")[:-2], url


def _chromium_identity():
    for i in range(60):
        ident = make_identity(Random(i), i, WORDS)
        if ident.chromium and "Chrome/" in ident.user_agent:
            return ident
    raise AssertionError("no Chromium identity in the library")


def test_plain_lane_sends_chromiums_header_order_and_values():
    ident = _chromium_identity()
    lines, _ = _raw_request(ident)
    names = [ln.split(":", 1)[0] for ln in lines[1:]]
    assert names == [n for n in CHROMIUM_NAV_ORDER]
    h = dict(ln.split(": ", 1) for ln in lines[1:])
    assert h["Accept"].startswith("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng")
    assert h["Sec-Fetch-Site"] == "none" and h["Sec-Fetch-User"] == "?1" and h["Connection"] == "keep-alive"
    assert h["User-Agent"] == ident.user_agent and h["Accept-Language"] == ident.accept_language
    assert "python-requests" not in " ".join(lines)
    from legalprivacy.identity import accept_encoding
    assert h["Accept-Encoding"] == accept_encoding() and h["Accept-Encoding"].startswith("gzip, deflate")


def test_a_click_through_carries_referer_and_matching_fetch_metadata():
    from legalprivacy.identity import navigation_headers, referer_value
    ident = _chromium_identity()
    lines, _ = _raw_request(ident, "/x", referer="http://127.0.0.1:1/some/page?q=1")
    names = [ln.split(":", 1)[0] for ln in lines[1:]]
    assert names == CHROMIUM_NAV_ORDER[:-1] + ["Referer", "Accept-Encoding"]       # Referer sits before Accept-Encoding
    # same origin: the whole address, same-origin; another site: just the origin, cross-site; https to http: nothing
    h = navigation_headers(ident, "https://a.example.com/x", "https://a.example.com/p?q=1")
    assert h["Sec-Fetch-Site"] == "same-origin" and h["Referer"] == "https://a.example.com/p?q=1"
    h = navigation_headers(ident, "https://www.example.org/x", "https://a.example.com/p?q=1")
    assert h["Sec-Fetch-Site"] == "cross-site" and h["Referer"] == "https://a.example.com/"
    h = navigation_headers(ident, "https://b.example.com/x", "https://a.example.com/p")
    assert h["Sec-Fetch-Site"] == "same-site"
    assert referer_value("http://a.example.com/", "https://a.example.com/p") == ""
    assert "Referer" not in navigation_headers(ident, "http://a.example.com/", "https://a.example.com/p")


def test_encodings_are_only_claimed_when_they_can_be_decoded(monkeypatch):
    import urllib3.util.request as req
    from legalprivacy.identity import accept_encoding
    monkeypatch.setattr(req, "ACCEPT_ENCODING", "gzip,deflate,br,zstd")
    assert accept_encoding() == "gzip, deflate, br, zstd"                  # what Chrome says, once brotli and zstd are installed
    monkeypatch.setattr(req, "ACCEPT_ENCODING", "gzip,deflate")
    assert accept_encoding() == "gzip, deflate"
