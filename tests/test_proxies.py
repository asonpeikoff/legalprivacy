import random
import time

from legalprivacy.proxies import DEFAULT_SOURCES, TEST_URL, ProxyManager, parse

GOOD = "fl=1\nh=www.cloudflare.com\nip=198.51.100.7\nts=1\n"


def test_parse_picks_out_public_addresses_from_text_and_pages():
    text = """<td>8.8.4.4:8080</td> socks5://9.9.9.9:1080 http://1.2.3.4:3128
    192.168.1.1:80 127.0.0.1:9050 10.0.0.2:8000 999.1.1.1:80 5.5.5.5:99999 8.8.4.4:8080 36.93.56.58:8080:Indonesia"""
    assert parse(text) == ["http://8.8.4.4:8080", "socks5://9.9.9.9:1080", "http://1.2.3.4:3128", "http://36.93.56.58:8080"]
    assert parse("") == [] and parse(None) == []


def _manager(tmp_path, behaviours, max_ms=300):
    """behaviours: proxy -> 'good' | 'slow' | 'dead' | 'wrong' | 'transparent'."""
    def get(url, proxy, timeout):
        if url != TEST_URL:                                   # a source list
            return 200, "\n".join(k.split("//")[1] for k in behaviours)
        if proxy is None:
            return 200, "h=www.cloudflare.com\nip=203.0.113.9\n"
        b = behaviours[proxy]
        if b == "dead":
            raise OSError("connection refused")
        if b == "slow":
            time.sleep(0.5)
        if b == "wrong":
            return 200, "<html>pay us</html>"
        if b == "transparent":
            return 200, "h=www.cloudflare.com\nip=203.0.113.9\n"
        return 200, GOOD
    m = ProxyManager(tmp_path / "p.json", get=get, rng=random.Random(1))
    m.max_ms = max_ms
    return m


def test_only_proxies_that_prove_themselves_are_kept_and_the_rest_are_thrown_out(tmp_path):
    beh = {"http://8.8.8.8:80": "good", "http://8.8.4.4:80": "slow", "http://9.9.9.9:80": "dead",
           "http://1.1.1.1:80": "wrong", "http://2.2.2.2:80": "transparent", "http://3.3.3.3:80": "good"}
    m = _manager(tmp_path, beh)
    res = m.refresh(workers=4)
    assert res["tested"] == 6 and res["kept"] == 2 and res["thrown_out"] == 4
    assert {r["proxy"] for r in m.good()} == {"http://8.8.8.8:80", "http://3.3.3.3:80"}
    assert m.pick() in {"http://8.8.8.8:80", "http://3.3.3.3:80"}
    assert m.sources[DEFAULT_SOURCES[0][0]]["found"] == 6


def test_a_proxy_that_worked_before_gets_one_more_try_then_goes(tmp_path):
    beh = {"http://8.8.8.8:80": "good"}
    m = _manager(tmp_path, beh)
    m.refresh()
    assert len(m.good()) == 1
    beh["http://8.8.8.8:80"] = "dead"
    m.clock = lambda: time.time() + 10 * 3600                 # long enough for a retest
    m.refresh()
    assert "http://8.8.8.8:80" in m.proxies and m.proxies["http://8.8.8.8:80"]["fails"] == 1
    m.clock = lambda: time.time() + 20 * 3600
    m.refresh()
    assert m.proxies == {} and m.pick() is None


def test_extra_sources_and_the_saved_state_survive_a_restart(tmp_path):
    m = _manager(tmp_path, {"http://8.8.8.8:80": "good"})
    m.add_source("https://example.com/list")
    m.refresh()
    again = ProxyManager(tmp_path / "p.json")
    assert again.extra_sources == ["https://example.com/list"] and len(again.good()) == 1
    try:
        m.add_source("ftp://x")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    again.remove_source("https://example.com/list")
    assert again.extra_sources == []


def test_the_app_exposes_the_proxy_list_and_rejects_a_bad_source(tmp_path, monkeypatch):
    import os
    os.environ["LEGALPRIVACY_HOME"] = str(tmp_path)
    from legalprivacy.config import ConfigError
    from legalprivacy.controller import Controller
    c = Controller()
    st = c.proxy_state()
    assert st["kept"] == 0 and len(st["sources"]) == len(DEFAULT_SOURCES) and "strangers" in st["warning"]
    assert c.proxy_source("add", "https://example.com/list.txt")["extra_sources"] == ["https://example.com/list.txt"]
    assert c.proxy_source("remove", "https://example.com/list.txt")["extra_sources"] == []
    for bad in (("add", "ftp://x"), ("zap", "https://x.example")):
        try:
            c.proxy_source(*bad)
            raise AssertionError("expected ConfigError")
        except ConfigError:
            pass
