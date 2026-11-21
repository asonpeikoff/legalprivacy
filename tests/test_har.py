"""HAR import: Chrome/Firefox flavours, bad input, limits, and that nothing but time + site is kept."""
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from legalprivacy import har  # noqa: E402
from legalprivacy.har import HarError, HarStore, parse_har, parse_time, site_name, summary  # noqa: E402

SECRET_PATH = "/account/secret-token-9f3a?session=hunter2"


def _entry(ts, url, **extra):
    e = {"startedDateTime": ts, "time": 12.5, "request": {"method": "GET", "url": url,
         "headers": [{"name": "Cookie", "value": "sid=SUPERSECRETCOOKIE"}], "cookies": [], "queryString": []},
         "response": {"status": 200, "content": {"text": "BODYTEXT"}}}
    e.update(extra)
    return e


def _file(entries, creator="WebInspector"):
    return json.dumps({"log": {"version": "1.2", "creator": {"name": creator}, "entries": entries}})


CHROME = _file([
    _entry("2024-05-01T10:00:05.123Z", "https://www.example.com" + SECRET_PATH, serverIPAddress="93.184.216.34"),
    _entry("2024-05-01T10:00:40.000Z", "https://cdn.example.com/a.js"),
    _entry("2024-05-01T10:00:50.000Z", "https://news.bbc.co.uk/x?q=1"),
    _entry("2024-05-01T10:03:10.000Z", "https://example.org/"),
    _entry("2024-05-01T10:03:11.000Z", "data:image/png;base64,AAAA"),
    _entry("2024-05-01T10:03:12.000Z", "http://192.168.1.10/admin"),
    {"bogus": True},
])
FIREFOX = _file([
    _entry("2024-05-01T12:00:05.000+02:00", "https://www.example.com/"),
    _entry("2024-05-01T12:00:30.500+02:00", "https://api.example.com/v1"),
    _entry("2024-05-01T05:30:00.000-05:00", "https://example.org/"),
], creator="Firefox")


def test_time_formats_and_offsets():
    z = parse_time("2024-05-01T10:00:00.000Z")
    assert parse_time("2024-05-01T12:00:00.000+02:00") == z
    assert parse_time("2024-05-01T05:00:00-05:00") == z
    assert parse_time("2024-05-01T10:00:00+0000") == z
    assert parse_time("garbage") is None and parse_time(None) is None


def test_site_names():
    assert site_name("https://a.b.example.com/p?q=1") == "example.com"
    assert site_name("https://news.bbc.co.uk/") == "bbc.co.uk"
    assert site_name("http://user:pw@www.example.org:8080/x") == "example.org"
    assert site_name("data:text/plain,hi") is None and site_name("http://127.0.0.1/") is None
    assert site_name("http://localhost/") is None and site_name(5) is None


def test_chrome_flavour():
    d = parse_har(CHROME)
    assert d["entries"] == 4 and d["skipped"] == 3
    mins = sorted(d["minutes"].items())
    assert [v for _, v in mins] == [[3, 2], [1, 1]]       # 3 requests to 2 sites, then 1 to 1
    assert dict(map(tuple, d["top_hosts"]))["example.com"] == 2
    assert d["last"] - d["first"] > 180


def test_firefox_flavour_offsets_land_in_same_minutes():
    d = parse_har(FIREFOX)
    assert d["entries"] == 3
    assert sorted(v[0] for v in d["minutes"].values()) == [1, 2]     # 12:00+02:00 == 10:00Z; 05:30-05:00 == 10:30Z


def test_nothing_but_time_and_site_is_kept():
    d = parse_har(CHROME)
    blob = json.dumps(d, default=str)
    for secret in ("secret-token", "hunter2", "SUPERSECRETCOOKIE", "BODYTEXT", "93.184.216.34", "a.js",
                   "/account", "https://", "192.168"):
        assert secret not in blob
    p = Path(tempfile.mkdtemp()) / "har.json"
    store = HarStore(p)
    store.save(d)
    text = p.read_text()
    assert "hunter2" not in text and "SUPERSECRETCOOKIE" not in text and "https://" not in text
    assert store.load()["entries"] == 4


def test_errors_are_plain_and_do_not_quote_the_file():
    for bad, frag in [("", "empty"), ("{not json SECRETWORD", "valid JSON"), ("[]", "HAR"),
                      ('{"log": {"entries": "x"}}', "HAR"), ('{"log": {"entries": []}}', "No usable"),
                      (b"\xff\xfe\x00bad", "text")]:
        with pytest.raises(HarError) as ei:
            parse_har(bad)
        assert frag in str(ei.value) and "SECRETWORD" not in str(ei.value)


def test_partial_file_with_some_bad_entries_still_imports():
    f = _file([{"startedDateTime": "nope", "request": {"url": "https://a.example.com/"}},
               {"startedDateTime": "2024-05-01T10:00:00Z", "request": "x"},
               _entry("2024-05-01T10:00:00Z", "https://ok.example.com/")])
    d = parse_har(f)
    assert d["entries"] == 1 and d["skipped"] == 2


def test_limits(monkeypatch):
    monkeypatch.setattr(har, "MAX_BYTES", 100)
    with pytest.raises(HarError, match="50 MB"):
        parse_har("x" * 101)
    monkeypatch.setattr(har, "MAX_BYTES", 50 * 1024 * 1024)
    monkeypatch.setattr(har, "MAX_ENTRIES", 2)
    with pytest.raises(HarError, match="more than"):
        parse_har(CHROME)


def test_denylist_filters_top_hosts_only_and_forget(tmp_path):
    d = parse_har(CHROME, denylist={"example.org"})
    assert "example.org" not in [h for h, _ in d["top_hosts"]]
    store = HarStore(tmp_path / "har.json")
    store.save(d)
    store.forget("hosts")
    s = summary(store.load())
    assert s["present"] and s["top_hosts"] == [] and s["entries"] == 4
    store.forget()
    assert store.load() is None and summary(None) == {"present": False}


def test_har_endpoints_roundtrip():
    import threading
    sys.path.insert(0, os.path.dirname(__file__))
    from test_controller import _call, _ctl
    from legalprivacy.webui import UIServer
    c = _ctl()
    c.har = HarStore(Path(tempfile.mkdtemp()) / "har.json")
    srv = UIServer(c, port=0)
    threading.Thread(target=srv.httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.port}"
    try:
        assert _call(base, srv.token, "/api/har")[1] == {"present": False}
        code, bad = _call(base, srv.token, "/api/har/import", {"text": "{nope"})
        assert code == 400 and "valid JSON" in bad["error"]
        code, ok = _call(base, srv.token, "/api/har/import", {"text": CHROME})
        assert code == 200 and ok["present"] and ok["entries"] == 4
        code, raw = _call(base, srv.token, "/api/har/import", json.loads(FIREFOX))      # the HAR object itself
        assert code == 200 and raw["entries"] == 3
        assert _call(base, srv.token, "/api/har/forget", {})[1] == {"present": False}
    finally:
        srv.httpd.shutdown()


def test_absurdly_nested_json_is_a_plain_error_not_a_crash():
    with pytest.raises(HarError):
        parse_har("[" * 100000)


def test_a_recording_spanning_decades_is_refused_before_it_can_eat_memory():
    es = [{"startedDateTime": "1971-01-01T00:00:00Z", "request": {"url": "https://a.example.com/"}},
          {"startedDateTime": "2099-01-01T00:00:00Z", "request": {"url": "https://b.example.com/"}}]
    with pytest.raises(HarError):
        parse_har({"log": {"entries": es}})
