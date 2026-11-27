import json

from legalprivacy import geoban
from legalprivacy.config import ExtrasConfig


def mk(tmp_path, resolve=None, rows=None):
    g = geoban.GeoBan(path=tmp_path / "g.json", resolve=resolve or (lambda h: ["1.2.3.4"]))
    if rows is not None:
        found = g.parse(rows)
        (tmp_path / "g.json").write_text(json.dumps({"month": "2026-11", "at": 1e12, "ranges": found}))
        g.load()
    return g


ROWS = [["20.0.0.0", "20.0.0.255", "NA", "US", "Virginia", "Ashburn"],
        ["20.0.1.0", "20.0.1.255", "NA", "US", "Virginia", "Reston"],
        ["30.30.0.0", "30.30.0.9", "NA", "US", "Ohio", "X"],
        ["2001:db8::", "2001:db8::ff", "NA", "US", "Virginia", "X"],
        ["50.0.0.0", "50.0.0.9", "NA", "CA", "Virginia", "X"]]


def test_parse_merges_and_filters():
    assert geoban.GeoBan.parse(ROWS) == [[335544320, 335544831]]


def test_government_and_virginia(tmp_path):
    g = mk(tmp_path, rows=ROWS)
    assert g.reason("11.5.5.5") == "a government range"
    assert g.reason("20.0.0.7") == "Virginia"
    assert g.reason("20.0.1.200") == "Virginia"
    assert g.reason("20.0.2.1") is None
    assert g.reason("9.9.9.9") is None and g.reason("2001:db8::1") is None and g.reason("junk") is None
    assert g.reason("50.0.0.5") is None


def test_host_reason_and_cache(tmp_path):
    calls = []

    def res(h):
        calls.append(h)
        return ["20.0.0.9"] if h == "va.example" else ["8.8.4.4"]
    g = mk(tmp_path, resolve=res, rows=ROWS)
    assert g.host_reason("va.example") == "Virginia"
    assert g.host_reason("va.example") == "Virginia" and calls == ["va.example"]
    assert g.host_reason("ok.example") is None
    assert g.host_reason("abc.onion") is None and g.host_reason("11.1.1.1") == "a government range"


def test_unresolvable_not_banned(tmp_path):
    def boom(h):
        raise OSError("nx")
    assert mk(tmp_path, resolve=boom, rows=ROWS).host_reason("nx.example") is None


def test_relays_and_tor_excludes(tmp_path):
    g = mk(tmp_path, rows=ROWS)
    data = {"relays": [{"fingerprint": "A" * 40, "or_addresses": ["20.0.0.5:9001"]},
                       {"fingerprint": "B" * 40, "or_addresses": ["8.8.8.8:443", "[2001:db8::1]:443"]}]}

    class R:
        def __enter__(s): return s
        def __exit__(s, *a): return False
        def read(s): return json.dumps(data).encode()
    assert g.update_relays(opener=lambda *a, **k: R()) == 1
    ex = g.tor_excludes()
    assert "$" + "A" * 40 in ex and "11.0.0.0/8" in ex and "$" + "B" * 40 not in ex
    assert geoban.GeoBan(path=tmp_path / "g.json").relays == ["A" * 40]


def test_default_on():
    assert ExtrasConfig().geoban is True
