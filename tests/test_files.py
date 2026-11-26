import http.server
import random
import threading

from legalprivacy.config import Profile, apply_overrides
from legalprivacy.files import KINDS, FileCatalog, human, transfer, upload_size, wanted_size
from legalprivacy.transports import Target


def _fake(items):
    """A stand-in for the Internet Archive: searches give identifiers, metadata gives files."""
    def get_json(url, params=None, timeout=20.0):
        if "advancedsearch" in url:
            return {"response": {"docs": [{"identifier": i} for i in items]}}
        ident = url.rsplit("/", 1)[-1]
        return {"files": items[ident]}
    return get_json


def test_the_catalog_picks_a_real_file_near_a_random_size_within_the_cap_and_weights_the_kinds():
    meta = {"a": [{"name": "a.jpg", "format": "JPEG", "size": "40000"}, {"name": "a-big.jpg", "format": "JPEG", "size": "9000000"},
                  {"name": "a.mp4", "format": "h.264", "size": "9999999999"}, {"name": "dir/x.jpg", "format": "JPEG", "size": "50000"}],
            "b": [{"name": "b.zip", "format": "ZIP", "size": "2000000"}]}
    kinds, sizes = {}, []
    for seed in range(60):
        cat = FileCatalog(random.Random(seed), get_json=_fake(meta))
        p = cat.pick(cap=20_000_000)
        if p:
            kinds[p.kind] = kinds.get(p.kind, 0) + 1
            sizes.append(p.size)
            assert p.url.startswith("https://archive.org/download/") and p.size <= 20_000_000 and "/" not in p.name
    assert kinds.get("image", 0) > kinds.get("video", 0)             # mostly images
    assert len(set(sizes)) > 1 and 9_999_999_999 not in sizes         # sizes vary; nothing over the cap
    assert FileCatalog(random.Random(1), get_json=lambda *a, **k: (_ for _ in ()).throw(OSError("down"))).pick() is None
    assert set(KINDS) == {"image", "video", "archive", "document", "audio"}


def test_wanted_and_upload_sizes_vary_a_lot_and_respect_their_caps():
    rng = random.Random(3)
    w = [wanted_size(rng, 20_000_000) for _ in range(500)]
    u = [upload_size(rng) for _ in range(500)]
    assert max(w) <= 20_000_000 and min(w) >= 30_000 and max(w) / min(w) > 50
    assert max(u) <= 3_000_000 and min(u) >= 10_000 and human(2_500_000) == "2.5 MB" and human(40_000) == "40 KB"


class _H(http.server.BaseHTTPRequestHandler):
    got = []

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "400000")
        self.end_headers()
        try:
            self.wfile.write(b"x" * 400_000)
        except OSError:
            pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        _H.got.append((n, len(set(body[:4000])) > 50))               # random bytes, not a pattern
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def test_a_download_stops_at_its_cap_and_an_upload_sends_that_many_random_bytes():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}/"
    try:
        d = transfer(Target(url=base, kind="download", size=100_000), None, None)
        full = transfer(Target(url=base, kind="download", size=10_000_000), None, None)
        u = transfer(Target(url=base, kind="upload", size=123_456), None, None)
        bad = transfer(Target(url="http://127.0.0.1:1/", kind="download", size=10), None, None)
    finally:
        srv.shutdown()
    assert d.ok and 100_000 <= d.bytes < 400_000 and "downloaded" in d.detail
    assert full.bytes == 400_000
    assert u.ok and u.bytes == 123_456 and _H.got[-1] == (123_456, True) and "uploaded" in u.detail
    assert bad.status is None and bad.error


def test_file_transfers_are_an_engine_that_can_be_switched_off_and_skips_low_data_mode():
    p = Profile(name="t")
    assert "files" in p.active_engines("clearnet") and "files" not in p.active_engines("tor")
    apply_overrides(p, {"extras": {"file_transfers": False}})
    assert "files" not in p.active_engines("clearnet")
    apply_overrides(p, {"extras": {"file_transfers": True, "low_data": True}})
    assert "files" not in p.active_engines("clearnet")


def test_the_scheduler_makes_download_and_upload_targets_with_varied_sizes():
    from legalprivacy.scheduler import Runner, build_lanes
    from legalprivacy.transports import HitResult
    p = Profile(name="t")
    r = Runner(profile=p, lanes=build_lanes(p, ["w"]), wordlist=["w"], sleep_fn=lambda s: None, clock=lambda: 0.0,
               probe_fn=lambda *a: HitResult(200, ""))
    r.rng = random.Random(5)
    r.__dict__["_catalog"] = FileCatalog(random.Random(5), get_json=_fake(
        {"a": [{"name": "a.jpg", "format": "JPEG", "size": "70000"}], "b": [{"name": "b.zip", "format": "ZIP", "size": "900000"}]}))
    ts = [r._files_target() for _ in range(80)]
    assert {t.kind for t in ts} == {"download", "upload"}
    assert len({t.size for t in ts if t.kind == "upload"}) > 3 and all("archive.org" in t.url for t in ts if t.kind == "download")


def test_onion_pages_offer_files_that_become_onion_downloads_over_tor():
    from legalprivacy.scheduler import Runner, build_lanes
    from legalprivacy.transports import HitResult
    p = Profile(name="t")
    r = Runner(profile=p, lanes=build_lanes(p, ["w"]), wordlist=["w"], sleep_fn=lambda s: None, clock=lambda: 0.0,
               probe_fn=lambda *a: HitResult(200, ""))
    html = '<a href="http://abcdefghij.onion/report.pdf">r</a><img src="/pic.jpg"><a href="https://clear.example/x.zip">c</a>'
    r._harvest_onion_files(html, "http://abcdefghij.onion/index.html")
    assert set(r.__dict__["_onion_files"]) == {"http://abcdefghij.onion/report.pdf", "http://abcdefghij.onion/pic.jpg"}
    apply_overrides(p, {"extras": {"file_transfers": False}})
    r.__dict__["_onion_files"].clear()
    r._harvest_onion_files(html, "http://abcdefghij.onion/index.html")
    assert r.__dict__["_onion_files"] == []
