import http.server
import random
import threading

from legalprivacy.scrape import ALL_KINDS, ScrapeJob, extract, kind_of

PAGE = """<html><head><title>Prices</title></head><body>
<table><tr><th>Item</th><th>Price</th></tr><tr><td>Tea</td><td>3</td></tr><tr><td>Cake</td><td>5</td></tr></table>
<img src="/img/cat.png"><video><source src="/media/clip.mp4"></video>
<a href="/docs.html">docs</a> <a href="/private/secret.html">secret</a> <a href="https://other.example/x">out</a>
<a href="/files/report.pdf">report</a> <a href="/files/big.zip">big</a> <a href="mailto:a@b.c">mail</a>
</body></html>"""


def _site(tmp_path):
    (tmp_path / "img").mkdir()
    (tmp_path / "media").mkdir()
    (tmp_path / "files").mkdir()
    (tmp_path / "private").mkdir()
    (tmp_path / "index.html").write_text(PAGE)
    (tmp_path / "docs.html").write_text("<title>Docs</title><table><tr><td>a</td><td>b</td></tr><tr><td>1</td><td>2</td></tr></table>")
    (tmp_path / "private" / "secret.html").write_text("<title>Secret</title>")
    (tmp_path / "img" / "cat.png").write_bytes(b"\x89PNG" + b"0" * 20000)
    (tmp_path / "media" / "clip.mp4").write_bytes(b"0" * 5000)
    (tmp_path / "files" / "report.pdf").write_bytes(b"%PDF" + b"0" * 3000)
    (tmp_path / "files" / "big.zip").write_bytes(b"0" * 3_000_000)
    (tmp_path / "robots.txt").write_text("User-agent: *\nDisallow: /private/\n")
    seen: list[str] = []

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(tmp_path), **k)

        def log_message(self, fmt, *a):
            seen.append(self.path)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


def test_extract_finds_links_files_tables_and_title():
    page = extract(PAGE, "http://site.example/a/")
    assert page["title"] == "Prices" and page["tables"][0] == [["Item", "Price"], ["Tea", "3"], ["Cake", "5"]]
    assert "http://site.example/docs.html" in page["links"] and not any(x.startswith("mailto") for x in page["links"])
    assert "http://site.example/img/cat.png" in page["files"] and "http://site.example/media/clip.mp4" in page["files"]
    assert kind_of("http://x/y.PDF") == "documents" and kind_of("http://x/y.html") is None and "tables" in ALL_KINDS


def test_a_job_saves_tables_and_files_follows_robots_and_stays_on_site_and_mixes_in_noise(tmp_path):
    srv, seen = _site(tmp_path)
    noise = []
    try:
        job = ScrapeJob(f"http://127.0.0.1:{srv.server_port}/index.html", tmp_path / "out", depth=1, max_pages=10, delay=0.01,
                        file_mb=1, mix_noise=True, noise_fn=lambda: noise.append(1), sleep=lambda s: None,
                        rng=random.Random(2))
        st = job.run()
    finally:
        srv.shutdown()
    out = tmp_path / "out"
    assert st["done"] and st["pages"] == 2 and st["tables"] == 2                      # index + docs, one table each
    assert len(list((out / "tables").glob("*.csv"))) == 2
    assert len(list((out / "images").iterdir())) == 1 and len(list((out / "video").iterdir())) == 1
    assert len(list((out / "documents").iterdir())) == 1
    assert not (out / "archives").exists() or not list((out / "archives").iterdir())  # big.zip is over the 1 MB file limit
    assert "/private/secret.html" not in seen and st["skipped_robots"] >= 1          # robots.txt followed
    assert not any("other.example" in e for e in st["errors"]) and noise and st["noise"] == len(noise)


def test_only_the_chosen_kinds_are_taken_and_a_stop_ends_the_job(tmp_path):
    srv, _seen = _site(tmp_path)
    try:
        job = ScrapeJob(f"http://127.0.0.1:{srv.server_port}/index.html", tmp_path / "o2", kinds=["tables"], depth=0,
                        delay=0, mix_noise=False, sleep=lambda s: None)
        st = job.run()
        stopped = ScrapeJob(f"http://127.0.0.1:{srv.server_port}/index.html", tmp_path / "o3", delay=0, mix_noise=False,
                            sleep=lambda s: None)
        stopped.stop.set()
        assert stopped.run()["pages"] == 0
    finally:
        srv.shutdown()
    assert st["tables"] == 1 and st["files"] == 0 and not (tmp_path / "o2" / "images").exists()


def test_a_bad_start_address_is_refused(tmp_path):
    try:
        ScrapeJob("ftp://x", tmp_path)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_the_app_runs_a_scrape_job_and_refuses_bad_input(tmp_path, monkeypatch):
    import os
    import time
    os.environ["LEGALPRIVACY_HOME"] = str(tmp_path / "home")
    from legalprivacy.config import ConfigError
    from legalprivacy.controller import Controller
    srv, _seen = _site(tmp_path)
    c = Controller()
    try:
        st = c.scrape_start({"url": f"http://127.0.0.1:{srv.server_port}/index.html", "kinds": ["tables"], "depth": 0,
                             "delay": 0, "mix_noise": False})
        assert st["job"] is not None
        for _ in range(100):
            if c.scrape_state()["job"]["done"]:
                break
            time.sleep(0.05)
    finally:
        srv.shutdown()
    job = c.scrape_state()["job"]
    assert job["done"] and job["tables"] == 1 and "scrapes" in job["folder"]
    for bad in ({"url": "nope"}, {"url": "https://example.com", "use_proxy": True}):
        try:
            c.scrape_start(bad)
            raise AssertionError("expected ConfigError")
        except ConfigError:
            pass


def test_errors_name_the_real_cause_instead_of_a_cut_off_line():
    import requests
    from legalprivacy.scrape import explain
    inner = OSError("Tunnel connection failed: 403 Forbidden")
    exc = requests.exceptions.ProxyError(f"HTTPSConnectionPool(host='example.com', port=443): Max retries exceeded "
                                         f"with url: / (Caused by ProxyError('Unable to connect to proxy', {inner!r}))")
    exc.__context__ = inner
    msg = explain(exc)
    assert msg.startswith("the proxy refused or dropped the connection") and "403 Forbidden" in msg
    assert "SSLError" not in explain(requests.exceptions.SSLError("x")) and "tampers" in explain(requests.exceptions.SSLError("x"))


def _proxy_job(tmp_path, fails, pool):
    import requests
    from legalprivacy.scrape import ScrapeJob
    used = []

    def nxt(bad):
        return pool.pop(0) if pool else None
    job = ScrapeJob("https://example.com/", tmp_path, depth=0, max_pages=1, delay=0, mix_noise=False,
                    respect_robots=False, proxy="http://198.51.100.1:8080", next_proxy=nxt, sleep=lambda s: None)

    def one(url, stream_to=None, limit=0):
        used.append(job.proxy)
        if job.proxy in fails:
            raise requests.exceptions.ProxyError("Unable to connect to proxy")
        return 200, "<html><title>ok</title></html>", {}
    job._one_get = one
    return job, used


def test_a_proxy_that_fails_in_use_is_swapped_for_another_tested_one(tmp_path):
    job, used = _proxy_job(tmp_path, {"http://198.51.100.1:8080"}, ["http://198.51.100.2:8080"])
    st = job.run()
    assert used == ["http://198.51.100.1:8080", "http://198.51.100.2:8080"] and st["pages"] == 1 and not st["errors"]
    assert st["proxy_switches"] == 1


def test_with_no_working_proxy_left_the_job_stops_instead_of_going_direct(tmp_path):
    bad = {"http://198.51.100.1:8080", "http://198.51.100.2:8080"}
    job, used = _proxy_job(tmp_path, bad, ["http://198.51.100.2:8080"])
    st = job.run()
    assert st["pages"] == 0 and "no working proxy: tried 2" in st["errors"][0] and None not in used


def test_the_scrape_folder_and_its_newest_files_are_shown_and_can_be_opened(tmp_path, monkeypatch):
    import subprocess
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    from legalprivacy.controller import Controller
    c = Controller(str(tmp_path / "config.yaml"))
    job = tmp_path / "scrapes" / "20261127-example.com"
    (job / "images").mkdir(parents=True)
    (job / "images" / "a.png").write_bytes(b"x" * 10)
    (job / "tables.csv").write_text("a,b")
    st = c.scrape_state()
    assert st["last_folder"] == str(job) and {f["name"] for f in st["files"]} == {"images/a.png", "tables.csv"}
    opened, envs = [], []

    class P:
        def __init__(self, args, **k):
            opened.append(args)
            envs.append(k.get("env"))

        def wait(self, timeout=None):
            return 3 if self_fail[0] and len(opened) == 1 else 0     # the first opener fails: the next one is tried
    self_fail = [False]
    monkeypatch.setattr(subprocess, "Popen", P)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr("shutil.which", lambda n: "/usr/bin/" + n if n in ("xdg-open", "nautilus") else None)
    monkeypatch.setenv("DISPLAY", ":0")
    r = c.scrape_open()
    assert r["folder"] == str(job.resolve()) and opened[0] == ["xdg-open", str(job.resolve())] and r["with"] == "xdg-open"
    assert envs[0] is not None                                   # the original environment, not PyInstaller's
    opened.clear()
    self_fail[0] = True
    assert c.scrape_open()["with"] == "nautilus" and [a[0] for a in opened] == ["xdg-open", "nautilus"]
    monkeypatch.delenv("DISPLAY")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    from legalprivacy.config import ConfigError
    try:
        c.scrape_open()
        raise AssertionError("expected ConfigError")
    except ConfigError as exc:
        assert "No desktop session" in str(exc) and str(job.resolve()) in str(exc)


def test_ui_images_tiny_files_and_sizes_are_filtered(tmp_path):
    import struct
    from legalprivacy.scrape import image_size, looks_like_ui

    def png(w, h, pad):
        return b"\x89PNG\r\n\x1a\n" + b"\0\0\0\rIHDR" + struct.pack(">II", w, h) + b"0" * pad
    for d in ("img",):
        (tmp_path / d).mkdir()
    (tmp_path / "img" / "photo.png").write_bytes(png(800, 600, 30000))
    (tmp_path / "img" / "site-logo.png").write_bytes(png(800, 600, 30000))      # UI by name
    (tmp_path / "img" / "pic.png").write_bytes(png(800, 600, 30000))            # UI by its class
    (tmp_path / "img" / "tiny.png").write_bytes(png(800, 600, 100))             # too small a file
    (tmp_path / "img" / "small.png").write_bytes(png(40, 40, 30000))            # too few pixels
    (tmp_path / "img" / "huge.png").write_bytes(png(5000, 5000, 30000))         # over the pixel maximum
    (tmp_path / "img" / "declared.png").write_bytes(png(800, 600, 30000))       # declared 16x16 in the tag
    (tmp_path / "index.html").write_text('<title>t</title><img src="/img/photo.png"><img src="/img/site-logo.png">'
                                         '<img src="/img/pic.png" class="nav-icon"><img src="/img/tiny.png">'
                                         '<img src="/img/small.png"><img src="/img/huge.png">'
                                         '<img src="/img/declared.png" width="16" height="16">')

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(tmp_path), **k)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        st = ScrapeJob(f"http://127.0.0.1:{srv.server_port}/index.html", tmp_path / "out", kinds=["images"], depth=0,
                       delay=0, mix_noise=False, respect_robots=False, sleep=lambda s: None, max_px=4000).run()
    finally:
        srv.shutdown()
    saved = [p.name.split("-")[0] for p in (tmp_path / "out" / "images").iterdir()]
    assert saved == ["photo"] and st["skipped_filter"] == 6 and st["files"] == 1
    assert image_size(tmp_path / "img" / "small.png") == (40, 40)
    assert looks_like_ui("http://x/a/icons.svg") and not looks_like_ui("http://x/a/closeup.jpg")
