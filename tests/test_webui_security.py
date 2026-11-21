"""Dashboard hardening: odd tokens, bad numbers, oversized bodies, error text, headers (offline)."""
import http.client
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

from legalprivacy.controller import Controller  # noqa: E402
from legalprivacy.webui import UIServer, _load_token, _public_error  # noqa: E402


def _serve():
    c = Controller(os.path.join(tempfile.mkdtemp(), "config.yaml"))
    srv = UIServer(c, port=0)
    threading.Thread(target=srv.httpd.serve_forever, daemon=True).start()
    return c, srv


def _req(srv, method, path, body=None, headers=None, token=True):
    conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
    h = {"X-Token": srv.token} if token else {}
    h.update(headers or {})
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    data = r.read()
    out = (r.status, dict(r.getheaders()), data)
    conn.close()
    return out


def test_non_ascii_token_is_refused_not_a_crash():
    _, srv = _serve()
    try:
        status, _, _ = _req(srv, "GET", "/api/state", headers={"X-Token": "café"})
        assert status == 401
        assert _req(srv, "GET", "/api/state")[0] == 200            # the server is still alive
    finally:
        srv.httpd.shutdown()


def test_bad_numbers_in_the_query_are_a_400_not_a_500():
    _, srv = _serve()
    try:
        for path in ("/api/logs?after=abc", "/api/hits?after=x", "/api/tools/selftest?days=nope",
                     "/api/ml/predict?site=a.com&hour=zz"):
            status, _, body = _req(srv, "GET", path)
            assert status == 400, path
            assert "Traceback" not in body.decode()
    finally:
        srv.httpd.shutdown()


def test_internal_errors_are_logged_and_not_echoed_to_the_browser():
    c, srv = _serve()

    def boom():
        raise KeyError("/home/someone/.legalprivacy/secret-path")
    c.state = boom
    try:
        status, _, body = _req(srv, "GET", "/api/state")
        assert status == 500
        text = body.decode()
        assert "secret-path" not in text and "Traceback" not in text and "KeyError" in text
        assert any("secret-path" in e["message"] for e in c.log.since(0, "error"))   # details stay in the log
    finally:
        srv.httpd.shutdown()
    assert _public_error(RuntimeError("Tor is not installed.")) == "Tor is not installed."


def test_post_body_limits_and_invalid_json():
    _, srv = _serve()
    try:
        assert _req(srv, "POST", "/api/config", body=b"{not json")[0] == 400
        assert _req(srv, "POST", "/api/config", body=b"[1,2]")[0] == 400
        assert _req(srv, "POST", "/api/config", headers={"Content-Length": "2000000"})[0] == 413
        assert _req(srv, "POST", "/api/har/import", headers={"Content-Length": str(60 * 1024 * 1024)})[0] == 413
    finally:
        srv.httpd.shutdown()


def test_page_headers_lock_down_the_dashboard():
    _, srv = _serve()
    try:
        status, hdr, _ = _req(srv, "GET", "/?t=" + srv.token, token=False)
        assert status == 200
        csp = hdr["Content-Security-Policy"]
        for part in ("default-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"):
            assert part in csp
        assert hdr["X-Content-Type-Options"] == "nosniff" and hdr["Referrer-Policy"] == "no-referrer"
        assert hdr["Cache-Control"] == "no-store"
    finally:
        srv.httpd.shutdown()


def test_token_file_is_private():
    if os.name == "nt":
        return
    from legalprivacy.paths import app_dir
    _load_token()
    assert (app_dir() / "ui_token").stat().st_mode & 0o777 == 0o600


def test_saved_settings_and_new_data_folder_are_owner_only():
    if os.name == "nt":
        return
    import legalprivacy.paths as paths
    c = Controller(os.path.join(tempfile.mkdtemp(), "config.yaml"))
    c.apply_config({"daily_max_failures": 7})
    assert os.stat(c.profile_path).st_mode & 0o777 == 0o600
    old = os.environ.get("LEGALPRIVACY_HOME")
    os.environ["LEGALPRIVACY_HOME"] = os.path.join(tempfile.mkdtemp(), "newhome")
    try:
        assert paths.app_dir().stat().st_mode & 0o777 == 0o700
    finally:
        os.environ["LEGALPRIVACY_HOME"] = old


def test_ensure_utf8_console_makes_a_cp1252_stream_printable():
    import io
    from legalprivacy.paths import ensure_utf8_console
    old = sys.stdout
    raw = io.BytesIO()
    sys.stdout = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    try:
        ensure_utf8_console()
        print("\u2696\ufe0f legalPrivacy", flush=True)      # would raise UnicodeEncodeError under cp1252
        assert "legalPrivacy" in raw.getvalue().decode("utf-8")
    finally:
        sys.stdout = old


def test_endpoints_validate_input_and_downloads_work():
    import json
    c, srv = _serve()

    def post(path, obj):
        return _req(srv, "POST", path, body=json.dumps(obj).encode(), headers={"Content-Type": "application/json"})
    try:
        assert post("/api/panic", {"level": "nuclear"})[0] == 400
        assert post("/api/accounts/forget", {"provider": "../../etc/passwd"})[0] == 400
        assert post("/api/accounts/signin", {"provider": "nope"})[0] == 400
        assert post("/api/mylist/scan", {"days": "soon"})[0] == 400
        assert post("/api/mylist/bookmarks", {"urls": "not-a-list"})[0] == 400
        bad = post("/api/config", {"transports": {"tor": {"bridges": ["obfs4 1.2.3.4:1 AA\nSocksPort 0.0.0.0:9"]}}})
        assert bad[0] == 400 and "bridge" in json.loads(bad[2])["error"]
        assert _req(srv, "GET", "/metrics")[0] == 404                      # off by default
        status, hdr, body = _req(srv, "GET", "/api/hits.csv")
        assert status == 200 and body.startswith(b"seq,ts,lane") and "attachment" in hdr["Content-Disposition"]
        assert _req(srv, "GET", "/api/logs.txt")[0] == 200
        assert _req(srv, "GET", "/api/nope")[0] == 404
        har = {"log": {"entries": [{"startedDateTime": "2024-05-01T10:00:00Z",
                                    "request": {"url": "https://www.example.org/private/path?token=SECRET123"}}] * 25}}
        st, _, body = post("/api/har/import", har)
        assert st == 200 and json.loads(body)["present"]
        logs = json.dumps(c.log.since(0))
        assert "SECRET123" not in logs and "private/path" not in logs      # the recording's addresses are never logged
        assert json.loads(_req(srv, "GET", "/api/har")[2])["entries"] == 25
        assert post("/api/har/forget", {"what": "all"})[0] == 200
    finally:
        srv.httpd.shutdown()


def test_package_version_matches_pyproject_and_changelog():
    import re
    root = os.path.join(os.path.dirname(__file__), "..")
    import legalprivacy
    with open(os.path.join(root, "pyproject.toml"), encoding="utf-8") as fh:
        declared = re.search(r'^version = "([^"]+)"', fh.read(), re.M).group(1)
    assert legalprivacy.__version__ == declared
    with open(os.path.join(root, "CHANGELOG.md"), encoding="utf-8") as fh:
        assert re.search(r"^## v(\S+)", fh.read(), re.M).group(1) in (declared, "Unreleased")
