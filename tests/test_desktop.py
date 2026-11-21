import os
import sys
import tempfile
import types
from legalprivacy import desktop


def fake_webview(calls):
    m = types.ModuleType("webview")

    class W:
        def destroy(self):
            calls.append("destroy")

    def create_window(title, url, **kw):
        calls.append(("window", title, url, kw.get("width")))
        return W()

    m.create_window = create_window
    m.start = lambda: calls.append("start")
    return m


def test_window_opens_the_dashboard_and_shuts_down(monkeypatch):
    calls = []
    monkeypatch.setitem(sys.modules, "webview", fake_webview(calls))
    rc = desktop.main(os.path.join(tempfile.mkdtemp(), "p.json"), port=0)
    assert rc == 0 and "start" in calls
    win = next(c for c in calls if isinstance(c, tuple))
    assert win[0] == "window" and win[1] == "legalPrivacy" and win[2].startswith("http://127.0.0.1:") and "?t=" in win[2]


def test_without_pywebview_it_falls_back_to_the_browser_dashboard(monkeypatch):
    monkeypatch.setitem(sys.modules, "webview", None)          # makes `import webview` fail
    seen = {}
    monkeypatch.setattr(desktop, "run_ui", lambda profile_path=None, port=None: seen.setdefault("ran", True) and 0)
    assert desktop.main(os.path.join(tempfile.mkdtemp(), "p.json")) == 0 and seen["ran"]
