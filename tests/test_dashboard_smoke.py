"""The dashboard draws without script errors while noise is running (a drawing bug once showed
"disconnected" and left the Tor tab empty). Needs Playwright and a Chromium; skipped otherwise."""
import threading
import time

import pytest

from legalprivacy.controller import Controller
from legalprivacy.transports import HitResult
from legalprivacy.webui import UIServer


def test_dashboard_draws_while_running_and_tor_tab_fills(tmp_path, monkeypatch):
    pw = pytest.importorskip("playwright.sync_api")
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    ctl = Controller(str(tmp_path / "config.yaml"))
    ctl.wizard({"rate_mode": "steady", "level": 5, "tor": "off", "autostart": False})
    srv = UIServer(ctl, 0)
    threading.Thread(target=srv.httpd.serve_forever, daemon=True).start()
    try:
        ctl.start()
        if ctl.runner is not None:                                  # never touch the network in the test
            ctl.runner.probe_fn = lambda *a: HitResult(200, "")
        with pw.sync_playwright() as p:
            from legalprivacy.browser import find_browser
            exe = find_browser()
            if not exe:
                pytest.skip("no Chrome/Chromium found")
            try:
                browser = p.chromium.launch(executable_path=exe)
            except Exception as exc:
                pytest.skip(f"no Chromium for Playwright: {exc}")
            page = browser.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.goto(srv.url)
            deadline = time.time() + 15
            while time.time() < deadline and page.eval_on_selector("#pRun", "e => e.textContent") in ("…", ""):
                page.wait_for_timeout(200)
            page.wait_for_timeout(2500)                              # a few polls
            assert page.eval_on_selector("#pRun", "e => e.textContent") == "Running"
            assert page.evaluate("() => { try { render(); return 'ok' } catch (e) { return String(e) } }") == "ok"
            page.click("#nav button[data-t=tor]")
            page.wait_for_timeout(500)
            assert page.eval_on_selector("#tState", "e => e.textContent").strip()   # the Tor status is filled in
            assert not errors, errors
            browser.close()
    finally:
        ctl.stop()
        srv.httpd.shutdown()
