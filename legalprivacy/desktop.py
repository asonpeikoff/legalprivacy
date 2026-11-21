"""Desktop window for legalPrivacy: the same dashboard, in its own native window instead of a browser tab.

Uses pywebview (optional: `pip install "legalprivacy[desktop]"`), which shows the dashboard with the web view
that comes with the operating system (Edge WebView2 on Windows, WebKit on macOS, GTK/Qt WebKit on Linux).
Without pywebview this falls back to the normal browser dashboard. Closing the window quits the app.
"""
from __future__ import annotations

import sys
import threading

from .controller import Controller
from .webui import UIServer, run_ui, running_instance, start_services

TITLE = "legalPrivacy"


def main(profile_path: str | None = None, port: int | None = None) -> int:
    from .paths import ensure_utf8_console
    ensure_utf8_console()
    try:
        import webview
    except ImportError:
        print('The desktop window needs pywebview:  pip install "legalprivacy[desktop]"\n'
              "Opening the dashboard in your browser instead.", file=sys.stderr)
        return run_ui(profile_path, port)

    ctl = Controller(profile_path)
    want = port if port is not None else int(ctl.app.get("port", 8765))
    other = running_instance(want) if port is None else None
    srv = None
    if other:                                    # already running: just show a window onto it
        url = other
    else:
        srv = UIServer(ctl, want)
        url = srv.url
        start_services(ctl)
        threading.Thread(target=srv.serve_forever, daemon=True, name="webui-main").start()
    window = webview.create_window(TITLE, url, width=1240, height=860, min_size=(900, 600))
    if srv is not None:
        def _close_on_quit():                    # the page's Quit button closes the window too
            srv.quit_event.wait()
            try:
                window.destroy()
            except Exception:
                pass
        threading.Thread(target=_close_on_quit, daemon=True, name="desktop-quit").start()
    try:
        webview.start()                          # blocks until the window is closed
    finally:
        if srv is not None:
            srv.quit_event.set()
            ctl.stop(stop_tor=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
