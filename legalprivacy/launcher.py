"""legalPrivacy launcher — double-click me.

Opens the dashboard in your browser (first run: 3 quick questions, then it
starts). Use --text for the old terminal menu.
"""
from __future__ import annotations

import argparse
import os
import sys
import traceback


def _pause_on_windows_error() -> None:
    # A double-clicked console closes instantly on crash; keep it readable.
    if sys.platform == "win32" and sys.stdin and sys.stdin.isatty():
        try:
            input("\nPress Enter to close…")
        except EOFError:
            pass


def main(argv: list[str] | None = None) -> int:
    from .procname import set_name
    set_name()                          # shows up as "legalprivacy": killall legalprivacy works
    ap = argparse.ArgumentParser(prog="legalprivacy-launch", description=__doc__)
    ap.add_argument("--text", action="store_true", help="terminal menu instead of the dashboard")
    ap.add_argument("--no-browser", action="store_true", help="don't open a browser automatically")
    ap.add_argument("--port", type=int, help="dashboard port (default 8765)")
    ap.add_argument("--profile", help="use this profile YAML instead of the saved config")
    ap.add_argument("--url", action="store_true", help="print the dashboard link and exit")
    ap.add_argument("--service", action="store_true",
                    help="run as a service: no window, starts the noise by itself, keeps going (see --install-service)")
    ap.add_argument("--install-service", action="store_true",
                    help="write the unit file that starts the service at login/boot and restarts it, then print what to run")
    args = ap.parse_args(argv)
    if args.url:
        import yaml
        from .paths import config_path
        from .webui import _load_token
        port = args.port
        if not port:
            try:
                with open(args.profile or config_path(), encoding="utf-8") as fh:
                    raw = yaml.safe_load(fh) or {}
                port = int((raw.get("app") or {}).get("port", 8765))
            except (OSError, ValueError, yaml.YAMLError):
                port = 8765
        print(f"http://127.0.0.1:{port}/?t={_load_token()}")
        return 0
    from .paths import ensure_utf8_console
    ensure_utf8_console()
    if args.install_service:
        from .service import install_service
        return install_service()
    if args.service:
        from .service import run_service
        return run_service(args.profile, args.port)
    if args.text:
        return _text_menu()
    try:
        from .webui import run_ui
        return run_ui(args.profile, args.port, False if args.no_browser else None)
    except Exception:
        traceback.print_exc()
        _pause_on_windows_error()
        return 1


# ── terminal fallback ────────────────────────────────────────────────────────
def _text_menu() -> int:
    import argparse as ap_
    from .cli import cmd_doctor, cmd_run
    from .controller import Controller
    from .tormanager import find_tor_binary, port_open

    def ask(prompt: str, default: str = "") -> str:
        try:
            return input(f"  {prompt}" + (f" [{default}]" if default else "") + ": ").strip() or default
        except (EOFError, KeyboardInterrupt):
            return "q"

    ctl = Controller()                  # once: each Controller starts background threads
    while True:
        tor_cfg = ctl.profile.transports["tor"]
        print("\n  ⚖️ legalPrivacy (text mode)\n")
        print(f"  Tor: {'ON' if tor_cfg.enabled else 'off'}  (program: {find_tor_binary() or 'not installed'}; "
              f"other Tor running: {port_open('127.0.0.1', 9050) or port_open('127.0.0.1', 9150)})")
        print("  [1] Start now   [2] One test round   [3] Health check   "
              "[4] Toggle Tor (onion sites)   [5] Dashboard (browser)   [Q] Quit\n")
        c = ask("Choice", "1").lower()
        base = dict(profile=ctl.profile_path if os.path.exists(ctl.profile_path) else None,
                    dry_run=False, verbose=True, reconnect_tor=False)
        try:
            if c == "1":
                cmd_run(ap_.Namespace(once=False, **base))
            elif c == "2":
                cmd_run(ap_.Namespace(once=True, **base))
            elif c == "3":
                cmd_doctor(ap_.Namespace(profile=base["profile"]))
            elif c == "4":
                ctl.apply_config({"transports": {"tor": {"enabled": not tor_cfg.enabled, "onion": True}}})
                print(f"  Tor is now {'ON' if not tor_cfg.enabled else 'off'}.")
            elif c == "5":
                from .webui import run_ui
                return run_ui()
            elif c in ("q", "quit"):
                return 0
        except KeyboardInterrupt:
            print("\n  Stopped.")
        except Exception as exc:
            print(f"  Error: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
