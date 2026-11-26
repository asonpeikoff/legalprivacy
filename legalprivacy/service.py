"""Run legalPrivacy as a service: no window, starts by itself, keeps going, comes back after a crash or a reboot.

`legalprivacy-launch --service` runs the same program as the double-click launcher, with these differences:
  * no browser is opened and nothing needs a person: on the first run it applies the recommended setup (randomised noise, Tor
    for onion sites if Tor is installed) without asking the three questions;
  * the noise starts by itself and "Keep it running" is on (it wakes itself if it pauses, restarts if it stops);
  * SIGTERM (what a service manager sends) stops it cleanly, so Tor and the relay do not outlive it;
  * the dashboard is still there whenever you want it: open the link `legalprivacy-launch --url` prints (it carries the
    private token) in any browser. Nothing needs the page to stay open.

`legalprivacy-launch --install-service` writes the unit file that starts it at login or boot and restarts it if it dies.
"""
from __future__ import annotations

import shlex
import signal
import sys
from pathlib import Path

UNIT_NAME = "legalprivacy.service"


def service_command() -> list[str]:
    """How to start the service: the frozen executable itself, or this Python running the launcher."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "--service"]
    return [sys.executable, "-m", "legalprivacy.launcher", "--service"]


def systemd_unit(command: list[str] | None = None) -> str:
    cmd = " ".join(shlex.quote(c) for c in (command or service_command()))
    return (
        "[Unit]\n"
        "Description=legalPrivacy (background noise, dashboard on 127.0.0.1)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        f"ExecStart={cmd}\n"
        "Restart=always\n"            # any exit, crash or kill: start again
        "RestartSec=15\n"
        "TimeoutStopSec=30\n"
        "KillMode=control-group\n"    # take Tor and the relay down with it
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def launchd_plist(command: list[str] | None = None) -> str:
    args = "".join(f"    <string>{c}</string>\n" for c in (command or service_command()))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n<dict>\n  <key>Label</key><string>org.legalprivacy</string>\n'
            f"  <key>ProgramArguments</key>\n  <array>\n{args}  </array>\n"
            "  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n</dict>\n</plist>\n")


def install_service() -> int:
    """Write the unit file for this system and print what to run next. Nothing is started or enabled for you."""
    if sys.platform.startswith("linux"):
        path = Path.home() / ".config" / "systemd" / "user" / UNIT_NAME
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(systemd_unit(), encoding="utf-8")
        print(f"Wrote {path}\n\nThen run:\n  systemctl --user daemon-reload\n  systemctl --user enable --now legalprivacy\n"
              "  loginctl enable-linger \"$USER\"      # keeps it running when you are logged out (needs administrator rights on some systems)\n"
              "\nSee its log:  journalctl --user -u legalprivacy -f\nOpen the dashboard any time:  legalprivacy-launch --url")
        return 0
    if sys.platform == "darwin":
        path = Path.home() / "Library" / "LaunchAgents" / "org.legalprivacy.plist"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(launchd_plist(), encoding="utf-8")
        print(f"Wrote {path}\n\nThen run:\n  launchctl load {path}")
        return 0
    cmd = " ".join(f'"{c}"' for c in service_command())
    print("On Windows, create a task that starts at logon and restarts on failure:\n"
          f'  schtasks /Create /TN legalPrivacy /SC ONLOGON /RL LIMITED /TR "{cmd}"\n'
          "(Windows service support is untested.)")
    return 0


def first_run_answers(tor_installed: bool) -> dict:
    """The recommended setup, with no questions asked."""
    return {"rate_mode": "random", "level": 5, "tor": "onion" if tor_installed else "off", "autostart": True}


def run_service(profile_path: str | None = None, port: int | None = None) -> int:
    from .controller import Controller
    from .tormanager import find_tor_binary
    from .webui import UIServer, running_instance, start_services

    ctl = Controller(profile_path)
    want = port or int(ctl.app.get("port", 8765))
    other = running_instance(want)
    if other:
        print(f"legalPrivacy is already running: {other}", flush=True)
        return 0
    if ctl.first_run:
        ctl.wizard(first_run_answers(bool(find_tor_binary())))
        ctl.first_run = False
    ctl.app["autostart"] = True
    ctl.app["open_browser"] = False
    ctl.profile.extras.keep_alive = True
    srv = UIServer(ctl, want)
    print(f"legalPrivacy service running. Dashboard: {srv.url}", flush=True)
    ctl.log.info("app", f"Service mode: dashboard on 127.0.0.1:{srv.port}, noise starts by itself, keep-alive on.")
    start_services(ctl)

    def _term(_sig, _frm):
        raise KeyboardInterrupt
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), _term)
            except (ValueError, OSError):
                pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        ctl.stop(stop_tor=True)
    return 0


__all__ = ["run_service", "install_service", "systemd_unit", "launchd_plist", "first_run_answers", "service_command"]
