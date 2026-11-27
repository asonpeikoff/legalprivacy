"""Detect Whonix and Qubes OS, so the app uses the Whonix-Gateway's Tor instead of starting its own.

Running a second Tor inside a Whonix-Workstation would be "Tor over Tor" (every connection through two Tor circuits:
slower, and worse for anonymity). On Whonix the gateway already runs Tor for the workstation, so the app attaches to it.

Detection follows Whonix's own guidance for applications (whonix.org/wiki/Dev/Project_friendly_applications_best_practices):
  * marker files: /usr/share/whonix/marker (any Whonix), /usr/share/anon-ws-base-files/workstation (Whonix-Workstation),
    /usr/share/anon-gw-base-files/gateway (Whonix-Gateway);
  * the gateway address: 10.152.152.10 on Non-Qubes-Whonix; on Qubes-Whonix what `qubesdb-read /qubes-gateway` says
    (whonix.org/wiki/Stream_Isolation);
  * the gateway's Tor: SOCKS on port 9050, control port 9051 behind onion-grater (a filter that allows only basic commands).
Qubes OS itself is recognised by /usr/share/qubes/marker-vm or the qubesdb-read tool. A plain (non-Whonix) Qubes qube
whose network qube is sys-whonix is detected by its gateway answering on the Tor SOCKS port.

The settings switch tor.anon_os ("auto", the default, or "off") turns all of this off.
"""
from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
from pathlib import Path

WHONIX_MARKER = "/usr/share/whonix/marker"
WS_MARKER = "/usr/share/anon-ws-base-files/workstation"
GW_MARKER = "/usr/share/anon-gw-base-files/gateway"
QUBES_MARKER = "/usr/share/qubes/marker-vm"
NON_QUBES_GATEWAY = "10.152.152.10"
SOCKS_PORT, CONTROL_PORT = 9050, 9051


def _exists(p: str, root: str) -> bool:
    return Path(root + p).exists()


def _qubes_gateway(run=subprocess.run) -> str | None:
    exe = shutil.which("qubesdb-read")
    if not exe:
        return None
    try:
        out = run([exe, "/qubes-gateway"], capture_output=True, text=True, timeout=3).stdout.strip()
        ipaddress.ip_address(out)                     # only an address is accepted, never text that could mean anything else
        return out
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def detect(root: str = "", run=subprocess.run, probe=_port_open) -> dict | None:
    """What anonymity OS this is, and where its Tor is. None on an ordinary computer.
    {"kind": "whonix-workstation" | "whonix-gateway" | "qubes-sys-whonix", "qubes": bool, "name": str,
     "socks": "host:port", "control": "host:port"}"""
    qubes = _exists(QUBES_MARKER, root) or bool(shutil.which("qubesdb-read"))
    if _exists(WS_MARKER, root):
        gw = (_qubes_gateway(run) if qubes else None) or NON_QUBES_GATEWAY
        return {"kind": "whonix-workstation", "qubes": qubes, "name": "Qubes-Whonix Workstation" if qubes else "Whonix-Workstation",
                "socks": f"{gw}:{SOCKS_PORT}", "control": f"{gw}:{CONTROL_PORT}"}
    if _exists(GW_MARKER, root):
        return {"kind": "whonix-gateway", "qubes": qubes, "name": "Qubes-Whonix Gateway" if qubes else "Whonix-Gateway",
                "socks": f"127.0.0.1:{SOCKS_PORT}", "control": f"127.0.0.1:{CONTROL_PORT}"}
    if qubes:
        gw = _qubes_gateway(run)
        if gw and probe(gw, SOCKS_PORT):          # this qube's network qube runs Tor (sys-whonix)
            return {"kind": "qubes-sys-whonix", "qubes": True, "name": "Qubes OS behind a Whonix-Gateway",
                    "socks": f"{gw}:{SOCKS_PORT}", "control": f"{gw}:{CONTROL_PORT}"}
    return None


_cached: tuple[bool, dict | None] = (False, None)


def current() -> dict | None:
    """detect(), worked out once per run."""
    global _cached
    if not _cached[0]:
        try:
            _cached = (True, detect())
        except Exception:
            _cached = (True, None)
    return _cached[1]
