"""Network checks for the Tools tab: which DNS resolvers your computer uses, a DNS
leak check, and a speed test.

Everything here is user-initiated and runs over the clearnet (never over Tor).
The speed test moves a fixed, modest amount of data (10 MB down, 2 MB up) once per
click, through the clearnet proxy if you set one, so the number reflects that route.
"""
from __future__ import annotations

import ipaddress
import os
import platform
import re
import secrets
import subprocess
import time
import urllib.request
from collections.abc import Callable

# Override with LEGALPRIVACY_SPEED_DOWN_URL / LEGALPRIVACY_SPEED_UP_URL to test against your own endpoint
# ({n} in the download URL is replaced by the byte count).
from .paths import getenv  # noqa: E402

DOWN_URL = getenv("SPEED_DOWN_URL") or "https://speed.cloudflare.com/__down?bytes={n}"
UP_URL = getenv("SPEED_UP_URL") or "https://speed.cloudflare.com/__up"
# speed.cloudflare.com (and many endpoints) answer 403 to a request with no browser User-Agent.
SPEED_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
DOWN_BYTES = 10_000_000
UP_BYTES = 2_000_000
LEAK_TEST_URL = "https://www.dnsleaktest.com/"


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _valid_ips(items) -> list[str]:
    out = []
    for x in items:
        try:
            ip = str(ipaddress.ip_address(x.strip()))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


def system_resolvers() -> dict:
    """Resolvers the operating system is configured to send lookups to."""
    system = platform.system()
    ips: list[str] = []
    note = ""
    if system == "Windows":
        out = _run(["ipconfig", "/all"])
        found = re.findall(r"DNS Servers[ .]*:\s*([0-9a-fA-F:.]+)", out)
        found += re.findall(r"^\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*$", out, re.M)
        ips = _valid_ips(found)
    elif system == "Darwin":
        out = _run(["scutil", "--dns"])
        ips = _valid_ips(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", out))
    else:
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as fh:
                ips = _valid_ips(re.findall(r"^\s*nameserver\s+(\S+)", fh.read(), re.M))
        except OSError:
            ips = []
        if "127.0.0.53" in ips or "127.0.0.1" in ips:
            note = ("Your system uses a local stub resolver (systemd-resolved or similar). "
                    "Run `resolvectl status` to see the upstream servers it forwards to.")
    return {"system": system, "resolvers": ips, "note": note}


def qubes_vm_type() -> str | None:
    """Qubes OS VM type ('AppVM', 'NetVM', ...) or None when not running on Qubes."""
    from .macspoof import MacSpoofer
    return MacSpoofer().qubes_vm_type()


def egress_resolver() -> dict:
    """The resolver that actually reached the internet for a lookup from this computer.
    `whoami.akamai.net` answers with the address of whichever resolver asked Akamai's name
    servers, i.e. the one that really sees your lookups, however many forwarders sit in
    between (router, VPN, another Qubes qube)."""
    import socket
    try:
        ip = socket.getaddrinfo("whoami.akamai.net", None, socket.AF_INET)[0][4][0]
    except OSError as exc:
        return {"error": f"lookup failed: {exc}"}
    try:
        name = socket.gethostbyaddr(ip)[0]
    except OSError:
        name = ""
    return {"ip": ip, "name": name}


def dns_leak_check(secure_ips: list[str]) -> dict:
    """Which resolvers your computer uses, and whether any of them is outside the
    resolvers you chose for noise. Also times one fresh, random lookup.

    Resolvers in your settings are often just a router, VPN or (on Qubes OS) another qube
    forwarding for you, so the last line asks the internet who really answered
    (`egress_resolver`): that is the resolver that sees your lookups.
    """
    info = system_resolvers()
    chosen = set(_valid_ips(secure_ips))
    qubes = qubes_vm_type()
    rows = []
    for ip in info["resolvers"]:
        try:
            private = ipaddress.ip_address(ip).is_private
        except ValueError:
            private = False
        if ip in ("127.0.0.53", "127.0.0.1"):
            verdict = "local stub: forwards upstream"
        elif chosen and ip in chosen:
            verdict = "one of your chosen secure resolvers"
        elif qubes and ip.startswith("10.139."):
            verdict = "Qubes virtual DNS: your network qube (sys-net or the VPN qube) forwards it"
        elif private:
            verdict = "private address: your router, VPN or network qube forwards it upstream"
        else:
            verdict = "public resolver set by your system (not one of your chosen secure resolvers)"
        rows.append({"ip": ip, "verdict": verdict})
    egress = egress_resolver()
    if chosen and egress.get("ip"):
        egress["is_chosen"] = egress["ip"] in chosen
    if qubes:
        info["note"] = ((info.get("note") or "") + (" " if info.get("note") else "") +
                        f"Qubes OS ({qubes}): DNS, VPN and encrypted DNS are set up in your network qubes, outside this "
                        "one, so they can't be inspected from here. The resolver reported below is the real one.")
    name = f"{secrets.token_hex(6)}.example.com"      # random, never used, so never cached
    import socket
    t0 = time.time()
    try:
        socket.getaddrinfo(name, 443)
        answer = "resolved"
    except socket.gaierror as exc:
        answer = f"answered: no such name ({exc.strerror or 'NXDOMAIN'})"   # a real reply from a resolver
    except OSError as exc:
        answer = f"no answer: {exc}"
    lookup = {"ms": round((time.time() - t0) * 1000), "result": answer}
    return {"system": info["system"], "resolvers": rows, "note": info["note"],
            "sample_lookup": lookup, "egress_resolver": egress, "qubes": qubes,
            "external_test": LEAK_TEST_URL}


def _mbps(nbytes: int, seconds: float) -> float:
    return round(nbytes * 8 / max(seconds, 1e-6) / 1_000_000, 2)


def speed_test(proxy: str | None = None, progress: Callable[[str], None] = lambda s: None,
               down_bytes: int = DOWN_BYTES, up_bytes: int = UP_BYTES, timeout: float = 60) -> dict:
    """Download then upload once. Returns Mbps for each, or an error message."""
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    result: dict = {"down_mbps": None, "up_mbps": None, "errors": [], "via": proxy or "direct"}
    progress("Downloading…")
    try:
        t0 = time.time()
        got = 0
        down_req = urllib.request.Request(DOWN_URL.format(n=down_bytes), headers={"User-Agent": SPEED_UA})
        with opener.open(down_req, timeout=timeout) as r:
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                got += len(chunk)
        result["down_mbps"] = _mbps(got, time.time() - t0)
        result["down_bytes"] = got
    except Exception as exc:  # network errors vary widely; report, don't crash
        result["errors"].append(f"download: {exc}")
    progress("Uploading…")
    try:
        payload = os.urandom(up_bytes)
        req = urllib.request.Request(UP_URL, data=payload, method="POST",
                                     headers={"Content-Type": "application/octet-stream", "User-Agent": SPEED_UA})
        t0 = time.time()
        with opener.open(req, timeout=timeout) as r:
            r.read()
        result["up_mbps"] = _mbps(up_bytes, time.time() - t0)
        result["up_bytes"] = up_bytes
    except Exception as exc:
        result["errors"].append(f"upload: {exc}")
    return result


# ── local privacy check (idea from NoisyCompany's `privacy`) ────────────────
UBO_CHROMIUM_IDS = ("cjpalhdlnbpafiamejdnhcphjbkeiagm", "ddkjiahejlhfcafbddmgiahcphecmpfh",   # uBO, uBO Lite (Chrome store)
                    "odfafepnkmbhccpbejgmiehpchacaeak")                                     # uBO (Edge store)
UBO_FIREFOX_ID = "uBlock0@raymondhill.net"
UBO_FIREFOX = UBO_FIREFOX_ID + ".xpi"
_VPN_IF = ("tun", "tap", "wg", "ppp", "ipsec", "nordlynx", "proton", "mullvad", "tailscale")
# Firefox-family profile folders beyond the ones the history reader knows (forks, Flatpaks, Tor/Mullvad Browser).
_MORE_FIREFOX_BASES = (".librewolf", ".waterfox", ".floorp", ".var/app/io.gitlab.librewolf-community/.librewolf",
                       ".var/app/net.waterfox.waterfox/.waterfox", ".var/app/one.ablaze.floorp/.floorp")
# Where distributions put system-wide Firefox add-ons (Fedora's mozilla-ublock-origin package, Debian's webext-ublock-origin).
_FIREFOX_SYSTEM_EXT = ("/usr/share/mozilla/extensions", "/usr/lib/mozilla/extensions", "/usr/lib64/mozilla/extensions",
                       "/usr/lib/firefox/distribution/extensions", "/usr/lib64/firefox/distribution/extensions",
                       "/usr/lib/firefox-esr/distribution/extensions", "/usr/share/webext/ublock-origin")
_MORE_CHROMIUM_BASES = (("Vivaldi", ".config/vivaldi"), ("Opera", ".config/opera"), ("Chrome Beta", ".config/google-chrome-beta"),
                        ("Brave (Flatpak)", ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"))


def _ubo_in_firefox_profile(prof: str) -> bool:
    """uBO in one Firefox profile: as an installed .xpi or folder, its storage, or in the add-on list (extensions.json,
    which also lists add-ons installed system-wide by a package)."""
    import glob
    if glob.glob(os.path.join(prof, "extensions", UBO_FIREFOX_ID + "*")) or \
            os.path.isdir(os.path.join(prof, "browser-extension-data", UBO_FIREFOX_ID)):
        return True
    try:
        with open(os.path.join(prof, "extensions.json"), encoding="utf-8", errors="replace") as fh:
            import json
            for a in json.load(fh).get("addons", []):
                if a.get("id") == UBO_FIREFOX_ID and a.get("active", True) is not False:
                    return True
    except (OSError, ValueError, AttributeError):
        pass
    return False


def _ubo_in_chromium_profile(prof: str) -> bool:
    """uBO in one Chromium-family profile: its Extensions folder, or its entry in (Secure) Preferences, which also covers
    unpacked and policy-installed copies."""
    if any(os.path.isdir(os.path.join(prof, "Extensions", ext)) for ext in UBO_CHROMIUM_IDS):
        return True
    for name in ("Secure Preferences", "Preferences"):
        try:
            with open(os.path.join(prof, name), encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if any(f'"{ext}"' in text for ext in UBO_CHROMIUM_IDS) or "uBlock Origin" in text:
            return True
    return False


def _content_blocker() -> list[str]:
    import glob
    from pathlib import Path
    from .history import _chromium_bases, _firefox_bases
    home = Path.home()
    found = []
    chromium = list(_chromium_bases()) + [(n, str(home / rel)) for n, rel in _MORE_CHROMIUM_BASES]
    for name, base in chromium:
        if any(_ubo_in_chromium_profile(p) for p in glob.glob(os.path.join(base, "*")) if os.path.isdir(p)):
            found.append(name)
    firefox = [("Firefox", b) for b in _firefox_bases()] + \
        [(Path(rel).name.lstrip(".").capitalize(), str(home / rel)) for rel in _MORE_FIREFOX_BASES]
    for name, base in firefox:
        if any(_ubo_in_firefox_profile(p) for p in glob.glob(os.path.join(base, "*")) if os.path.isdir(p)):
            found.append(name)
    if "Firefox" not in found:
        for d in _FIREFOX_SYSTEM_EXT:                     # installed for every user by the system's package manager
            if glob.glob(os.path.join(d, "*", UBO_FIREFOX_ID + "*")) or glob.glob(os.path.join(d, UBO_FIREFOX_ID + "*")) \
                    or (d.endswith("ublock-origin") and os.path.isdir(d)):
                found.append("Firefox (system add-on)")
                break
    return sorted(set(found))


# Who owns the address the world sees: names of VPN companies, and networks that mostly rent servers to VPNs.
VPN_ORGS = ("proton", "nordvpn", "nord security", "tefincom", "packethub", "mullvad", "31173 services", "expressvpn", "surfshark",
            "private internet access", "pia ", "cyberghost", "kape", "windscribe", "ivpn", "airvpn", "torguard",
            "hide.me", "purevpn", "gz systems", "ipvanish", "strongvpn", "hotspot shield", "pango", "astrill",
            "perfect privacy", "ovpn", "azire", "vpn")
VPN_HOSTS = ("m247", "datacamp", "cdn77", "clouvider", "xtom", "leaseweb", "zenlayer", "hostroyale", "creanova",
             "tzulo", "quadranet", "performive", "gsl networks", "100tb", "tier.net")


def external_ip_owner(timeout: float = 6.0) -> dict:
    """The address this computer reaches the internet from, and who it is registered to (ifconfig.me for the
    address, then ipinfo.io for the owner). Sends one small request to each; no identifying data beyond the
    address itself, which both see anyway."""
    import json
    out: dict = {"ip": None, "org": "", "hostname": "", "error": None}
    hdr = {"User-Agent": "curl/8.5.0", "Accept": "application/json"}
    try:
        with urllib.request.urlopen(urllib.request.Request("https://ifconfig.me/ip", headers=hdr), timeout=timeout) as r:
            ip = r.read(64).decode().strip()
        ipaddress.ip_address(ip)
        out["ip"] = ip
    except Exception as exc:  # offline, blocked, odd answer: say so, don't crash the check
        out["error"] = f"could not learn the public address: {exc}"
        return out
    try:
        with urllib.request.urlopen(urllib.request.Request(f"https://ipinfo.io/{out['ip']}/json", headers=hdr),
                                    timeout=timeout) as r:
            d = json.loads(r.read(20000).decode("utf-8", "replace"))
        out["org"], out["hostname"] = str(d.get("org") or ""), str(d.get("hostname") or "")
    except Exception as exc:
        out["error"] = f"could not look up who owns {out['ip']}: {exc}"
    return out


def vpn_provider(owner: dict) -> tuple[str | None, str]:
    """('vpn' | 'host' | None, why) from external_ip_owner(): 'vpn' when the address belongs to a VPN company,
    'host' when it is a server network that VPNs commonly rent."""
    text = f"{owner.get('org', '')} {owner.get('hostname', '')}".lower()
    org = re.sub(r"^as\d+\s+", "", owner.get("org") or "", flags=re.I) or "unknown"
    if any(k in text for k in VPN_ORGS):
        return "vpn", org
    if any(k in text for k in VPN_HOSTS):
        return "host", org
    return None, org


def _vpn_interfaces() -> list[str]:
    import socket
    try:
        names = [n for _, n in socket.if_nameindex()]
    except (OSError, AttributeError):
        return []
    return [n for n in names if n.lower().startswith(_VPN_IF)]


def _mac_row(add) -> None:
    """MAC address line for the privacy check (read-only; changing it is `legalprivacy mac`)."""
    try:
        from .macspoof import MacSpoofer
        sp = MacSpoofer()
        env, rows = sp.environment(), [r for r in sp.status() if r["eligible"]]
    except Exception:  # a broken sysfs must never break the whole check
        return
    xen = [r for r in rows if r["iface"] in env["xen_virtual_interfaces"]]
    if xen and len(xen) == len(rows):
        names = ", ".join(r["iface"] for r in xen)
        add("MAC address", "ok" if any(r["spoofed"] for r in xen) else "info",
            f"Xen virtual NIC ({names}, Qubes qube). It has its own MAC, which you can randomize, but only the network "
            "qube sees it: the outside network sees the physical NIC in sys-net.",
            f"Here: sudo legalprivacy mac randomize {xen[0]['iface']} --force (if this qube loses its network, "
            "sudo legalprivacy mac restore --all). For the outside world: the same in sys-net.")
    elif any(r["spoofed"] for r in rows):
        add("MAC address", "ok", "Changed from the factory address on: " + ", ".join(r["iface"] for r in rows if r["spoofed"]))
    elif rows:
        add("MAC address", "info", "Factory MAC in use on: " + ", ".join(r["iface"] for r in rows),
            "Networks you join can log it. Randomize with: sudo legalprivacy mac randomize --all (docs/MAC.md).")


def privacy_check(ctl) -> list[dict]:
    """Plain-language checks of what actually protects you, with advice. The only thing sent is the VPN check's
    lookup of this computer's public address and its owner (ifconfig.me and ipinfo.io)."""
    out = []

    def add(name, status, detail, advice=""):
        out.append({"name": name, "status": status, "detail": detail, "advice": advice})

    blockers = _content_blocker()
    qubes = qubes_vm_type()
    add("Content blocker", "ok" if blockers else "info" if qubes else "warn",
        f"uBlock Origin found in: {', '.join(blockers)}" if blockers else
        "uBlock Origin not found in this qube's browsers. Browsers in other qubes (a disposable one, say) can't be seen "
        "from here." if qubes else "uBlock Origin not found in your browsers",
        "" if blockers else "Blocking trackers stops more profiling than any amount of noise. Install uBlock Origin first.")
    vpn = _vpn_interfaces()
    owner = external_ip_owner()
    kind, org = vpn_provider(owner)
    seen = f"Your public address {owner['ip']} belongs to {org}" if owner.get("ip") else ""
    vpn_on = kind == "vpn" or (kind == "host" and bool(vpn or qubes))
    if kind == "vpn":
        add("VPN", "ok", f"{seen}, a VPN provider: your traffic leaves through a VPN.")
    elif kind == "host":
        add("VPN", "ok" if vpn_on else "info", f"{seen}, a server network many VPNs rent: very likely a VPN"
            + (f" (interface {', '.join(vpn)})." if vpn else "."),
            "" if vpn_on else "If you didn't turn on a VPN or proxy, check what your traffic goes through.")
    elif vpn:
        add("VPN", "info", f"VPN-style network interface: {', '.join(vpn)}" + (f". {seen}, not a known VPN company." if seen else ""),
            "A VPN moves what your ISP sees to the VPN provider; noise still helps against whoever sees your traffic.")
    elif qubes:
        add("VPN", "info", f"Qubes OS ({qubes}): a VPN normally runs in its own qube (sys-vpn), outside this one. "
            + (f"{seen}, not a known VPN company." if seen else (owner.get("error") or "")),
            "If you use a VPN qube, this qube's network qube should be it (or sit behind it).")
    else:
        add("VPN", "info", "No VPN seen" + (f": {seen}, not a known VPN company." if seen else
                                             f" ({owner['error']})." if owner.get("error") else "."),
            "A VPN moves what your ISP sees to the VPN provider; noise still helps against whoever sees your traffic.")
    dot = "+DNSOverTLS" in _run(["resolvectl", "status"]) if platform.system() == "Linux" else False
    res = system_resolvers()["resolvers"]
    if vpn_on:
        add("Encrypted DNS", "ok", "Your lookups go through the VPN's encrypted tunnel to the VPN provider "
            "(the usual VPN setup), so your ISP doesn't see them.",
            "Run the DNS leak test on Proof to confirm the VPN's resolver is the one answering.")
    elif qubes:
        add("Encrypted DNS", "info", "Set up in your network qubes (sys-net / sys-vpn), not in this one, "
            "so it can't be seen from here.", "Configure it there; this qube only forwards to its virtual DNS.")
    else:
        add("Encrypted DNS", "ok" if dot else "info",
            "DNS over TLS is on (systemd-resolved)" if dot else
            f"Your system resolvers: {', '.join(res) or 'unknown'}. Whether they are encrypted can't be seen from here.",
            "" if dot else "Turning on encrypted DNS (DoH/DoT) in your OS or router hides lookups from your ISP.")
    _mac_row(add)
    tor_on = ctl._tor_cfg().enabled
    add("Tor in the mix", "ok" if tor_on else "info", "On: .onion noise runs" if tor_on else "Off",
        "" if tor_on else "Optional. Turning it on adds Tor traffic to your mix (🧅 Tor tab).")
    bi = ctl.browser_info()
    add("Real browser for noise", "ok" if bi["active"] else "warn",
        "Noise runs in a real browser" if bi["active"] else f"Plain HTTP only ({bi['detail']})",
        "" if bi["active"] else "Plain HTTP can't scroll or run pages and is easier to tell apart. Install Playwright and Chrome.")
    ident = ctl.profile.identity
    own = ident.ua_mode == "pin" and ident.ua_pin == "own"
    if ident.ua_mode == "mix":
        add("Noise looks like your browser", "info",
            f"Mixed: about {round(float(ident.ua_own_share) * 100)}% of the noise uses your own browser's user agent, "
            "the rest a random one", "Raise the share (Settings → User agent) to look more like you.")
        return out
    add("Noise looks like your browser", "ok" if own else "info",
        "Pinned to your own browser's user agent" if own else "User agent rotates",
        "" if own else "Recommended: Settings → User agent → Pin to my own browser's user agent.")
    return out
