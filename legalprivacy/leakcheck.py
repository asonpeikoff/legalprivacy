"""Plain-language "is it working?" checks.

Every check says what you WANT to see, what we actually SAW, and a simple status:
  ok      working
  bad     not working (with what to do)
  info    shown for your information, nothing to fix
  unknown could not be tested yet
Nothing here changes any setting. The only network calls are the ones named in the hints.
"""
from __future__ import annotations

import threading
import time
from typing import Any

from .nettools import system_resolvers

TOR_API = "https://check.torproject.org/api/ip"      # {"IsTor": bool, "IP": "..."} — same page the Tor self-test uses


def _c(cid, title, want, saw, status, hint=""):
    return {"id": cid, "title": title, "want": want, "saw": saw, "status": status, "hint": hint}


def build_checks(f: dict[str, Any]) -> list[dict]:
    """Pure: turn gathered facts into the list of checks (easy to test)."""
    out = []
    # 1. is noise running
    if f.get("running"):
        out.append(_c("noise", "Noise is running", "ON", "Paused" if f.get("paused") else "ON",
                      "bad" if f.get("paused") else "ok",
                      "Press Resume on the Dashboard." if f.get("paused") else ""))
    else:
        out.append(_c("noise", "Noise is running", "ON", "OFF", "bad", "Press Start on the Dashboard."))

    # 2. DNS goes where you chose
    d = f.get("dns") or {}
    if d.get("mode") == "system":
        out.append(_c("dns", "Lookups use the servers you chose", "Your normal resolver",
                      "Your normal resolver (you chose this)", "info",
                      "In Settings → DNS you can send noise lookups to OpenNIC / Quad9 servers instead."))
    else:
        rows = [r for r in d.get("resolvers", []) if r.get("enabled")]
        checked = [r for r in rows if r.get("verdict") not in (None, "unknown")]
        if not checked:
            out.append(_c("dns", "Lookups use the servers you chose", "Answers come from the servers you chose",
                          "Not tested yet", "unknown", "Press “Run checks”."))
        elif d.get("intercepted"):
            out.append(_c("dns", "Lookups use the servers you chose", "Answers come from the servers you chose",
                          "Your network redirects DNS: every server answered from the same machine"
                          + (f" ({d['system_egress']})" if d.get("system_egress") else ""), "bad",
                          "Your router or provider is answering instead of the servers you picked, so your choice "
                          "isn't taking effect. A VPN or encrypted DNS (DoH/DoT) in your system gets around this."))
        else:
            good = [r for r in checked if r["verdict"] in ("ok", "slow", "disputed")]
            down = [r for r in checked if r["verdict"] == "down"]
            liars = [r for r in checked if r["verdict"] in ("hijack", "disagrees")]
            if good:
                saw = f"{len(good)} of {len(checked)} chosen servers answered honestly for themselves"
                if liars:
                    saw += f"; {len(liars)} caught giving wrong answers and left out"
                out.append(_c("dns", "Lookups use the servers you chose", "Answers come from the servers you chose",
                              saw, "ok", f"{len(down)} not answering; the fallback covers it." if down else ""))
            else:
                out.append(_c("dns", "Lookups use the servers you chose", "Answers come from the servers you chose",
                              "None of the chosen servers answered", "bad",
                              "Check your connection; noise falls back to your normal resolver meanwhile."))

    # 3. your computer's own resolvers (information)
    sysr = f.get("system_resolvers") or []
    out.append(_c("sysdns", "Your computer's own DNS servers", "Servers you trust",
                  ", ".join(f"{s['ip']} ({s['what']})" if s.get("what") else s["ip"] for s in sysr) or "unknown",
                  "info", "Your everyday browsing uses these; noise doesn't change them."))

    # 4/5. Tor
    t = f.get("tor")
    if t is not None:
        if t.get("ready"):
            out.append(_c("tor", "Tor is connected", "Connected (100%)", "Connected", "ok"))
        else:
            out.append(_c("tor", "Tor is connected", "Connected (100%)",
                          f"{t.get('state', 'stopped')} {t.get('pct', 0)}%",
                          "bad" if t.get("state") in ("stopped", "error") else "unknown",
                          t.get("hint") or "Open the Tor tab and press Start; the first connection can take a minute."))
        ex = f.get("exit")
        if t.get("ready"):
            if ex is None:
                out.append(_c("exit", "Tor traffic leaves from a different address than yours",
                              "Different address, marked as Tor", "Not tested yet", "unknown", "Press “Run checks”."))
            elif ex.get("error"):
                out.append(_c("exit", "Tor traffic leaves from a different address than yours",
                              "Different address, marked as Tor", f"Test failed: {ex['error']}", "bad",
                              "Try again; if it keeps failing use the Tor tab’s Test Tor button."))
            else:
                same = bool(ex.get("direct_ip")) and ex.get("direct_ip") == ex.get("tor_ip")
                ok = bool(ex.get("is_tor")) and not same
                saw = f"Directly: {ex.get('direct_ip') or '?'} · Through Tor: {ex.get('tor_ip') or '?'}" + \
                      (" (Tor exit ✓)" if ex.get("is_tor") else " (NOT a Tor exit)")
                out.append(_c("exit", "Tor traffic leaves from a different address than yours",
                              "Different address, marked as Tor", saw, "ok" if ok else "bad",
                              "" if ok else "Traffic meant for Tor is not coming out of Tor. Restart Tor from the Tor tab."))

    # 5b. Tor DNS answers (only when the optional Tor DNS switch is on)
    td = f.get("tordns")
    if td is not None:
        want = "Answers through Tor"
        title = "Tor DNS answers"
        res = td.get("result")
        if not td.get("ready"):
            out.append(_c("tordns", title, want, "Tor isn't ready yet", "unknown",
                          "Start Tor on the Tor tab and wait for 100%, then press “Run checks”."))
        elif res is None:
            out.append(_c("tordns", title, want, "Not tested yet", "unknown", "Press “Run checks”."))
        elif res.get("ok"):
            out.append(_c("tordns", title, want,
                          f"{res.get('name')} answered {', '.join(res.get('answers') or [])} in {res.get('ms')} ms", "ok"))
        else:
            out.append(_c("tordns", title, want, res.get("error") or "No answer", "bad",
                          "Open the Tor tab, check Tor DNS and use its Test button. Tor resolves names through its "
                          "exit relays, so the first answer can take several seconds."))

    # 6. noise browser looks like yours
    if f.get("real_browser") is not None:
        out.append(_c("browser", "Noise runs in a real browser", "Real browser",
                      "Real browser" if f["real_browser"] else "Plain HTTP only",
                      "ok" if f["real_browser"] else "bad",
                      "" if f["real_browser"] else "Plain HTTP can't scroll or run pages and is easier to tell apart. "
                                                   "Install Chrome/Edge and the Playwright package."))
    if f.get("own_ua") is not None:
        out.append(_c("ua", "Noise looks like your own browser", "Same browser and version as yours",
                      "Matches yours" if f["own_ua"] else "Uses other browser identities",
                      "ok" if f["own_ua"] else "info",
                      "" if f["own_ua"] else "Settings → User agent → pin to your own browser's user agent."))

    # 7. the optional antivirus scanner never connects (only shown once the person has used the Security tab)
    av = f.get("av")
    if av is not None:
        want = "0 connections during scans"
        if av.get("connections") is None or av.get("when") is None:
            out.append(_c("av", "Antivirus scanner stays offline", want, "No scan yet", "unknown",
                          "Run a scan or the self-test on the Security tab."))
        elif av["connections"] == 0:
            how = "network removed" if av.get("isolated") else "connections watched"
            out.append(_c("av", "Antivirus scanner stays offline", want,
                          f"0 connections in the last {av.get('kind') or 'scan'} ({how})", "ok"))
        else:
            out.append(_c("av", "Antivirus scanner stays offline", want,
                          f"{av['connections']} connection(s) in the last {av.get('kind') or 'scan'}: NOT OFFLINE", "bad",
                          "The scanner was stopped. Block clamscan in your firewall, and see the Live Log."))
    return out


def summarize(checks: list[dict]) -> dict:
    ok = sum(c["status"] == "ok" for c in checks)
    bad = sum(c["status"] == "bad" for c in checks)
    unk = sum(c["status"] == "unknown" for c in checks)
    if bad:
        word = f"{bad} thing{'s' if bad != 1 else ''} not working"
    elif unk:
        word = "Not fully tested yet"
    else:
        word = "Everything checked is working"
    return {"ok": ok, "bad": bad, "unknown": unk, "headline": word, "all_good": bad == 0 and unk == 0}


def _exit_test(tm) -> dict:
    import requests
    from .transports import explain_tor_error
    try:
        direct = requests.get(TOR_API, timeout=15).json()
        proxies = {"http": f"socks5h://leak:check@{tm.socks_addr}", "https": f"socks5h://leak:check@{tm.socks_addr}"}
        via = requests.get(TOR_API, proxies=proxies, timeout=60).json()
        return {"direct_ip": direct.get("IP"), "tor_ip": via.get("IP"), "is_tor": bool(via.get("IsTor"))}
    except Exception as exc:
        return {"error": explain_tor_error(str(exc), tm.socks_addr)[:160]}


def gather(ctl, with_network: bool = True) -> dict:
    """Collect the facts from the live app (and, if asked, run the Tor exit test)."""
    r = ctl.runner
    f: dict[str, Any] = {"running": ctl.running, "paused": bool(r and r.paused)}
    rep = ctl.dns_report()
    f["dns"] = {"mode": ctl.profile.dns.mode, "resolvers": rep.get("resolvers", []),
                "intercepted": rep.get("intercepted"), "system_resolvers": None,
                "system_egress": rep.get("system_egress")}
    from .dnsplan import describe_ip
    f["system_resolvers"] = [{"ip": ip, "what": describe_ip(ip)} for ip in system_resolvers()["resolvers"]]
    cfg = ctl._tor_cfg()
    if cfg.enabled:
        tm = ctl.tor_manager()
        f["tor"] = {"ready": bool(tm.ready), "state": tm.state, "pct": getattr(tm, "bootstrap_pct", 0)}
        if tm.ready and with_network:
            f["exit"] = _exit_test(tm)
    dns_info = ctl.tor_manager().dns_info() if cfg.dns_port else None
    if dns_info and dns_info["on"] and dns_info["managed"]:
        res = None
        if dns_info["ready"] and with_network:
            from . import tordns
            res = tordns.probe(dns_info["address"], dns_info["port"], timeout=20)
        f["tordns"] = {"ready": dns_info["ready"], "result": res}
    bi = ctl.browser_info()
    f["real_browser"] = bool(bi.get("active"))
    ident = ctl.profile.identity
    f["own_ua"] = ident.ua_mode == "pin" and ident.ua_pin == "own"
    try:
        f["av"] = ctl.av.proof_fact()
    except Exception:
        f["av"] = None
    return f


class LeakRunner:
    """Runs the checks in the background; the dashboard polls .state()."""

    def __init__(self, ctl):
        self.ctl, self._lock = ctl, threading.Lock()
        self._state: dict = {"running": False, "ts": 0, "checks": [], "summary": None}

    def run(self) -> None:
        with self._lock:
            if self._state["running"]:
                return
            self._state = {**self._state, "running": True}
        threading.Thread(target=self._go, daemon=True, name="leak-check").start()

    def _go(self) -> None:
        try:
            self.ctl.check_dns()
            for _ in range(40):                      # wait (up to ~8 s) for the resolver check
                plan = getattr(self.ctl, "dns_plan", None)
                if not plan or not plan.checking:
                    break
                time.sleep(0.2)
            checks = build_checks(gather(self.ctl))
            self._state = {"running": False, "ts": time.time(), "checks": checks, "summary": summarize(checks)}
        except Exception as exc:
            self._state = {"running": False, "ts": time.time(), "checks": [], "summary": None, "error": repr(exc)[:200]}

    def state(self) -> dict:
        s = dict(self._state)
        if not s["checks"] and not s["running"] and not s.get("error"):
            # first look: no network, so the page shows something useful straight away
            try:
                checks = build_checks(gather(self.ctl, with_network=False))
                s.update(checks=checks, summary=summarize(checks), preview=True)
            except Exception:
                pass
        return s
