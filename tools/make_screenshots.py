"""Maintainer tool: take the README's screenshots of the dashboard and its graphs, filled with made-up but
realistic example data (nothing here is anyone's real traffic).

Usage:  python tools/make_screenshots.py [output folder]      (default docs/screenshots)
Needs Playwright and a Chrome/Chromium (the same one legalPrivacy uses). It starts a throw-away copy of the
app in a temporary folder, fills its observer with 30 hours of invented traffic, and photographs each graph.
"""
from __future__ import annotations

import os
import random
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

HOSTS_YOU = ["github.com", "api.github.com", "mail.google.com", "www.youtube.com", "i.ytimg.com", "docs.google.com",
             "slack.com", "files.slack.com", "outlook.office.com", "www.nytimes.com", "stackoverflow.com", "pypi.org",
             "files.pythonhosted.org", "cdn.jsdelivr.net", "fonts.gstatic.com", "www.reddit.com", "i.redd.it"]
HOSTS_NOISE = ["www.bing.com", "duckduckgo.com", "www.google.com", "en.wikipedia.org", "arxiv.org", "www.kaggle.com",
               "huggingface.co", "scikit-learn.org", "pandas.pydata.org", "www.reddit.com", "news.ycombinator.com",
               "www.aynrand.org", "www.atlassociety.org", "www.theobjectivestandard.com", "legalizingprivacy.substack.com",
               "medium.com", "www.youtube.com", "www.goodreads.com", "www.etsy.com", "www.imdb.com", "www.python.org",
               "pytorch.org", "www.coursera.org", "www.geeksforgeeks.org", "docs.python.org", "pypi.org"]


def _ip(rng: random.Random) -> str:
    return ".".join(str(rng.randint(11, 223)) for _ in range(4))


def pick_timezone() -> None:
    """Photograph in the afternoon: choose a time zone in which it is about 4 PM right now."""
    off = (16 - time.gmtime().tm_hour) % 24
    off = off - 24 if off > 14 else off
    os.environ["TZ"] = f"Etc/GMT{'-' if off > 0 else '+'}{abs(off)}" if off else "UTC"
    time.tzset()


def fill(ctl, now: float) -> None:
    """Invent 30 hours of minute-by-minute traffic, a live connection map and a few hundred recent hits."""
    rng = random.Random(7)
    obs = ctl.observer
    obs.stop()
    t_now = int(now) - int(now) % 60
    start = t_now - 72 * 3600
    # noise off for the first day (your own rhythm), on for a day and a half, stopped for a few hours, on again
    segments = [(t_now - 72 * 3600, t_now - 48 * 3600, False), (t_now - 48 * 3600, t_now - 9 * 3600, True),
                (t_now - 9 * 3600, t_now - 3 * 3600, False), (t_now - 3 * 3600, t_now + 60, True)]
    from legalprivacy.activity import intended
    ex = ctl.profile.extras
    plan = intended(ctl.profile.rate, ctl._search_share(), ex.active_hours, ex.active_from, ex.active_to, ex.persona)
    hour_wobble = {}
    on_burst, left = False, 0
    for t in range(start, t_now + 60, 60):
        h = time.localtime(t).tm_hour
        # you: a workday rhythm with bursts and gaps
        base = {0: .02, 1: .01, 2: .01, 3: .01, 4: .01, 5: .03, 6: .12, 7: .35, 8: .6, 9: .7, 10: .72, 11: .65, 12: .45,
                13: .6, 14: .72, 15: .7, 16: .62, 17: .5, 18: .35, 19: .4, 20: .45, 21: .38, 22: .2, 23: .08}[h]
        if left <= 0:
            on_burst = rng.random() < base * .78
            left = rng.randint(2, 11) if on_burst else rng.randint(2, 14)
        left -= 1
        you = rng.randint(1, 6) if on_burst else (rng.randint(0, 1) if rng.random() < .2 else 0)
        m = {"you": you, "noise": 0, "tor": 0, "on": False, "bytes": you * rng.randint(20_000, 160_000), "req": 0}
        if any(a <= t < b and flag for a, b, flag in segments):
            m["on"] = True
            wob = hour_wobble.setdefault(t // 3600, rng.uniform(.8, 1.2))       # some hours busier than others
            per_min = plan["p50"][h] / 60 * wob * 1.15                           # about what the plan says for this hour
            req = (1 if rng.random() < per_min % 1 else 0) + int(per_min)
            if req:
                m["req"] = req
                m["noise"] = rng.randint(2, 6)
                m["tor"] = 1 if rng.random() < .22 else 0
                m["bytes"] += req * rng.randint(250_000, 900_000)
        obs.minutes[t] = m
    # the live map: your apps, the noise, and Tor
    obs.live.clear()
    for host in rng.sample(HOSTS_YOU, 14):
        ip = _ip(rng)
        obs.names[ip] = host
        obs.live[ip] = {"kind": "you", "first": now - rng.randint(20, 900), "last": now - rng.random() * 8, "seen": 4,
                        "ports": {443, 443 + rng.randint(1, 3)} if rng.random() < .3 else {443}}
    for host in rng.sample(HOSTS_NOISE, 22):
        ip = _ip(rng)
        obs.names[ip] = host
        obs.live[ip] = {"kind": "noise", "first": now - rng.randint(5, 600), "last": now - rng.random() * 30, "seen": 3,
                        "ports": {443}}
    for _ in range(6):
        ip = _ip(rng)
        obs.live[ip] = {"kind": "tor", "first": now - rng.randint(60, 3000), "last": now - rng.random() * 5, "seen": 9,
                        "ports": {9001, 443}}
    # recent hits for the dashboard graph, the lane cards and the activity log
    runner = ctl.runner
    if runner is not None:
        runner.hit_log.clear()
        seq = 0
        for t0 in range(t_now - 1800, t_now, 60):                        # the last half hour, minute by minute
            for _ in range(obs.minutes.get(t0, {}).get("req", 0)):           # (the graph counts successful hits)
                seq += 1
                onion = rng.random() < .2
                host = rng.choice(HOSTS_NOISE)
                runner.hit_log.append({"seq": seq, "ts": t0 + rng.random() * 60, "lane": "tor" if onion else "clearnet",
                                       "engine": "onion" if onion else rng.choice(["search", "crawl", "dns"]),
                                       "url": f"https://{host}/", "status": 200, "ok": rng.random() > .04, "error": None,
                                       "latency_ms": rng.randint(180, 2400), "note": "", "role": "page", "detail": "",
                                       "on_page_s": round(rng.uniform(4, 60), 1)})
        runner._hit_seq = seq
        shown = [h for h in runner.hit_log if h["ts"] > now - 1800]
        for lane in runner.lanes:
            mine = [h for h in runner.hit_log if h["lane"] == lane.name]
            lane.hits_total = len(mine) * 7
            lane.failures_total = sum(1 for h in mine if not h["ok"]) * 3
            lane.last_hit_ts = max((h["ts"] for h in mine), default=None)
            for b in lane.budgets.values():
                b.spent = max(0, int(b.per_day * .6))
        runner.bytes_today = 184_000_000
        runner.started_at = now - (4 * 3600 + 37 * 60)
        runner.day_failures = len(shown) // 30


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "screenshots"
    out.mkdir(parents=True, exist_ok=True)
    pick_timezone()
    home = tempfile.mkdtemp(prefix="lp-shots-")
    os.environ["LEGALPRIVACY_HOME"] = home
    from legalprivacy.browser import find_browser
    from legalprivacy.controller import Controller
    from legalprivacy.transports import HitResult
    from legalprivacy.webui import UIServer
    from playwright.sync_api import sync_playwright

    exe = find_browser()
    if not exe:
        print("No Chrome/Chromium found.", file=sys.stderr)
        return 1
    ctl = Controller(os.path.join(home, "config.yaml"))
    ctl.wizard({"rate_mode": "random", "level": 6, "tor": "off", "autostart": False})
    ctl.apply_config({"transports": {"tor": {"enabled": False}}})
    ctl.start()
    if ctl.runner is not None:
        ctl.runner.probe_fn = lambda *a: HitResult(200, "")
        ctl.runner.sleep_fn = lambda s: ctl._stop.wait(max(s, 120))   # stay quiet while photographing
    now = time.time()
    fill(ctl, now)
    srv = UIServer(ctl, 0)
    threading.Thread(target=srv.httpd.serve_forever, daemon=True).start()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=exe)
        for theme in ("light",):
            page = browser.new_page(viewport={"width": 1280, "height": 900}, device_scale_factor=2,
                                    color_scheme=theme)
            page.goto(srv.url)
            page.wait_for_timeout(2500)
            page.add_style_tag(content="#wiz{display:none!important}")

            def snap(selector: str, name: str) -> None:
                page.locator(selector).first.screenshot(path=str(out / name))
                print("wrote", out / name)

            def card(tab_id: str, title: str, name: str) -> None:
                page.locator(f"#t-{tab_id} .card:has(h3:has-text('{title}'))").first.screenshot(path=str(out / name))
                print("wrote", out / name)

            def tab(name: str, wait: int = 3500) -> None:
                page.click(f"#nav button[data-t={name}]")
                page.wait_for_timeout(wait)

            tab("dash", 3500)
            snap("#t-dash", "dashboard.png")
            tab("proof", 6000)
            snap("#pMap", "proof-map.png")
            snap("#pTime", "proof-timeline.png")
            snap("#pOnOff", "proof-off-vs-on.png")
            snap("#pCmp", "proof-looks-like-you.png")
            page.wait_for_timeout(4500)
            for sel, name in (("#aIntended", "planned-pattern.png"), ("#aSession", "session-vs-plan.png"),
                              ("#aBase", "you-vs-noise.png"), ("#aRuns", "bursts-and-gaps.png")):
                snap(f"{sel}", name)
            page.add_style_tag(content="#nav,header{position:static!important}")
            tab("set", 1500)
            card("set", "Amount of noise", "amount.png")
            page.evaluate("""() => {                      // example resolver results (this machine's own network is not typical)
                pollBusy = true;
                S.dns = {intercepted: false, checking: false, system: [{ip: '192.168.1.1', what: 'your router'}],
                         resolvers: dRes.map((r, i) => ({ip: r.ip, verdict: 'ok', rtt_ms: [38, 52, 44, 21][i % 4], egress: r.ip}))};
                renderDnsHealth();
            }""")
            card("set", "DNS lookups", "dns.png")
            tab("tor", 2500)
            card("tor", "Bridges", "bridges.png")
        browser.close()
    srv.httpd.shutdown()
    ctl.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
