"""Display-free pieces of the native desktop app: formatters, the state-to-view mapping, the debounced
live-apply helper and the thread hand-off queue. Nothing here imports tkinter, so it is fully testable
without a display (see tests/test_gui.py)."""
from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable
from urllib.parse import urlparse

# ── palette (the same colours as the web dashboard) ─────────────────────────
LIGHT = {
    "bg": "#f5f6f8", "panel": "#ffffff", "fg": "#1c2230", "muted": "#5d677b", "accent": "#2a7348",
    "accent_fg": "#ffffff", "border": "#dfe3ea", "ok": "#2a7348", "ok_bg": "#e8f3ec", "warn": "#8f5a0e",
    "warn_bg": "#fdf3df", "bad": "#c0392b", "bad_bg": "#fbe9e7", "tor": "#7a3fb0", "tor_bg": "#f1e8f9",
    "info": "#2a6fb0", "info_bg": "#e6f0fa", "code": "#f0f2f6", "field": "#ffffff", "select": "#e8f3ec",
    "hover": "#eef1f5", "band": "#cfe0f3", "line": "#2a6fb0", "you": "#2a7348", "noise": "#c0392b",
    "grid": "#e4e8ee", "log_bg": "#fbfcfd",
}
DARK = {
    "bg": "#11141b", "panel": "#1a1f2a", "fg": "#e6e9f0", "muted": "#8b94a8", "accent": "#4cc07d",
    "accent_fg": "#0b1a12", "border": "#2a3140", "ok": "#4cc07d", "ok_bg": "#183326", "warn": "#e0a94a",
    "warn_bg": "#35290f", "bad": "#ef6a5b", "bad_bg": "#3a1b17", "tor": "#b98aea", "tor_bg": "#2a1b3b",
    "info": "#6aaef0", "info_bg": "#16283a", "code": "#222938", "field": "#222938", "select": "#183326",
    "hover": "#222938", "band": "#1f3a57", "line": "#6aaef0", "you": "#4cc07d", "noise": "#ef6a5b",
    "grid": "#2a3140", "log_bg": "#0e1218",
}
PALETTES = {"light": LIGHT, "dark": DARK}
MIX_COLORS = ["#2f7d4f", "#3b6fb6", "#c27a1a", "#8a4fb3", "#b23a48", "#2a9d9b", "#7a7a2a", "#5b5b8f", "#a0522d"]

LOG_LEVEL_ORDER = ["debug", "info", "warn", "error"]
LOG_LEVEL_LABELS = {"debug": "Everything", "info": "Normal", "warn": "Warnings and errors", "error": "Errors only"}
LOG_MAX_LINES = 5000
ACTIVITY_MAX_ROWS = 500

STATUS_GLYPH = {"ok": "✓", "bad": "✗", "info": "ℹ", "unknown": "?"}


# ── formatters ──────────────────────────────────────────────────────────────
def fmt_uptime(seconds: float | None) -> str:
    s = int(seconds or 0)
    if s <= 0:
        return "—"
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d:
        return f"{d}d {h:02d}h {m:02d}m"
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def fmt_clock(ts: float | None) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else ""


def fmt_log_line(ev: dict) -> str:
    return f"{fmt_clock(ev['ts'])}  {ev['level'].upper():5s} [{ev['source']}] {ev['message']}"


def fmt_bytes(n: float | None) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


LANE_LABELS = {"clearnet": "Web (browser)", "clearnet-plain": "Web (plain)", "tor": "Onion (Tor)"}
ENGINE_LABELS = {"search": "searches", "crawl": "following links", "dns": "DNS lookups",
                 "onion": "onion sites", "packages": "package installs"}


def lane_label(name: str) -> str:
    return LANE_LABELS.get(name, name)


def lanes_rows(state: dict) -> list[tuple]:
    """Rows for the Dashboard lanes table: (lane, engines, hits, failures, budgets, last problem)."""
    rows = []
    for ln in state.get("lanes") or []:
        eng = ln.get("engines") or {}
        names = ", ".join(ENGINE_LABELS.get(e, e) for e in eng) or "—"
        budgets = "  ".join(f"{ENGINE_LABELS.get(e, e)} {int(b.get('spent', 0))}/{int(b.get('per_day', 0))}"
                            for e, b in eng.items()) or "—"
        status = lane_label(ln.get("name", "")) + ("" if ln.get("open", True) else " (waiting)")
        rows.append((status, names, ln.get("hits", 0), ln.get("failures", 0), budgets,
                     (ln.get("last_error") or "")[:60]))
    return rows


def short_host(url: str, width: int = 60) -> str:
    """Long .onion names are shortened in the middle, like the web dashboard does."""
    import re
    s = re.sub(r"([a-z2-7]{10})[a-z2-7]{30,}([a-z2-7]{6}\.onion)", r"\1…\2", str(url))
    return s if len(s) <= width else s[:width - 1] + "…"


def now_text(current: dict | None, now: float | None = None) -> str:
    """The Dashboard's 'what it is doing now' line (site name only, never a full address)."""
    if not current:
        return "Idle: waiting for the next action."
    now = time.time() if now is None else now
    role, eng = current.get("role"), current.get("engine")
    what = ("looking at search results" if role == "search" else "a DNS lookup" if eng == "dns"
            else "installing a package" if eng == "packages" else "reading a result" if role == "result"
            else "on a page")
    secs = max(0, int(now - (current.get("started") or now)))
    return f"Now: {what}: {site_name(current.get('url', ''))} (for {secs} s)"


def site_name(url: str) -> str:
    """Just the site (host) of an address; DNS rows and package lines are already names."""
    u = str(url or "").strip()
    if "://" in u:
        host = urlparse(u).hostname or u
    elif "/" in u and " " not in u:
        host = u.split("/", 1)[0]
    else:
        host = u
    return short_host(host.removeprefix("www."), 48)


KIND_LABELS = {"search": "search", "crawl": "page", "dns": "DNS lookup", "onion": "onion page",
               "packages": "package"}


def hit_kind(hit: dict) -> str:
    if hit.get("role") == "result":
        return "clicked a result"
    return KIND_LABELS.get(hit.get("engine"), hit.get("engine") or "")


def hit_status(hit: dict) -> tuple[str, str]:
    """(text, tag) with tag in ok | bad | mute."""
    err = hit.get("error") or ""
    if hit.get("ok"):
        return ("OK" if not hit.get("status") else f"OK ({hit['status']})"), "ok"
    if "offline" in err:
        return "site offline", "mute"
    return (f"HTTP {hit['status']}" if hit.get("status") else (err[:40] or "error")), "bad"


def hit_row(hit: dict) -> tuple:
    """(seq, time, lane, kind, site, status, tag)  — a site name only, never a page address."""
    text, tag = hit_status(hit)
    return (hit.get("seq"), fmt_clock(hit.get("ts")), lane_label(hit.get("lane", "")), hit_kind(hit),
            site_name(hit.get("url", "")), text, tag)


def newest_first(hits: list[dict], cap: int = ACTIVITY_MAX_ROWS) -> list[dict]:
    return list(reversed(hits[-cap:]))


def hit_detail(hit: dict) -> str:
    return " · ".join(x for x in (hit.get("note"), hit.get("detail")) if x)


def hit_ms(hit: dict) -> str:
    return str(int(hit["latency_ms"])) if hit.get("latency_ms") else ""


def fmt_ago(ts: float | None, now: float | None = None) -> str:
    if not ts:
        return "—"
    s = max(0, int((time.time() if now is None else now) - ts))
    return f"{s} s ago" if s < 90 else f"{s // 60} min ago" if s < 5400 else f"{s // 3600} h ago"


def hits_per_minute(hits: list[dict], now: float, minutes: int = 30) -> list[int]:
    """Hits in each of the last `minutes` minutes, oldest first (the Dashboard sparkline)."""
    out = [0] * minutes
    for h in hits:
        age = int((now - h.get("ts", 0)) // 60)
        if 0 <= age < minutes:
            out[minutes - 1 - age] += 1
    return out


def relay_estimate_text(mb: float) -> str:
    if not mb or mb <= 0:
        return ""
    gb = mb * 86400 * 30 / 1000
    return (f"At full speed that is up to about {gb:,.0f} GB a month each way ({gb * 2:,.0f} GB in total). "
            "A relay usually uses much less. Tor needs at least about 0.08 MBytes per second.")


def tor_test_text(t: dict | None) -> str:
    if not t:
        return ""
    if t.get("running"):
        return "Testing Tor… this takes up to a minute."
    lines = [t.get("summary") or ""]
    ex, on = t.get("exit"), t.get("onion")
    if ex:
        lines.append("Through Tor to the web: " + (f"✓ yes, sites see exit {ex.get('ip')} ({ex.get('ms')} ms)" if ex.get("ok")
                                                   else f"✗ {ex.get('error') or 'not via Tor'}"))
    if on:
        lines.append("Onion site (Tor Project): " + (f"✓ loaded in {on.get('ms')} ms" if on.get("ok")
                                                      else f"✗ {on.get('error') or 'HTTP ' + str(on.get('status'))}"))
    return "\n".join(x for x in lines if x)


def onoff_rows(oo: dict) -> list[tuple]:
    off, on = oo.get("off") or {}, oo.get("on") or {}

    def f(v):
        return "—" if v is None else str(v)

    def kb(d):
        return "—" if d.get("bytes") is None else str(round(d["bytes"] / 1024))
    return [("", "Noise off", "Noise on"), ("Minutes observed", f(off.get("minutes")), f(on.get("minutes"))),
            ("Your apps: addresses / min", f(off.get("you")), f(on.get("you"))),
            ("legalPrivacy: addresses / min", f(off.get("noise")), f(on.get("noise"))),
            ("legalPrivacy: requests / min", "—", f(on.get("req"))), ("All traffic: KB / min", kb(off), kb(on))]


def compare_lines(c: dict) -> list[tuple]:
    """Rows for 'Does the noise look like you?': (text, tone, None) lines, or ((name, pct), tone, fraction) bars."""
    if not c:
        return [("No data yet.", "off", None)]
    if c.get("verdict") == "collecting":
        n = c.get("needed") or {}
        return [(f"Collecting data. Needs about {n.get('baseline_active', 0)} more busy minutes of your own traffic with the "
                 f"noise off, and {n.get('noise_active', 0)} more with it on.", "off", None),
                ("Tip: use your computer normally with legalPrivacy stopped for an hour or two, then start it, or import a "
                 "browser recording (HAR file) above.", "off", None)]
    word = {"similar": ("Looks like you", "ok"), "somewhat": ("Somewhat like you", "warn"),
            "different": ("Noticeably different", "bad")}.get(c.get("verdict"), ("", "off"))
    score = c.get("score")
    out = [(f"{round((score or 0) * 100)}%  {word[0]}" + (f" · least similar: {c['weakest']}" if c.get("weakest") else ""),
            word[1], None)]
    for m in c.get("metrics") or []:
        s = m.get("similarity")
        out.append(((m["name"], "later" if s is None else f"{round(s * 100)}%"), "ok", s or 0.0))
    out.append((f"Based on {c.get('baseline_active')} busy minutes of yours and {c.get('noise_active')} with noise.", "off", None))
    return out


def trace_row(it: dict) -> tuple:
    from urllib.parse import urlparse
    host = urlparse(it.get("url", "")).hostname or it.get("url", "")
    return fmt_clock(it.get("ts")), it.get("why") or "", short_host(host, 70)


# ── header / chips ──────────────────────────────────────────────────────────
def run_status(state: dict) -> tuple[str, str]:
    """(kind, text): kind in running | paused | stopped."""
    if state.get("running"):
        return ("paused", "Paused") if state.get("paused") else ("running", "Running")
    return "stopped", "Stopped"


def tor_chip(tor: dict | None, enabled: bool | None = None) -> tuple[str, str]:
    """(text, tone) tone in ok | warn | bad | off."""
    tor = tor or {}
    if enabled is None:
        enabled = bool(tor.get("enabled"))
    if not enabled:
        return "Tor: off", "off"
    st = tor.get("state") or "stopped"
    pct = tor.get("bootstrap_pct") or 0
    if st == "ready":
        return "Tor: connected", "ok"
    if st == "error":
        return "Tor: problem", "bad"
    if st in ("bootstrapping", "starting", "installing"):
        return (f"Tor: connecting {pct}%" if pct else f"Tor: {st}"), "warn"
    return f"Tor: {st}", "warn"


def settings_chip(status: dict | None, applying: bool = False, error: str | None = None) -> tuple[str, str]:
    """The header chip for ctl.settings_status(): '✓ settings in effect HH:MM:SS'."""
    if error:
        return f"✗ Not saved: {error}", "bad"
    if applying:
        return "Applying…", "warn"
    status = status or {}
    if not status.get("running"):
        return "Settings saved", "off"
    if status.get("in_effect"):
        at = status.get("applied_at")
        return "✓ settings in effect" + (f" {fmt_clock(at)}" if at else ""), "ok"
    return "! running settings differ from saved: press Stop, then Start", "warn"


def apply_message(status: dict | None, was_running: bool) -> tuple[str, str]:
    """Text under the settings after a live apply."""
    if not was_running:
        return "✓ Saved. It takes effect when you press Start.", "ok"
    if status and status.get("in_effect"):
        return "✓ Live and verified", "ok"
    return "Applied, but the running settings do not match the saved ones. Press Stop, then Start.", "warn"


def button_states(state: dict) -> dict[str, bool]:
    running = bool(state.get("running"))
    return {"start": not running, "pause": running, "stop": running}


def pause_label(state: dict) -> str:
    return "Resume" if state.get("paused") else "Pause"


def rate_text(level: int | float, rate_info: list[dict] | None) -> str:
    info = None
    if rate_info:
        try:
            info = rate_info[int(round(level)) - 1]
        except (IndexError, ValueError):
            info = None
    if not info:
        return f"Level {int(round(level))}"
    return (f"Level {int(round(level))}: {info['name']}. About {info['actions_per_hour']} actions an hour "
            f"({info['searches_per_hour']} searches), {info['vs_average_person']}× an average person's searching.")


# ── settings <-> controller ────────────────────────────────────────────────
DNS_CHOICES = [("mix", "Mix of both (recommended)"), ("system", "Your normal DNS only"),
               ("secure", "Privacy DNS servers only")]
WINDOW_CHOICES = [("hidden", "Hidden (recommended)"), ("offscreen", "Off-screen window"),
                  ("visible", "Visible (watch it work)")]
BRIDGE_CHOICES = [("off", "No bridges (direct)"), ("obfs4", "obfs4 (built in)"), ("snowflake", "Snowflake (built in)"),
                  ("meek", "meek (built in)"), ("custom", "My own bridges (add them in the web dashboard)")]
COOKIE_UNITS = [("hours", 1.0), ("days", 24.0)]


from .gui_fields import *  # noqa: F401,F403,E402
from .gui_fields import app_flags, build_config_payload, profile_values  # noqa: F401,E402


# ── log view ───────────────────────────────────────────────────────────────
def visible_events(events: list[dict], min_level: str) -> list[dict]:
    from .events import LEVELS
    floor = LEVELS.get(min_level, 10)
    return [e for e in events if LEVELS.get(e.get("level"), 20) >= floor]


# ── proof tab ───────────────────────────────────────────────────────────────
def check_lines(check: dict) -> tuple[str, str, str, str]:
    """(glyph + title, 'You want to see: …', 'We saw: …', hint) for one leak-check result."""
    return (f"{STATUS_GLYPH.get(check.get('status'), '?')}  {check.get('title', '')}",
            f"You want to see: {check.get('want', '')}", f"We saw: {check.get('saw', '')}", check.get("hint") or "")


def hours_label(h: int) -> str:
    return f"{h % 24:02d}"


def nice_max(v: float) -> float:
    """A round upper bound for a chart axis."""
    if v <= 0:
        return 1.0
    import math
    mag = 10 ** math.floor(math.log10(v))
    for k in (1, 2, 5, 10):
        if v <= k * mag:
            return float(k * mag)
    return float(10 * mag)


def scale(v: float, lo: float, hi: float, a: float, b: float) -> float:
    """Map v from [lo, hi] onto [a, b] (b may be smaller than a for an upward axis)."""
    return a if hi == lo else a + (v - lo) / (hi - lo) * (b - a)


def baseline_sources_text(base: dict) -> str:
    """'Where your baseline comes from' as plain lines."""
    inner = (base or {}).get("baseline") or {}
    lines = [inner.get("status") or "Not enough data yet."]
    for s in inner.get("sources") or []:
        note = f" ({s['note']})" if s.get("note") else ""
        lines.append(f"  • {s['name']}: {s['detail']}: {s['state']}{note}")
    return "\n".join(lines)


# ── threads ─────────────────────────────────────────────────────────────────
class UiQueue:
    """Worker threads post callables; the Tk main thread drains them from an `after` poll."""

    def __init__(self) -> None:
        self._q: queue.Queue = queue.Queue()

    def post(self, fn: Callable, *a, **kw) -> None:
        self._q.put((fn, a, kw))

    def drain(self, limit: int = 100) -> int:
        n = 0
        while n < limit:
            try:
                fn, a, kw = self._q.get_nowait()
            except queue.Empty:
                break
            n += 1
            try:
                fn(*a, **kw)
            except Exception:                    # one bad callback must not stop the others
                import traceback
                traceback.print_exc()
        return n

    def empty(self) -> bool:
        return self._q.empty()


def run_in_thread(fn: Callable, post: Callable, on_done: Callable | None = None,
                  on_error: Callable | None = None, name: str = "gui-worker") -> threading.Thread:
    """Run fn() off the main thread; hand the result (or exception) back with `post`."""
    def work():
        try:
            res = fn()
        except BaseException as exc:             # noqa: BLE001 - shown to the person, not swallowed
            if on_error:
                post(on_error, exc)
            return
        if on_done:
            post(on_done, res)
    t = threading.Thread(target=work, daemon=True, name=name)
    t.start()
    return t


class Debouncer:
    """Call `fire` once, `delay_ms` after the last `poke()`. `schedule(ms, fn) -> handle` and
    `cancel(handle)` are injected (Tk's after/after_cancel in the app, a fake clock in the tests)."""

    def __init__(self, schedule: Callable, cancel: Callable, fire: Callable, delay_ms: int = 700):
        self._schedule, self._cancel, self._fire, self.delay_ms = schedule, cancel, fire, delay_ms
        self._h = None

    @property
    def pending(self) -> bool:
        return self._h is not None

    def poke(self) -> None:
        if self._h is not None:
            self._cancel(self._h)
        self._h = self._schedule(self.delay_ms, self._go)

    def _go(self) -> None:
        self._h = None
        self._fire()

    def flush(self) -> None:
        if self._h is not None:
            self._cancel(self._h)
            self._h = None
            self._fire()


class LiveApply:
    """Debounced save-and-apply. `collect()` runs on the main thread (it reads the controls) and returns
    {"config": partial profile dict, "app": {flags}}; the work then runs in one worker thread:
    apply_config, update_app, and, if the noise is running with different settings, reapply().
    `report(kind, text, tone)` is called on the main thread with kind in applying | done | error."""

    def __init__(self, ctl, collect: Callable[[], dict], post: Callable, report: Callable,
                 schedule: Callable, cancel: Callable, delay_ms: int = 700, runner: Callable | None = None):
        self.ctl, self.collect, self.post, self.report = ctl, collect, post, report
        self._run = runner or run_in_thread
        self._lock = threading.Lock()
        self.debounce = Debouncer(schedule, cancel, self._start, delay_ms)
        self.busy = False

    def changed(self) -> None:
        self.report("applying", "Applying…", "warn")
        self.debounce.poke()

    def _start(self) -> None:
        job = self.collect()
        self.busy = True

        def work():
            with self._lock:                      # one apply at a time; later edits queue up behind it
                was_running = bool(self.ctl.running)
                if job.get("config"):
                    self.ctl.apply_config(job["config"])
                if job.get("app"):
                    self.ctl.update_app(job["app"])
                if was_running or self.ctl.running:
                    st = self.ctl.settings_status()
                    if st.get("running") and not st.get("in_effect"):
                        self.ctl.reapply()
                return was_running, self.ctl.settings_status()

        def done(res):
            self.busy = False
            if self.debounce.pending:             # more edits arrived meanwhile: stay in "Applying…"
                return
            was_running, st = res
            text, tone = apply_message(st, was_running)
            self.report("done", text, tone)

        def failed(exc):
            self.busy = False
            self.report("error", str(exc) or exc.__class__.__name__, "bad")

        self._run(work, self.post, done, failed, "gui-apply")
