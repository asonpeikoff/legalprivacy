"""Display-free mapping between the desktop app's controls and the saved profile, plus the maths of the
"always adds up to 100%" mixes. Nothing here imports tkinter."""
from __future__ import annotations

import copy
import re
import time
from typing import Any

# ── controls <-> profile ────────────────────────────────────────────────────
# key -> (path into the profile, kind). Kinds: bool int float str  pct (profile 0..1, shown 0..100)
# optstr (None shown as "")  csv ("a, b" <-> list)  lines ("a\nb" <-> list)  raw (kept as it is)
FIELDS: dict[str, tuple[tuple, str]] = {
    "dns_mode": (("dns", "mode"), "str"), "dns_encrypted": (("dns", "encrypted"), "bool"), "dns_share": (("dns", "system_share"), "pct"),
    "dns_slow": (("dns", "slow_ms"), "int"), "dns_opennic": (("dns", "opennic"), "bool"),
    "dns_quad9": (("dns", "quad9"), "bool"), "dns_custom": (("dns", "custom"), "csv"),
    "dns_resolvers": (("dns", "resolvers"), "raw"),
    "window": (("transports", "clearnet", "browser_window"), "str"),
    "browser": (("transports", "clearnet", "browser"), "str"),
    "engine": (("transports", "clearnet", "browser_engine"), "str"),
    "cookie_vary": (("transports", "clearnet", "cookie_vary"), "bool"),
    "proxy": (("transports", "clearnet", "proxy"), "optstr"),
    "firefox_path": (("transports", "clearnet", "firefox_path"), "str"),
    "clearnet_enabled": (("transports", "clearnet", "enabled"), "bool"),
    "tor_enabled": (("transports", "tor", "enabled"), "bool"), "tor_onion": (("transports", "tor", "onion"), "bool"),
    "tor_onion_browser": (("transports", "tor", "onion_browser"), "bool"),
    "tor_manage": (("transports", "tor", "manage"), "bool"), "tor_socks": (("transports", "tor", "socks"), "str"),
    "tor_control": (("transports", "tor", "control"), "optstr"),
    "tor_seeds": (("transports", "tor", "onion_seeds"), "lines"),
    "tor_share_browser": (("transports", "tor", "share_browser"), "bool"),
    "tor_bridges": (("transports", "tor", "bridges"), "lines"),
    "bridge_mode": (("transports", "tor", "bridge_mode"), "str"),
    "bridge_auto": (("transports", "tor", "bridge_auto"), "bool"),
    "tor_dns": (("transports", "tor", "dns_port"), "dnson"),       # Tor DNS switch: on = the default local port
    "tor_dns_lan": (("transports", "tor", "dns_lan"), "bool"),
    "tor_dns_addr": (("transports", "tor", "dns_lan_addr"), "str"),
    "active_hours": (("extras", "active_hours"), "bool"), "active_from": (("extras", "active_from"), "int"),
    "active_to": (("extras", "active_to"), "int"), "browser_dns": (("extras", "browser_dns"), "bool"),
    "dns_bursts": (("extras", "dns_bursts"), "bool"),
    "auto_correct": (("rate", "auto_correct"), "bool"),
    "duck_chat": (("extras", "duck_chat"), "bool"),
    "duck_images": (("extras", "duck_images"), "bool"),
    "file_transfers": (("extras", "file_transfers"), "bool"),
    "keep_alive": (("extras", "keep_alive"), "bool"), "geoban": (("extras", "geoban"), "bool"),
    "spray": (("extras", "spray"), "bool"), "spray_level": (("extras", "spray_level"), "str"),
    "typos": (("extras", "typos"), "bool"), "polite": (("extras", "polite"), "bool"),
    "low_data": (("extras", "low_data"), "bool"), "data_cap": (("extras", "daily_data_mb"), "float"),
    "site_list": (("extras", "site_list"), "str"), "persona": (("extras", "persona"), "str"),
    "persona_share": (("extras", "persona_share"), "pct"), "packages": (("extras", "packages"), "str"),
    "interests": (("extras", "interests"), "bool"), "interest_active": (("extras", "interest_active"), "int"),
    "interest_days": (("extras", "interest_rotate_days"), "int"),
    "interest_share": (("extras", "interest_share"), "pct"), "interest_list": (("extras", "interest_list"), "raw"),
    "household": (("extras", "household"), "bool"), "household_size": (("extras", "household_size"), "int"),
    "activity": (("extras", "activity"), "str"), "busy_kbps": (("extras", "busy_kbps"), "int"),
    "metrics": (("extras", "metrics"), "bool"), "search_engines": (("extras", "search_engines"), "raw"),
    "q_live": (("queries", "live"), "bool"), "q_dataset": (("queries", "dataset"), "bool"),
    "q_builtin": (("queries", "builtin"), "bool"), "q_words": (("queries", "words"), "bool"),
    "traffic_pattern": (("traffic", "pattern"), "str"), "mix_browser": (("traffic", "browser"), "float"),
    "mix_plain": (("traffic", "plain"), "float"), "mix_onion": (("traffic", "onion"), "float"),
    "mobile_share": (("traffic", "mobile_share"), "pct"), "device": (("traffic", "device"), "str"),
    "speed": (("realtime_scale",), "inv"),
    "ua_mode": (("identity", "ua_mode"), "str"), "rotate_every": (("identity", "rotate_every"), "str"),
    "ua_pin": (("identity", "ua_pin"), "str"), "own_ua": (("identity", "own_ua"), "str"),
    "ua_own_share": (("identity", "ua_own_share"), "pct"),
    "mylist_enabled": (("mylist", "enabled"), "bool"), "mylist_share": (("mylist", "random_share"), "pct"),
    "mylist_sites": (("mylist", "sites"), "raw"), "mylist_weights": (("mylist", "weights"), "raw"),
}
DNS_DEFAULT_PORT = 19053        # same as tordns.DEFAULT_PORT (this module stays free of other imports)
APP_KEYS = ("autostart", "clear_logs_on_restart", "observe", "auto_refresh_sources", "ml_auto", "auto_update")


def cookie_to_hours(value: float, unit: str) -> float:
    return max(0.0, float(value)) * (24.0 if unit == "days" else 1.0)


def cookie_from_hours(hours: float) -> tuple[float, str]:
    """Show whole days when it divides evenly, otherwise hours."""
    h = float(hours or 0)
    if h >= 24 and abs(h / 24 - round(h / 24)) < 1e-6:
        return float(round(h / 24)), "days"
    return round(h, 2), "hours"


def _dig(obj, path: tuple):
    for p in path:
        obj = obj[p] if isinstance(obj, dict) else getattr(obj, p)
    return obj


def read_fields(profile) -> dict:
    """Control values for every FIELDS key, from the saved profile."""
    out = {}
    for key, (path, kind) in FIELDS.items():
        v = _dig(profile, path)
        if kind == "pct":
            v = int(round(float(v) * 100))
        elif kind == "optstr":
            v = v or ""
        elif kind == "dnson":
            v = bool(v)
        elif kind == "inv":                       # time compression: 1 / realtime_scale
            v = round(1.0 / float(v), 2) if v else 1.0
        elif kind == "csv":
            v = ", ".join(v or [])
        elif kind == "lines":
            v = "\n".join(v or [])
        elif kind == "raw":
            v = copy.deepcopy(v)
        out[key] = v
    return out


def _put(out: dict, path: tuple, value) -> None:
    for p in path[:-1]:
        out = out.setdefault(p, {})
    out[path[-1]] = value


def fields_payload(v: dict) -> dict:
    """The partial profile dict for the FIELDS keys present in v (the others are left alone)."""
    out: dict = {}
    for key, (path, kind) in FIELDS.items():
        if key not in v:
            continue
        x = v[key]
        if kind == "pct":
            x = float(x) / 100.0
        elif kind == "optstr":
            x = (str(x).strip() or None)
        elif kind == "dnson":
            x = DNS_DEFAULT_PORT if x else 0
        elif kind == "int":
            x = int(x)
        elif kind == "float":
            x = float(x)
        elif kind == "inv":
            x = 1.0 / max(0.01, float(x))
        _put(out, path, x)
    return out


def profile_values(profile, app: dict) -> dict:
    """The control values that match the saved profile (inverse of build_config_payload / app_flags)."""
    rate, clear = profile.rate, profile.transports["clearnet"]
    cv, cu = cookie_from_hours(clear.cookie_hours)
    steady = rate.mode == "steady" or float(rate.randomness or 0) == 0
    out = read_fields(profile)
    out.update({
        "level": int(round(float(rate.level))), "rate_mode": "steady" if steady else "random",
        "randomness": 0 if steady else int(round(float(rate.randomness) * 100)),
        "cookie_value": cv, "cookie_unit": cu,
        "engines_mix": {n: (e.budget_per_day if e.enabled else 0) for n, e in profile.engines.items()
                        if n not in BACKGROUND_ENGINES},
        "dns_amount": background_amount(profile.engines, "dns", DNS_AMOUNTS),
        "pkg_amount": background_amount(profile.engines, "packages", PKG_AMOUNTS),
        "accounts": {n: {"enabled": bool(a.enabled), "per_hour": a.per_hour, "per_day": a.per_day,
                         "on_challenge": a.on_challenge} for n, a in profile.accounts.items()},
        "ua_choice": ua_choice_from_identity(profile.identity.ua_mode, profile.identity.rotate_every,
                                             profile.identity.ua_pin),
        "autostart": bool(app.get("autostart")),
        "auto_update": app.get("auto_update", True) is not False,
        "clear_logs_on_restart": bool(app.get("clear_logs_on_restart", True)),
        "log_keep_days": int(app.get("log_keep_days", 7)),
        "observe": bool(app.get("observe", True)), "auto_refresh_sources": bool(app.get("auto_refresh_sources")),
        "ml_auto": bool(app.get("ml_auto"))})
    return out


def build_config_payload(v: dict[str, Any], current_rate: dict | None = None) -> dict:
    """Controls -> the partial profile dict `Controller.apply_config` takes. `v` holds plain values (the
    FIELDS keys plus level, rate_mode, randomness, cookie_value/cookie_unit, engines_mix, accounts,
    ua_choice). Missing keys are left out, so a partial form never overwrites other settings."""
    out: dict[str, Any] = fields_payload(v)
    rate: dict[str, Any] = {}
    if "level" in v:
        rate["level"] = float(min(10, max(1, round(float(v["level"])))))
    if "rate_mode" in v:
        steady = v["rate_mode"] == "steady"
        old = float((current_rate or {}).get("randomness", 1.0) or 0)
        rate["mode"] = "steady" if steady else "random"
        rate["randomness"] = 0.0 if steady else (old if old > 0 else 1.0)
    if "randomness" in v:                                    # the 0-100 "how random" slider wins
        r = min(1.0, max(0.0, float(v["randomness"]) / 100.0))
        rate.update(mode="random" if r > 0 else "steady", randomness=r)
    if rate:
        out["rate"] = rate
    if "cookie_value" in v:
        _put(out, ("transports", "clearnet", "cookie_hours"),
             cookie_to_hours(v["cookie_value"], v.get("cookie_unit", "hours")))
    if "engines_mix" in v:
        out["engines"] = engines_from_mix({k: x for k, x in v["engines_mix"].items() if k not in BACKGROUND_ENGINES})
        mv = v["engines_mix"]
        base = max(1, round((float(mv.get("search", 0) or 0) + float(mv.get("crawl", 0) or 0)) * 10))
        for key, eng in (("dns_amount", "dns"), ("pkg_amount", "packages")):
            if key in v:
                f = float(v[key] or 0)
                out["engines"][eng] = {"enabled": f > 0, "budget_per_day": max(1, round(f * base))}
    if "accounts" in v:
        out["accounts"] = v["accounts"]
    if "ua_choice" in v:
        out["identity"] = {**out.get("identity", {}), **ua_choice_to_identity(v["ua_choice"], v.get("ua_pin", ""))}
    return out


def app_flags(v: dict[str, Any]) -> dict:
    """The on/off settings that live in the app section (saved with Controller.update_app)."""
    out = {k: bool(v[k]) for k in APP_KEYS if k in v}
    if "log_keep_days" in v:
        out["log_keep_days"] = int(v["log_keep_days"])
    return out


# ── user agent choice ───────────────────────────────────────────────────────
UA_CHOICES = [("mix", "Mix: mostly my own browser's, the rest random (recommended)"),
              ("own", "Pin to my own browser's user agent"),
              ("rotate-hour", "Random, changing every hour"), ("rotate-day", "Random, changing every day"),
              ("lib", "Pin to one library entry (not recommended)")]


def ua_choice_from_identity(mode: str, rotate_every: str, pin: str) -> str:
    if mode == "mix":
        return "mix"
    if mode == "rotate":
        return "rotate-day" if rotate_every == "day" else "rotate-hour"
    return "own" if pin == "own" else "lib"


def ua_choice_to_identity(choice: str, lib_id: str = "") -> dict:
    if choice == "own":
        return {"ua_mode": "pin", "ua_pin": "own"}
    if choice == "mix":
        return {"ua_mode": "mix"}
    if choice == "lib":
        return {"ua_mode": "pin", "ua_pin": lib_id if lib_id and lib_id != "own" else "own"}
    return {"ua_mode": "rotate", "rotate_every": "day" if choice == "rotate-day" else "hour"}


# ── mixes that always add up to 100% ────────────────────────────────────────
ENGINE_LABELS_MIX = {"search": "Searches", "crawl": "Following links", "dns": "DNS lookups",
                     "onion": "Onion sites", "packages": "Package installs"}


def mix_normalize(values: list[float]) -> list[float]:
    """Scale to a total of 100; all zero means an even split (as the web dashboard does)."""
    vals = [max(0.0, float(v or 0)) for v in values]
    if not vals:
        return []
    t = sum(vals)
    return [100 * v / t for v in vals] if t else [100.0 / len(vals)] * len(vals)


def mix_adjust(vals: list[float], k: int, new: float) -> list[float]:
    """Move part k to `new` percent; the others give or take the difference in proportion to their size."""
    v = min(100.0, max(0.0, float(new)))
    left = 100.0 - v
    rest = sum(x for j, x in enumerate(vals) if j != k)
    n = len(vals) - 1
    return [v if j == k else (x * left / rest if rest > 0 else (left / n if n else 0.0)) for j, x in enumerate(vals)]


def mix_percent_text(v: float) -> str:
    return f"{round(v * 10) / 10:g}%" if 0 < v < 10 else f"{round(v)}%"


def engines_from_mix(values: dict) -> dict:
    """{engine: mix value} -> engine settings; 0% turns an engine off, otherwise 10 actions a day per point."""
    return {n: {"enabled": float(v) > 0, "budget_per_day": int(round(float(v) * 10))} for n, v in values.items()}


def visible_engines(engines, tor_on: bool, pkg_on: bool) -> list[str]:
    return [n for n in engines if (n != "onion" or tor_on) and (n != "packages" or pkg_on)]


# DNS lookups and package installs run alongside the activity mix (their own threads) and never take a share
# of it, so they are set as an amount relative to searches + link-following, not as part of the 100% bar.
BACKGROUND_ENGINES = ("dns", "packages")
DNS_AMOUNTS = [("0", "Off"), ("1", "Fewer"), ("2", "Normal"), ("3", "More (recommended)"), ("5", "Lots")]
PKG_AMOUNTS = [("0", "Off"), ("0.04", "Rare"), ("0.075", "Normal"), ("0.15", "Often")]


def background_amount(engines, name: str, options: list[tuple]) -> str:
    """The option closest to this background engine's amount (its budget over searches + link-following)."""
    e = engines.get(name)
    if e is None or not e.enabled:
        return "0"
    base = max(1, sum(engines[n].budget_per_day for n in ("search", "crawl") if n in engines and engines[n].enabled))
    ratio = e.budget_per_day / base
    return min((v for v, _ in options if float(v) > 0), key=lambda v: abs(float(v) - ratio))


from .packages import TECHY_PERSONAS as TECHY  # noqa: E402


def packages_on(extras) -> bool:
    return extras.packages == "on" or (extras.packages != "off" and extras.persona in TECHY)


def traffic_items(traffic: dict, tor_on: bool) -> list[dict]:
    items = [{"key": "mix_browser", "label": "Web pages in a real browser", "value": traffic.get("mix_browser", 100),
              "hint": "recommended: most of it; runs pages and scrolls like a person"},
             {"key": "mix_plain", "label": "Web pages over plain HTTP", "value": traffic.get("mix_plain", 0),
              "hint": "0% recommended: no JavaScript or scrolling"}]
    if tor_on:
        items.append({"key": "mix_onion", "label": "Tor .onion sites", "value": traffic.get("mix_onion", 15),
                      "hint": "about 10-15% recommended"})
    return items


def engine_items(engines: dict, names: list[str]) -> list[dict]:
    return [{"key": n, "label": ENGINE_LABELS_MIX.get(n, n), "value": engines.get(n, 0)} for n in names]


# ── DNS resolver verdicts ──────────────────────────────────────────────────
def resolver_verdict(h: dict | None) -> tuple[str, str, str]:
    """(text, tone, tooltip) for one resolver row of ctl.dns_report()."""
    if not h or h.get("verdict") in (None, "unknown"):
        return "not checked", "off", ""
    v, ms = h["verdict"], h.get("rtt_ms")
    return {
        "ok": (f"✓ {ms} ms" + (" verified" if h.get("egress") else ""), "ok", ""),
        "slow": (f"slow {ms} ms", "warn", "Slower than the limit set below"),
        "down": (f"✗ {h.get('error') or 'no answer'}", "bad", ""),
        "intercepted": ("⚠ intercepted", "warn", f"answered by {h.get('egress')}"),
        "hijack": ("✗ hijacks missing names (not used)", "bad",
                   "It answered for a name that cannot exist, so it sends you to pages of its own"),
        "disagrees": ("✗ disagrees with the others (not used)", "bad",
                      "Its answers for ordinary sites differ from what the other servers agree on"),
        "disputed": ("? servers disagree", "warn", "The servers split evenly about the same names; used less"),
    }.get(v, (str(v), "off", ""))


# ── small mappings used by several tabs ─────────────────────────────────────
def rand_text(v: int) -> str:
    if v == 0:
        return "Steady: about the same amount every hour."
    if v == 100:
        return "Fully random (recommended): each hour varies like a person, with busier evenings and quiet spells."
    return f"{v}% random: each hour is {100 - v}% steady and {v}% random, so the swings are gentler."


def level_scope(clearnet_on: bool, tor_on: bool) -> str:
    parts = [p for p in ("web pages and searches" if clearnet_on else "", "DNS lookups" if clearnet_on else "",
                         ".onion sites" if tor_on else "") if p]
    if not parts:
        return "Nothing is turned on yet."
    return "This sets the total for everything that is on: " + ", ".join(parts) + "."


def account_status_text(a: dict) -> tuple[str, str]:
    """(pill text, tone) for one ctl.accounts.status() entry."""
    st = a.get("state")
    if st == "signed_in":
        saved = a.get("saved_at")
        return "Signed in" + (f" · saved {time.strftime('%Y-%m-%d', time.localtime(saved))}" if saved else ""), "ok"
    if st == "needs_attention":
        until = a.get("attention_until")
        from .gui_logic import clock12
        return "Paused" + (f" until about {clock12(until, day=True)}" if until else ""), "warn"
    if st == "needs_signin":
        return "Needs sign-in again", "warn"
    return "Signed out", "off"


def account_note(a: dict) -> str:
    si = a.get("signin") or {}
    if si.get("state") in ("starting", "waiting", "saving", "failed", "done") and si.get("message"):
        return si["message"]
    if a.get("state") == "needs_attention":
        return f"Paused because {a.get('attention_reason')}. The ordinary noise carries on."
    if a.get("state") == "signed_in":
        return f"{a.get('visits_hour')} of {a.get('per_hour')} visits this hour, {a.get('visits_day')} of {a.get('per_day')} today."
    return ""


FEED_LABELS = {"deny": "Safety blocklist", "trends": "Google Trends", "wiki": "Wikipedia most-read",
               "news": "BBC headlines", "dataset": "Real past searches", "tranco": "Popular sites (Tranco)",
               "opennic": "OpenNIC resolvers", "crux": "Popular sites (Chrome / CrUX)"}


def _dur(s: float) -> str:
    s = max(0, int(s))
    return f"{s // 86400} d" if s >= 86400 * 2 else f"{s // 3600} h" if s >= 3600 else f"{max(1, s // 60)} min"


def feed_row(f: dict, now: float | None = None) -> tuple:
    now = time.time() if now is None else now
    upd = f.get("updated")
    age = "—" if not upd else _dur(now - upd) + " ago"
    if f.get("error"):
        status = "unavailable: " + str(f["error"])[:50]
    elif f.get("count"):
        status = "old, consider refreshing" if f.get("stale") else "ok"
    else:
        status = "missing"
    return (FEED_LABELS.get(f.get("name"), f.get("name")), f"{int(f.get('count') or 0):,}", f.get("origin") or "", age, status)


def mylist_weight_label(w: float) -> str:
    return "Rarely" if w <= 2 else "Sometimes" if w <= 4 else "Often" if w <= 7 else "Very often"


def weight_from_rank(i: int, n: int, bookmarks: bool = False) -> int:
    r = i / max(1, n)
    return 3 if bookmarks else (10 if r < 0.1 else 6 if r < 0.3 else 3 if r < 0.6 else 1)


def estimate_text(d: dict) -> str:
    kind = (("real browser without images" if d.get("low_data") else "real browser with images")
            if d.get("real_browser") else "plain HTTP")
    return (f"About {d['mb_per_day']} MB a day (≈{d['gb_per_month']} GB a month): ≈{d['actions_per_hour']} actions "
            f"an hour for {d['hours_per_day']:g} hours, {kind}"
            + (f", capped at {d['cap_mb']:g} MB a day" if d.get("cap_mb") else "") + ".")


def urls_from_text(text: str, limit: int = 50000) -> list[str]:
    """Addresses in a bookmarks export, HAR, Takeout JSON or a plain list: only the links are used."""
    seen, out = set(), []
    for m in re.finditer(r"https?://[^\s\"'<>\\,)]+", text):
        u = m.group(0)
        if u not in seen:
            seen.add(u)
            out.append(u)
            if len(out) >= limit:
                break
    if not out:                                          # a plain list of site names, one per line
        for ln in text.splitlines():
            ln = ln.strip().split(",")[0].strip()
            if ln and " " not in ln and "." in ln:
                out.append("https://" + ln)
    return out
