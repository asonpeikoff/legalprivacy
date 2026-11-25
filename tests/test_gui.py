"""Native desktop app. The logic tests need no display and always run; the widget smoke tests skip
cleanly when tkinter or a display is missing (CI has neither)."""
import os
import sys
import tempfile
import time

import pytest

from legalprivacy import gui_logic as L


# ── formatters ──────────────────────────────────────────────────────────────
def test_uptime_formats():
    assert L.fmt_uptime(0) == "—" and L.fmt_uptime(None) == "—"
    assert L.fmt_uptime(5) == "5s" and L.fmt_uptime(125) == "2m 05s"
    assert L.fmt_uptime(3725) == "1h 02m 05s" and L.fmt_uptime(90000) == "1d 01h 00m"


def test_bytes_and_site_names():
    assert L.fmt_bytes(0) == "0 B" and L.fmt_bytes(2048) == "2.0 KB" and L.fmt_bytes(5 * 1024 ** 2) == "5.0 MB"
    assert L.site_name("https://www.example.com/a/b?q=1") == "example.com"
    assert L.site_name("ads.example.org") == "ads.example.org"
    assert L.site_name("example.net/some/page") == "example.net"
    assert L.site_name("pip install numpy") == "pip install numpy"
    long = "abcdefghij" + "a" * 40 + "abcdef.onion"
    assert "…" in L.site_name("http://" + long + "/x")


def test_hit_row_shows_site_only_and_status():
    h = {"seq": 3, "ts": 0, "lane": "clearnet", "engine": "search", "url": "https://www.example.com/secret?q=x",
         "ok": True, "status": 200, "role": "search"}
    seq, _t, lane, kind, site, status, tag = L.hit_row(h)
    assert (seq, lane, kind, site, tag) == (3, "Web (browser)", "search", "example.com", "ok")
    assert "secret" not in site and status == "OK (200)"
    bad = dict(h, ok=False, status=0, error="timeout")
    assert L.hit_row(bad)[5:] == ("timeout", "bad")
    assert L.hit_row(dict(bad, error="site offline"))[5:] == ("site offline", "mute")
    assert L.hit_row(dict(h, role="result"))[3] == "clicked a result"


def test_newest_first_is_capped():
    hits = [{"seq": i} for i in range(1, 701)]
    out = L.newest_first(hits)
    assert len(out) == 500 and out[0]["seq"] == 700 and out[-1]["seq"] == 201


def test_log_line_and_level_filter():
    ev = {"ts": 0, "level": "warn", "source": "tor", "message": "hello"}
    assert "WARN" in L.fmt_log_line(ev) and "[tor] hello" in L.fmt_log_line(ev)
    evs = [{"level": lv} for lv in ("debug", "info", "warn", "error")]
    assert [e["level"] for e in L.visible_events(evs, "warn")] == ["warn", "error"]
    assert len(L.visible_events(evs, "debug")) == 4


# ── state to view ───────────────────────────────────────────────────────────
def test_run_status_and_buttons():
    assert L.run_status({"running": False}) == ("stopped", "Stopped")
    assert L.run_status({"running": True}) == ("running", "Running")
    assert L.run_status({"running": True, "paused": True}) == ("paused", "Paused")
    assert L.button_states({"running": False}) == {"start": True, "pause": False, "stop": False}
    assert L.button_states({"running": True}) == {"start": False, "pause": True, "stop": True}
    assert L.pause_label({"paused": True}) == "Resume" and L.pause_label({}) == "Pause"


def test_tor_chip():
    assert L.tor_chip({}, False)[1] == "off"
    assert L.tor_chip({"state": "ready"}, True) == ("Tor: connected", "ok")
    assert L.tor_chip({"state": "bootstrapping", "bootstrap_pct": 40}, True) == ("Tor: connecting 40%", "warn")
    assert L.tor_chip({"state": "error"}, True)[1] == "bad"


def test_settings_chip_and_apply_message():
    assert L.settings_chip({"running": True, "in_effect": True, "applied_at": 1700000000})[0].startswith("✓ Settings applied ")
    assert L.settings_chip({"running": False}) == ("Settings saved", "off")
    assert L.settings_chip({"running": True, "in_effect": False})[1] == "warn"
    assert L.settings_chip({}, applying=True) == ("Applying…", "warn")
    assert L.settings_chip({}, error="bad value")[1] == "bad"
    assert L.apply_message({"in_effect": True}, True) == ("✓ Live and verified", "ok")
    assert L.apply_message({"in_effect": False}, True)[1] == "warn"
    assert "Start" in L.apply_message({}, False)[0]


def test_lanes_rows_and_now_text():
    st = {"lanes": [{"name": "clearnet", "open": True, "hits": 4, "failures": 1, "last_error": "boom",
                     "engines": {"search": {"spent": 2, "per_day": 5}, "dns": {"spent": 0, "per_day": 8}}}]}
    row = L.lanes_rows(st)[0]
    assert row[0] == "Web (browser)" and row[2:4] == (4, 1) and "searches 2/5" in row[4] and row[5] == "boom"
    assert L.now_text(None).startswith("Idle")
    cur = {"engine": "crawl", "role": "page", "url": "https://www.example.com/x", "started": 100}
    assert L.now_text(cur, now=107) == "Now: on a page: example.com (for 7 s)"
    assert "search results" in L.now_text(dict(cur, role="search"), now=100)


def test_rate_text():
    info = [{"name": f"n{i}", "actions_per_hour": i, "searches_per_hour": i / 2, "vs_average_person": 1.0}
            for i in range(1, 11)]
    assert "Level 3: n3" in L.rate_text(3, info)
    assert L.rate_text(3, None) == "Level 3"


def test_check_lines_and_baseline_text():
    c = {"status": "bad", "title": "Noise is running", "want": "ON", "saw": "OFF", "hint": "Press Start."}
    assert L.check_lines(c) == ("✗  Noise is running", "You want to see: ON", "We saw: OFF", "Press Start.")
    assert L.STATUS_GLYPH == {"ok": "✓", "bad": "✗", "info": "ℹ", "unknown": "?"}
    txt = L.baseline_sources_text({"baseline": {"status": "Not enough.", "sources": [
        {"name": "HAR", "detail": "none", "state": "none", "note": "import one"}]}})
    assert txt.splitlines()[0] == "Not enough." and "HAR: none: none (import one)" in txt


def test_chart_helpers():
    assert L.nice_max(0) == 1.0 and L.nice_max(7) == 10.0 and L.nice_max(0.13) == 0.2 and L.nice_max(23) == 50.0
    assert L.scale(5, 0, 10, 0, 100) == 50 and L.scale(5, 0, 10, 100, 0) == 50 and L.scale(1, 1, 1, 3, 4) == 3


# ── settings <-> controller ─────────────────────────────────────────────────
def test_cookie_unit_round_trip():
    assert L.cookie_to_hours(2, "days") == 48 and L.cookie_to_hours(1.5, "hours") == 1.5
    assert L.cookie_from_hours(48) == (2.0, "days") and L.cookie_from_hours(1) == (1.0, "hours")
    assert L.cookie_from_hours(36) == (36.0, "hours")


def test_payload_only_contains_what_was_given():
    v = {"level": 7.4, "rate_mode": "steady", "dns_mode": "secure", "cookie_value": 2, "cookie_unit": "days",
         "window": "offscreen", "tor_enabled": True, "bridge_mode": "obfs4", "bridge_auto": False,
         "autostart": True}
    p = L.build_config_payload(v, {"randomness": 0.6})
    assert p["rate"] == {"level": 7.0, "mode": "steady", "randomness": 0.0}
    assert p["dns"] == {"mode": "secure"}
    assert p["transports"]["clearnet"] == {"cookie_hours": 48.0, "browser_window": "offscreen"}
    assert p["transports"]["tor"] == {"enabled": True, "bridge_mode": "obfs4", "bridge_auto": False}
    assert L.app_flags(v) == {"autostart": True}
    assert L.build_config_payload({"level": 20})["rate"]["level"] == 10.0
    # random keeps the user's own randomness, or goes fully random from steady
    assert L.build_config_payload({"rate_mode": "random"}, {"randomness": 0.6})["rate"]["randomness"] == 0.6
    assert L.build_config_payload({"rate_mode": "random"}, {"randomness": 0})["rate"]["randomness"] == 1.0
    assert L.build_config_payload({}) == {}


def test_payload_is_accepted_by_the_controller_and_round_trips():
    from legalprivacy.controller import Controller
    ctl = Controller(os.path.join(tempfile.mkdtemp(), "p.yaml"))
    v = L.profile_values(ctl.profile, ctl.app)
    v.update(level=8, dns_mode="system", cookie_value=3, cookie_unit="days", window="offscreen",
             bridge_mode="snowflake", randomness=0)
    ctl.apply_config(L.build_config_payload(v, {"randomness": 1.0}))
    back = L.profile_values(ctl.profile, ctl.app)
    for k in ("level", "dns_mode", "cookie_value", "cookie_unit", "window", "bridge_mode", "randomness"):
        assert back[k] == v[k], k
    ctl.update_app(L.app_flags({"autostart": True, "observe": False, "clear_logs_on_restart": False}))
    assert ctl.app["autostart"] is True and ctl.app["observe"] is False
    ctl.observer.stop()


# ── threads: queue, worker hand-off, debounce, live apply ───────────────────
def test_queue_runs_callbacks_in_order_on_drain():
    q, seen = L.UiQueue(), []
    q.post(seen.append, 1)
    q.post(lambda: 1 / 0)                        # a failing callback must not stop the rest
    q.post(seen.append, 2)
    assert seen == [] and not q.empty()
    assert q.drain() == 3 and seen == [1, 2] and q.empty()


def test_worker_result_and_error_are_handed_back_not_run_in_the_worker():
    import threading
    q, got = L.UiQueue(), []
    main = threading.current_thread()
    L.run_in_thread(lambda: threading.current_thread() is not main, q.post, got.append).join(2)
    L.run_in_thread(lambda: 1 / 0, q.post, None, lambda e: got.append(type(e).__name__)).join(2)
    assert got == []                             # nothing ran the callbacks yet
    q.drain()
    assert got == [True, "ZeroDivisionError"]


class FakeClock:
    def __init__(self):
        self.now, self.jobs, self.n = 0, {}, 0

    def schedule(self, ms, fn):
        self.n += 1
        self.jobs[self.n] = (self.now + ms, fn)
        return self.n

    def cancel(self, h):
        self.jobs.pop(h, None)

    def advance(self, ms):
        self.now += ms
        for h, (t, fn) in sorted(self.jobs.items(), key=lambda kv: kv[1][0]):
            if t <= self.now and h in self.jobs:
                del self.jobs[h]
                fn()


def test_debouncer_fires_once_after_the_last_poke():
    clk, fired = FakeClock(), []
    d = L.Debouncer(clk.schedule, clk.cancel, lambda: fired.append(clk.now), 700)
    d.poke(); clk.advance(300); d.poke(); clk.advance(300); d.poke()
    assert fired == [] and d.pending
    clk.advance(699)
    assert fired == []
    clk.advance(1)
    assert fired == [1300] and not d.pending
    d.poke(); d.flush()
    assert len(fired) == 2 and not d.pending


class FakeCtl:
    def __init__(self, running=True, in_effect=True):
        self.running, self.in_effect, self.calls = running, in_effect, []

    def apply_config(self, cfg):
        self.calls.append(("apply", cfg))

    def update_app(self, flags):
        self.calls.append(("app", flags))

    def settings_status(self):
        return {"running": self.running, "in_effect": self.in_effect}

    def reapply(self):
        self.calls.append(("reapply",))
        self.in_effect = True


def make_live(ctl, collect=None):
    clk, q, reports = FakeClock(), L.UiQueue(), []
    live = L.LiveApply(ctl, collect or (lambda: {"config": {"rate": {"level": 3}}, "app": {"autostart": True}}),
                       q.post, lambda *a: reports.append(a), clk.schedule, clk.cancel, 700)
    return live, clk, q, reports


def wait_drain(q, n=1):
    end = time.time() + 3
    done = 0
    while done < n and time.time() < end:
        done += q.drain()
        time.sleep(0.01)


def test_live_apply_debounces_then_saves_and_reapplies_when_running():
    ctl = FakeCtl(running=True, in_effect=False)
    live, clk, q, reports = make_live(ctl)
    live.changed(); live.changed()
    assert reports[0][0] == "applying" and ctl.calls == []
    clk.advance(700)
    wait_drain(q)
    assert [c[0] for c in ctl.calls] == ["apply", "app", "reapply"]
    assert reports[-1] == ("done", "✓ Live and verified", "ok")


def test_live_apply_while_stopped_just_saves():
    ctl = FakeCtl(running=False)
    live, clk, q, reports = make_live(ctl)
    live.changed(); clk.advance(700); wait_drain(q)
    assert [c[0] for c in ctl.calls] == ["apply", "app"]
    assert reports[-1][0] == "done" and "Start" in reports[-1][1]


def test_live_apply_skips_restart_when_nothing_differs():
    ctl = FakeCtl(running=True, in_effect=True)
    live, clk, q, reports = make_live(ctl)
    live.changed(); clk.advance(700); wait_drain(q)
    assert [c[0] for c in ctl.calls] == ["apply", "app"]


def test_live_apply_reports_errors():
    ctl = FakeCtl()

    def boom(_cfg):
        raise ValueError("dns.mode must be system, secure or mix")
    ctl.apply_config = boom
    live, clk, q, reports = make_live(ctl)
    live.changed(); clk.advance(700); wait_drain(q)
    assert reports[-1] == ("error", "dns.mode must be system, secure or mix", "bad")
    assert not live.busy


def test_palettes_have_the_same_keys():
    assert set(L.LIGHT) == set(L.DARK)


# ── entry point without Tk ─────────────────────────────────────────────────
def test_falls_back_to_the_web_dashboard_without_tkinter(monkeypatch, capsys):
    from legalprivacy import gui, webui
    monkeypatch.setitem(sys.modules, "tkinter", None)            # `import tkinter` now raises ImportError
    called = []
    monkeypatch.setattr(webui, "run_ui", lambda p=None, port=None: called.append((p, port)) or 0)
    assert gui.main("x.yaml", 1234) == 0
    assert called == [("x.yaml", 1234)]
    err = capsys.readouterr().err
    assert "python3-tk" in err and "web dashboard" in err


def test_claim_instance_detects_a_second_copy():
    from legalprivacy import gui
    first = gui.claim_instance(0)                  # any free port
    assert first
    port = first.getsockname()[1]
    assert gui.claim_instance(port) is None
    first.close()


def test_logo_is_drawn_without_image_files():
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    try:
        from legalprivacy import gui
        img = gui.make_logo(tk, 32, "#000000", "#ffffff")
        assert img.width() == 32 and img.height() == 32
    finally:
        root.destroy()


# ── widget smoke test (skips without Tk or a display) ──────────────────────
@pytest.fixture
def tk_app(tmp_path, monkeypatch):
    tk = pytest.importorskip("tkinter")
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    from legalprivacy import gui
    from legalprivacy.controller import Controller
    ctl = Controller(str(tmp_path / "p.yaml"))
    app = gui.build_app_class()(root, ctl, 0)

    def pump(seconds=1.0):
        end = time.time() + seconds
        while time.time() < end:
            root.update()
            time.sleep(0.02)
    app.pump_for = pump
    yield app
    try:
        app.closing = True
        ctl.observer.stop()
        root.destroy()
    except tk.TclError:
        pass


def test_window_builds_polls_and_saves_a_change(tk_app):
    app = tk_app
    app.pump_for(1.6)
    assert [t.title for t in app.tabs] == ["Dashboard", "Activity", "Live Log", "Tor", "Settings", "My List", "ML",
                                           "Proof", "Security", "Tools", "Health", "Help"]
    assert app.state.get("version") and app.status_var.get() == "Stopped"
    assert str(app.b_start.cget("state")) != "disabled" and "disabled" in app.b_stop.state()
    assert "Applying" not in app.set_chip.cget("text")
    dash = app.tabs[0]
    dash.level.set(9)
    dash._snap()
    assert app.set_chip.cget("text") == "Applying…"
    app.pump_for(2.0)
    assert app.ctl.profile.rate.level == 9.0
    assert "Start" in app.apply_var.get() or "Live" in app.apply_var.get()
    app.tabs[4].load({"dns_mode": "system"})            # setting a control saves it like a click would
    app.pump_for(2.0)
    assert app.ctl.profile.dns.mode == "system"
    # the log tab got the start-up lines; dark mode switches without error
    assert "legalPrivacy" in app.tabs[2].text.get("1.0", "end")
    app.set_theme("dark")
    app.set_theme("light")
    # proof tab renders the checks and the three charts from real controller data
    app.nb.select(7)
    app.pump_for(3.0)
    assert app.tabs[7].headline.get()
    assert app.tabs[7].verdicts["intended"].get().startswith("Reads as")


def test_every_tab_opens_and_the_controls_match_the_profile(tk_app):
    app = tk_app
    app.pump_for(1.0)
    for i, _t in enumerate(app.tabs):
        app.nb.select(i)
        app.pump_for(0.2)
    vals = {}
    for t in app.tabs:
        vals.update(t.values())
    want = L.profile_values(app.ctl.profile, app.ctl.app)
    for k in ("level", "dns_mode", "typos", "persona", "q_live", "tor_enabled", "bridge_mode", "mobile_share",
              "mylist_share", "speed", "window", "traffic_pattern", "ua_choice"):
        assert vals[k] == want[k], k


def test_the_traffic_mix_bar_adds_up_to_100_and_saves(tk_app):
    app = tk_app
    app.pump_for(1.0)
    mix = app.tabs[0].traffic_mix
    assert abs(sum(mix.values().values()) - 100) < 0.2
    mix._moved(1, 30)                                  # as if the plain-HTTP slider were dragged to 30%
    assert mix.values() == {"mix_browser": 70.0, "mix_plain": 30.0}
    app.pump_for(2.0)
    assert (app.ctl.profile.traffic.browser, app.ctl.profile.traffic.plain) == (70.0, 30.0)
    eng = app.tabs[0].eng_mix
    eng._moved(0, 0)                                   # 0% turns a part off
    app.pump_for(2.0)
    assert app.ctl.profile.engines[eng.items[0]["key"]].enabled is False
    assert abs(sum(eng.values().values()) - 100) < 0.2


def test_logo_easter_egg_needs_something_a_normal_user_would_not_do(tk_app, tmp_path, monkeypatch):
    from legalprivacy import gui
    f = tmp_path / "logo_egg"
    monkeypatch.setattr(gui, "_egg_file", lambda: f)
    app = tk_app
    app._egg = False
    app._show_logo(0)
    assert app._logo_now is app.logo_trad                       # the plain wordmark by default
    for _ in range(2):
        app._logo_click()
    assert not app._egg                                         # two clicks are nothing special
    app._logo_click()
    assert app._egg and f.exists() and app._logo_now is app.logos[0]
    app._logo_click()
    assert app._logo_now is app.logos[1]                        # now clicking switches versions
    app._show_logo(3)
    assert app._logo_now is app.logos[3]                        # and tabs pick their own
    app._logo_keys = gui.KONAMI[:-1]

    class Ev:
        keysym, widget = "a", app.root

    app._logo_key(Ev)                                           # the Konami code undoes it
    assert not app._egg and not f.exists() and app._logo_now is app.logo_trad


def test_nudge_buttons_move_the_mix_and_save_it(tk_app):
    app = tk_app
    tab = next(t for t in app.tabs if type(t).__name__ == "DashboardTab")
    app.ctl.apply_config({"traffic": {"browser": 100, "plain": 0}})
    tab._show_nudge(app.ctl.mix_status())
    assert tab.nudge_rows["browser"][1].cget("text") == "100%" and str(tab.nudge_rows["browser"][3].cget("state")) == "disabled"
    app.work = lambda fn, done=None, error=None: done and done(fn())          # run inline for the test
    app.flash = lambda *_a, **_k: None
    tab.nudge("browser", -1)
    assert tab.nudge_rows["browser"][1].cget("text") == "90%" and tab.nudge_rows["plain"][1].cget("text") == "10%"
    assert app.ctl.profile.traffic.plain == 10.0 and not tab.nudge_busy
    tab.nudge("phones", 1)
    assert tab.nudge_rows["phones"][1].cget("text") == "65%"


def test_tor_tab_has_the_tor_browser_card_like_the_web_dashboard(tk_app, monkeypatch):
    app = tk_app
    tab = next(t for t in app.tabs if type(t).__name__ == "TorTab")
    tab._tb_show({"supported": True, "installed": None, "latest": "15.0.1", "state": "idle", "progress": 0,
                  "update_available": False, "signature": None})
    assert tab.b_tb_open.cget("text") == "Install and open Tor Browser"
    assert "Not installed yet" in tab.tb_stat.cget("text") and "15.0.1" in tab.tb_stat.cget("text")
    tab._tb_show({"supported": True, "installed": "14.5.8", "latest": "15.0.1", "update_available": True, "state": "idle",
                  "signature": {"ok": True, "fingerprint": "ABCDEF0123456789ABCDEF0123456789ABCDEF01", "at": 1_800_000_000}})
    assert tab.b_tb_open.cget("text") == "Open Tor Browser" and "update will be installed" in tab.tb_stat.cget("text")
    assert "Signature verified" in tab.tb_sig.cget("text") and "23456789ABCDEF01" in tab.tb_sig.cget("text")
    tab._tb_show({"supported": True, "installed": None, "state": "installing", "progress": 0.42})
    assert "42%" in tab.tb_stat.cget("text")
    opened = []
    import webbrowser
    monkeypatch.setattr(webbrowser, "open", lambda u, *a, **k: opened.append(u))
    tab._tb_show({"supported": False, "download_page": "https://example.invalid/tb"})
    assert tab.b_tb_open.cget("text").startswith("Get Tor Browser")
    tab.tb_open()
    assert opened == ["https://example.invalid/tb"]                      # nothing to install here: the download page
    # sharing the app's Tor is a saved setting, like the web dashboard's tickbox
    from legalprivacy import gui_fields as F
    assert F.FIELDS["tor_share_browser"][0] == ("transports", "tor", "share_browser")
