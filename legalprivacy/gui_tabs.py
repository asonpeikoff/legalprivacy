"""Dashboard, Activity, Live Log, Tor and Proof tabs of the native app. Each tab reads what it shows from the
state the app polls (`update_state`), reports edits with `app.edited()` and never blocks: slow work goes
through `app.work(...)`."""
from __future__ import annotations

import csv
import json
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import gui_fields as F
from . import gui_logic as L
from .gui_base import Tab
from .gui_charts import BaselineChart, IntendedChart, SessionChart, TimelineChart
from .gui_theme import Banner, Card, MixBar, ScrollFrame, Sparkline, autowrap, tip

GAP = 12


def grid_cards(parent, cards: list, columns: int) -> None:
    """Lay cards out in equal-width columns."""
    for c in range(columns):
        parent.columnconfigure(c, weight=1, uniform="cards")
    for i, card in enumerate(cards):
        card.grid(row=i // columns, column=i % columns, sticky="nsew", padx=(0 if i % columns == 0 else GAP // 2, 0 if i % columns == columns - 1 else GAP // 2),
                  pady=(0, GAP))


class Kpi(Card):
    def __init__(self, master, app, title: str):
        super().__init__(master, app, title, pad=14)
        self.value = tk.StringVar(value="—")
        self.sub = tk.StringVar()
        ttk.Label(self.body, textvariable=self.value, style="KPI.TLabel").pack(anchor="w")
        ttk.Label(self.body, textvariable=self.sub, style="CardMuted.TLabel").pack(anchor="w")

    def set(self, value, sub: str = "") -> None:
        self.value.set(str(value))
        self.sub.set(sub)


# ── Dashboard ───────────────────────────────────────────────────────────────
class DashboardTab(Tab):
    title, icon = "Dashboard", "dash"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.sf = ScrollFrame(self, app)
        self.sf.grid(sticky="nsew")
        f = self.sf.inner
        f.columnconfigure(0, weight=1)
        self.rate_info: list = []
        self._mix_keys: dict = {}

        head = ttk.Frame(f)
        head.grid(row=0, column=0, sticky="ew", pady=(0, GAP))
        head.columnconfigure(1, weight=1)
        self.state_var = tk.StringVar(value="Stopped")
        ttk.Label(head, textvariable=self.state_var, style="H1.TLabel").grid(row=0, column=0, sticky="w")
        self.now = Banner(head, L.now_text(None), "off", host=head)
        self.now.grid(row=0, column=1, sticky="ew", padx=(16, 0))

        kp = ttk.Frame(f)
        kp.grid(row=1, column=0, sticky="ew")
        self.k_hits, self.k_fail, self.k_up, self.k_last, self.k_data = (
            Kpi(kp, app, t) for t in ("Hits today", "Failures", "Running for", "Last hit", "Data today"))
        grid_cards(kp, [self.k_hits, self.k_fail, self.k_up, self.k_last, self.k_data], 5)

        sc = Card(f, app, "Hits per minute (last 30 minutes)", "act")
        sc.grid(row=2, column=0, sticky="ew", pady=(0, GAP))
        self.spark = Sparkline(sc.body, app)
        self.spark.pack(fill="x")

        lc = Card(f, app, "Lanes", "list", help="Each lane is one kind of noise with its own daily budgets.")
        lc.grid(row=3, column=0, sticky="ew", pady=(0, GAP))
        app.btn(lc.actions, "Send one test hit", "play", "secondary", self.test_hit,
                "Fires a single noise request immediately and shows it in Activity.").pack()
        cols = ("lane", "does", "hits", "fails", "budget", "problem")
        self.tree = ttk.Treeview(lc.body, columns=cols, show="headings", height=3, selectmode="none")
        for c, t, w in (("lane", "Lane", 120), ("does", "What it does", 200), ("hits", "Hits", 60), ("fails", "Failed", 60),
                        ("budget", "Today (done / allowed)", 300), ("problem", "Last problem", 160)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="e" if c in ("hits", "fails") else "w", stretch=c in ("budget", "problem"))
        self.tree.pack(fill="x")
        self.empty = lc.note("No lanes yet. Press Start (F5) and the lanes appear here with their hits and budgets.",
                             pady=(8, 0))

        # Nudge the mix: a few buttons that steer the traffic mix live
        self.nudge_card = Card(f, app, "Nudge the mix", "act",
                               help="Each press moves one part of the traffic mix up or down by 10 points and the rest "
                                    "give or take the difference. It applies live and is saved. Fine control is in "
                                    "Traffic mix below.")
        self.nudge_card.grid(row=4, column=0, sticky="ew", pady=(0, GAP))
        self.nudge_rows: dict = {}
        for key, label in L.NUDGE_PARTS:
            r = self.nudge_card.row((4, 0))
            self.nudge_card.lbl(r, label, False).pack(side="left")
            plus = app.btn(r, "+", None, "secondary", lambda k=key: self.nudge(k, 1), "More of this")
            plus.pack(side="right")
            pct = self.nudge_card.lbl(r, "—", False)
            pct.configure(width=7, anchor="center")
            pct.pack(side="right", padx=6)
            minus = app.btn(r, "\u2212", None, "secondary", lambda k=key: self.nudge(k, -1), "Less of this")
            minus.pack(side="right")
            self.nudge_rows[key] = (r, pct, minus, plus)
        self.nudge_busy = False

        # How much noise
        nc = Card(f, app, "How much noise", "set")
        nc.grid(row=5, column=0, sticky="ew", pady=(0, GAP))
        self.level = tk.DoubleVar(value=5)
        r = nc.row()
        nc.lbl(r, "How much", False).pack(side="left")
        nc.lbl(r, "  the average amount, however random you make it", True).pack(side="left")
        r = nc.row()
        nc.lbl(r, "Less", True).pack(side="left")
        self.scale = ttk.Scale(r, from_=1, to=10, variable=self.level, command=self._snap, style="Card.Horizontal.TScale")
        self.scale.pack(side="left", fill="x", expand=True, padx=8)
        nc.lbl(r, "More", True).pack(side="left")
        tip(self.scale, "Level 1-10. Even the highest level stays under what gets one address rate-limited.")
        self._reg("level", lambda: int(round(self.level.get())), lambda x: (self.level.set(x), self._text()))
        self.rate_msg = nc.note("", muted=True)
        self.scope_msg = nc.note("", muted=True)
        r = nc.row((8, 2))
        nc.lbl(r, "How random").pack(side="left")
        nc.lbl(r, "  how much each hour varies around that average", True).pack(side="left")
        r = nc.row()
        nc.lbl(r, "Steady", True).pack(side="left")
        self.rand = tk.DoubleVar(value=100)
        self.rand_scale = ttk.Scale(r, from_=0, to=100, variable=self.rand, command=self._rand_moved,
                                    style="Card.Horizontal.TScale")
        self.rand_scale.pack(side="left", fill="x", expand=True, padx=8)
        nc.lbl(r, "Random", True).pack(side="left")
        self._reg("randomness", lambda: int(round(self.rand.get() / 10) * 10),
                  lambda x: (self.rand.set(x), self.rand_msg.configure(text=F.rand_text(int(x)))))
        self.rand_msg = nc.note("", muted=True)
        nc.heading("Mix of activity", "always adds up to 100%; drag one and the others make room. 0% turns that part off")
        self.eng_mix = MixBar(nc.body, app, [], self.app.edited)
        self.eng_mix.pack(fill="x")
        self.eng_note = nc.note("Onion sites join this mix automatically when Tor is on (Tor tab).", pady=(4, 0))
        self._reg("engines_mix", self.eng_mix.values, lambda x: None)

        # Traffic mix
        tc = Card(f, app, "Traffic mix", "web", help="Ordinary web noise never goes through Tor; .onion noise always "
                                                      "does, in its own lane.")
        tc.grid(row=6, column=0, sticky="ew", pady=(0, GAP))
        tc.note("What kinds of noise run, and how the mix changes over time.")
        tc.heading("How the mix changes")
        self.f_radios(tc, "traffic_pattern", [
            ("drift", "Drift (recommended)", "The shares wander slowly through the day, like a person who browses more on "
                                              "the phone some hours and more on the computer others."),
            ("blend", "Blend", "The same mix every hour."),
            ("alternate", "Alternate", "One kind at a time, switching every 1-3 hours.")])
        tc.heading("How much of each", "always adds up to 100%")
        self.traffic_mix = MixBar(tc.body, app, [], self.app.edited)
        self.traffic_mix.pack(fill="x")
        self.onion_note = tc.note("Onion sites join this mix automatically when Tor is on (Tor tab).", pady=(4, 0))
        self._reg("traffic_mix", self.traffic_mix.values, lambda x: None)
        tc.heading("Phones")
        r = tc.row()
        tc.lbl(r, "Share of noise that is a phone").pack(side="left")
        self.f_spin(r, "mobile_share", 0, 100, 5, 5).pack(side="left", padx=6)
        tc.lbl(r, "%  (55% recommended: most browsing happens on phones)", True).pack(side="left")
        r = tc.row()
        tc.lbl(r, "Phone to emulate").pack(side="left")
        self.f_combo(r, "device", [("iPhone 13", "iPhone 13 (recommended)"), ("iPhone 15", "iPhone 15"),
                                   ("iPhone SE (3rd gen)", "iPhone SE (3rd gen)"), ("Pixel 7", "Pixel 7"),
                                   ("Galaxy S24", "Galaxy S24"), ("mix", "Mix of phones (mostly iPhone 13)")],
                     30).pack(side="left", padx=8)
        tc.note("In the real browser, a phone gets that phone's screen size, touch input and its own browser's user agent. "
                "It still runs on this computer's Chromium underneath, so a site that checks deeply can tell.")

    # -- values/load for the two mix bars
    def values(self) -> dict:
        v = super().values()
        v.pop("traffic_mix", None)
        v.update({k: x for k, x in self.traffic_mix.values().items()})
        return v

    def load(self, v: dict) -> None:
        super().load(v)
        tor_on = bool(v.get("tor_enabled"))
        pkg = v.get("packages") == "on" or (v.get("packages") != "off" and v.get("persona") in ("Ason", "Data scientist", "Developer"))
        names = F.visible_engines(self.app.ctl.profile.engines, tor_on, pkg)
        eng_vals = v.get("engines_mix", {})
        if self._mix_keys.get("eng") != names:
            self._mix_keys["eng"] = names
            self.eng_mix.set_items(F.engine_items(eng_vals, names))
        else:
            self.eng_mix.set_values(eng_vals)
        items = F.traffic_items(v, tor_on)
        keys = [i["key"] for i in items]
        if self._mix_keys.get("traffic") != keys:
            self._mix_keys["traffic"] = keys
            self.traffic_mix.set_items(items)
        else:
            self.traffic_mix.set_values(v)
        for note in (self.eng_note, self.onion_note):
            note.configure(text="" if tor_on else "Onion sites join this mix automatically when Tor is on (Tor tab).")
        self.scope_msg.configure(text=F.level_scope(bool(v.get("clearnet_enabled", True)), tor_on))
        self._text()

    def retheme(self) -> None:
        self.sf.retheme()
        self.spark.redraw()
        self.eng_mix.retheme()
        self.traffic_mix.retheme()

    def _snap(self, _v=None) -> None:
        v = int(round(self.level.get()))
        if abs(self.level.get() - v) > 1e-6:
            self.level.set(v)
        self._text()
        self.app.edited()

    def _text(self) -> None:
        self.rate_msg.configure(text=L.rate_text(self.level.get(), self.rate_info))

    def _rand_moved(self, _v=None) -> None:
        v = int(round(self.rand.get() / 10) * 10)
        if abs(self.rand.get() - v) > 1e-6:
            self.rand.set(v)
        self.rand_msg.configure(text=F.rand_text(v))
        self.app.edited()

    def test_hit(self) -> None:
        self.app.work(self.app.ctl.test_once, done=lambda _r: self.app.flash("Sent one test hit; see Activity."))

    def nudge(self, what: str, direction: int) -> None:
        if self.nudge_busy:
            return
        self.nudge_busy = True
        self._show_nudge(self.app.ctl.mix_status())

        def done(m):
            self.nudge_busy = False
            self._show_nudge(m)
            self.app.flash("Mix nudged" + (" and applied." if self.app.ctl.running else "."))

        def error(exc):
            self.nudge_busy = False
            self._show_nudge(self.app.ctl.mix_status())
            self.app.error("Could not nudge the mix", exc)

        self.app.work(lambda: self.app.ctl.nudge_mix(what, direction), done=done, error=error)

    def _show_nudge(self, m: dict) -> None:
        for key, (row, pct, minus, plus) in self.nudge_rows.items():
            if key == "onion":
                if m["tor"]:
                    row.pack(fill="x", pady=(4, 0))
                else:
                    row.pack_forget()
                    continue
            v = m["phones"] if key == "phones" else m["shares"].get(key, 0.0)
            pct.configure(text=f"{v:g}%")
            for b, off in ((minus, v <= 0), (plus, v >= 100)):
                b.configure(state="disabled" if off or self.nudge_busy else "normal")

    def update_state(self, st: dict) -> None:
        kind, text = L.run_status(st)
        self.state_var.set(text)
        if st.get("mix") and not self.nudge_busy:
            self._show_nudge(st["mix"])
        lanes = st.get("lanes") or []
        hits, fails = sum(x.get("hits", 0) for x in lanes), sum(x.get("failures", 0) for x in lanes)
        self.k_hits.set(f"{hits:,}", " · ".join(f"{L.lane_label(x['name'])} {x.get('hits', 0)}" for x in lanes))
        self.k_fail.set(f"{fails:,}", "network errors / blocks")
        self.k_up.set(L.fmt_uptime(st.get("uptime")) if st.get("running") else "—",
                      f"about {st['hour_target']} action{'' if st['hour_target'] == 1 else 's'} this hour" if st.get("hour_target") else "")
        last = max([x.get("last_hit_ts") or 0 for x in lanes] or [0])
        self.k_last.set(L.fmt_ago(last), L.clock12(last, seconds=True) if last else "")
        cap = st.get("data_cap_mb")
        self.k_data.set(L.fmt_bytes(st.get("bytes_today")), f"of {cap:g} MB allowed" if cap else "approximate")
        if st.get("running") and not st.get("paused"):
            self.now.configure(text=L.now_text(st.get("current")), style="Noteinfo.TLabel")
        else:
            self.now.configure(text="Paused." if st.get("paused") else "Idle: the noise is not running.",
                               style="Notewarn.TLabel" if st.get("paused") else "Noteoff.TLabel")
        self.rate_info = st.get("rate_info") or self.rate_info
        self._text()
        self.spark.set_values(L.hits_per_minute(self.app.ctl.hits(0), time.time(), 30))
        rows = L.lanes_rows(st)
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            self.tree.insert("", "end", values=r)
        self.tree.configure(height=max(1, len(rows)))
        if rows:
            self.empty.pack_forget()
        elif not self.empty.winfo_ismapped():
            self.empty.pack(fill="x", anchor="w", pady=(8, 0))


# ── Activity ────────────────────────────────────────────────────────────────
class ActivityTab(Tab):
    title, icon = "Activity", "act"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.configure(padding=(18, 14))
        bar = ttk.Frame(self)
        bar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        ttk.Label(bar, text="Recent hits, newest first. Only the site name is shown, never a full page address.",
                  style="Muted.TLabel").pack(side="left")
        app.btn(bar, "Export JSON", None, "ghost", lambda: self.export("json")).pack(side="right")
        app.btn(bar, "Export CSV", None, "ghost", lambda: self.export("csv")).pack(side="right")
        fl = ttk.Frame(self)
        fl.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        self.lane_f, self.kind_f, self.err_f, self.q_f = tk.StringVar(value="All lanes"), tk.StringVar(value="All kinds"), \
            tk.BooleanVar(), tk.StringVar()
        self.lane_box = ttk.Combobox(fl, state="readonly", width=14, textvariable=self.lane_f,
                                     values=["All lanes", "Web (browser)", "Web (plain)", "Onion (Tor)"])
        self.kind_box = ttk.Combobox(fl, state="readonly", width=16, textvariable=self.kind_f,
                                     values=["All kinds", "search", "page", "DNS lookup", "onion page", "package",
                                             "clicked a result"])
        self.lane_box.pack(side="left")
        self.kind_box.pack(side="left", padx=6)
        ttk.Checkbutton(fl, text="Problems only", variable=self.err_f).pack(side="left", padx=6)
        ttk.Entry(fl, textvariable=self.q_f, width=22).pack(side="left", padx=6)
        ttk.Label(fl, text="filter by site", style="Muted.TLabel").pack(side="left")
        for w in (self.lane_f, self.kind_f, self.err_f, self.q_f):
            w.trace_add("write", lambda *_a: self.render())
        cols = ("time", "lane", "kind", "site", "status", "detail", "ms")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="browse")
        for c, t, w in (("time", "Time", 80), ("lane", "Lane", 110), ("kind", "Kind", 110), ("site", "Site", 260),
                        ("status", "Status", 120), ("detail", "Details", 220), ("ms", "ms", 60)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="e" if c == "ms" else "w", stretch=c in ("site", "detail"))
        sb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.grid(row=2, column=0, sticky="nsew")
        sb.grid(row=2, column=1, sticky="ns")
        self.rowconfigure(2, weight=1)
        self.rowconfigure(1, weight=0)
        self.empty = ttk.Label(self.tree, text="Nothing here yet.\nPress Start (F5): each request the noise makes "
                                               "shows up here with what happened on it.", style="Muted.TLabel", justify="center")
        self.count = tk.StringVar()
        ttk.Label(self, textvariable=self.count, style="Muted.TLabel").grid(row=3, column=0, sticky="w", pady=(6, 0))
        self.hits: list[dict] = []
        self.last_seq = 0
        self.retheme()

    def retheme(self) -> None:
        p = self.app.pal
        self.tree.tag_configure("ok", foreground=p["ok"])
        self.tree.tag_configure("bad", foreground=p["bad"])
        self.tree.tag_configure("mute", foreground=p["muted"])

    def _match(self, h: dict) -> bool:
        row = L.hit_row(h)
        lane, kind = self.lane_f.get(), self.kind_f.get()
        if lane not in ("", "All lanes") and row[2] != lane:
            return False
        if kind not in ("", "All kinds") and row[3] != kind:
            return False
        if self.err_f.get() and row[6] == "ok":
            return False
        q = self.q_f.get().strip().lower()
        return not q or q in row[4].lower()

    def render(self) -> None:
        self.tree.delete(*self.tree.get_children())
        shown = [h for h in L.newest_first(self.hits) if self._match(h)]
        for h in shown:
            r = L.hit_row(h)
            self.tree.insert("", "end", iid=f"h{r[0]}", values=(r[1], r[2], r[3], r[4], r[5], L.hit_detail(h), L.hit_ms(h)),
                             tags=(r[6],))
        self.count.set(f"{len(shown)} shown of {len(self.hits)} recent hits (up to {L.ACTIVITY_MAX_ROWS} are kept)")
        if self.hits:
            self.empty.place_forget()
        else:
            self.empty.place(relx=0.5, rely=0.4, anchor="center")

    def update_state(self, st: dict) -> None:
        new = self.app.ctl.hits(self.last_seq)
        if not new:
            if not self.hits:
                self.render()
            return
        self.hits.extend(new)
        del self.hits[:-L.ACTIVITY_MAX_ROWS]
        self.last_seq = max(h["seq"] for h in new)
        self.render()

    def export(self, kind: str) -> None:
        rows = self.app.ctl.hits(0)
        if not rows:
            self.app.flash("Nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(parent=self.app.root, defaultextension="." + kind,
                                            initialfile="legalprivacy-activity." + kind)
        if not path:
            return
        cols = ["seq", "ts", "lane", "engine", "url", "status", "ok", "latency_ms", "note", "role", "detail", "error"]

        def go():
            with open(path, "w", encoding="utf-8", newline="") as fh:
                if kind == "json":
                    json.dump(rows, fh, indent=1)
                else:
                    w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
                    w.writeheader()
                    w.writerows(rows)
        self.app.work(go, done=lambda _r: self.app.flash(f"Saved {len(rows)} rows."), error=lambda e: self.app.error("Export", e))


# ── Live Log ────────────────────────────────────────────────────────────────
class LogTab(Tab):
    title, icon = "Live Log", "log"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.configure(padding=(18, 14))
        bar = ttk.Frame(self)
        bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Label(bar, text="Show").pack(side="left")
        self.level = tk.StringVar(value=L.LOG_LEVEL_LABELS["info"])
        self.level_box = ttk.Combobox(bar, state="readonly", width=22, textvariable=self.level,
                                      values=[L.LOG_LEVEL_LABELS[k] for k in L.LOG_LEVEL_ORDER])
        self.level_box.pack(side="left", padx=8)
        self.level_box.bind("<<ComboboxSelected>>", lambda _e: self.render_all())
        self.hold = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Pause scrolling", variable=self.hold).pack(side="left", padx=10)
        app.btn(bar, "Clear", None, "ghost", self.clear, "Forget everything in the live log").pack(side="right")
        app.btn(bar, "Copy", None, "ghost", self.copy, "Copy the selection, or the whole log, to the clipboard").pack(side="right")
        self.text = tk.Text(self, wrap="none", height=10, state="disabled", relief="flat", borderwidth=0,
                            highlightthickness=1, font=app.fonts["mono"], padx=10, pady=8)
        sy = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        sx = ttk.Scrollbar(self, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.text.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        sy.grid(row=1, column=1, sticky="ns", pady=(8, 0))
        sx.grid(row=2, column=0, sticky="ew")
        self.events: list[dict] = []
        self.last_id = 0
        self.epoch = None
        app.text_widgets.append(self.text)
        self.retheme()

    def min_level(self) -> str:
        for k, lab in L.LOG_LEVEL_LABELS.items():
            if lab == self.level.get():
                return k
        return "info"

    def retheme(self) -> None:
        p = self.app.pal
        self.text.configure(bg=p["log_bg"], fg=p["fg"], insertbackground=p["fg"], selectbackground=p["select"],
                            selectforeground=p["fg"], highlightbackground=p["border"], highlightcolor=p["border"])
        for tag, col in (("debug", p["muted"]), ("info", p["fg"]), ("warn", p["warn"]), ("error", p["bad"])):
            self.text.tag_configure(tag, foreground=col)

    def _insert(self, evs: list[dict]) -> None:
        if not evs:
            return
        self.text.configure(state="normal")
        for e in evs:
            self.text.insert("end", L.fmt_log_line(e) + "\n", e["level"] if e["level"] in L.LOG_LEVEL_ORDER else "info")
        lines = int(self.text.index("end-1c").split(".")[0])
        if lines > L.LOG_MAX_LINES:
            self.text.delete("1.0", f"{lines - L.LOG_MAX_LINES + 1}.0")
        self.text.configure(state="disabled")
        if not self.hold.get():
            self.text.see("end")

    def render_all(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        if not self.events:
            self.text.insert("end", "Nothing logged yet. Everything the app and Tor say appears here as it happens.\n", "debug")
        self.text.configure(state="disabled")
        self._insert(L.visible_events(self.events, self.min_level())[-L.LOG_MAX_LINES:])

    def update_state(self, st: dict) -> None:
        ep = st.get("log_epoch")
        if self.epoch is not None and ep != self.epoch:        # the app cleared its log: empty our copy too
            self.events.clear()
            self.render_all()
        self.epoch = ep
        new = self.app.ctl.log.since(self.last_id, "debug", limit=1000)
        if new:
            first = not self.events
            self.last_id = new[-1]["id"]
            self.events.extend(new)
            del self.events[:-L.LOG_MAX_LINES]
            if first:
                self.render_all()
            else:
                self._insert(L.visible_events(new, self.min_level()))

    def copy(self) -> None:
        try:
            data = self.text.get("sel.first", "sel.last")
        except tk.TclError:
            data = self.text.get("1.0", "end-1c")
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(data)
        self.app.flash("Log copied to the clipboard.")

    def clear(self) -> None:
        self.app.ctl.log.clear()
        self.events.clear()
        self.render_all()


# ── Tor ─────────────────────────────────────────────────────────────────────
class TorTab(Tab):
    title, icon = "Tor", "tor"

    def _mix_text(self, tor_on: bool, onion_on: bool) -> None:
        web_on = bool(self.app.ctl.profile.transports["clearnet"].enabled)
        from .gui_logic import tor_mix_text
        self.mix_note.configure(text=tor_mix_text(tor_on, onion_on, web_on))

    def __init__(self, nb, app):
        super().__init__(nb, app)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.sf = ScrollFrame(self, app)
        self.sf.grid(sticky="nsew")
        f = self.sf.inner
        f.columnconfigure(0, weight=1)
        Banner(f, "Tor is optional. When on, it visits real .onion sites (darknet noise); ordinary web noise never goes "
                  "through Tor. legalPrivacy runs its own private Tor in the background and never touches your system "
                  "Tor or Tor Browser.", "tor", host=f).grid(row=0, column=0, sticky="ew", pady=(0, GAP))

        top = ttk.Frame(f)
        top.grid(row=1, column=0, sticky="ew")
        sc = Card(top, app, "Status", "tor")
        self.state_var = tk.StringVar(value="Stopped")
        ttk.Label(sc.body, textvariable=self.state_var, style="KPI.TLabel").pack(anchor="w")
        self.bar = ttk.Progressbar(sc.body, mode="determinate", maximum=100, style="Tor.Horizontal.TProgressbar")
        self.bar.pack(fill="x", pady=8)
        self.sum_var = tk.StringVar()
        self.sum_lbl = ttk.Label(sc.body, textvariable=self.sum_var, style="CardMuted.TLabel", justify="left")
        self.sum_lbl.pack(fill="x", anchor="w")
        autowrap(self.sum_lbl, sc.body, 8)
        dc = Card(top, app, "Details")
        self.kv = ttk.Frame(dc.body, style="CardBody.TFrame")
        self.kv.pack(fill="x")
        grid_cards(top, [sc, dc], 2)

        cc = Card(f, app, "Control", "power" if False else "play")
        cc.grid(row=2, column=0, sticky="ew", pady=(0, GAP))
        r = cc.row()
        self.b_start = app.btn(r, "Start Tor", "play", "tor", lambda: self.act("start"))
        self.b_stop = app.btn(r, "Stop Tor", "stop", "secondary", lambda: self.act("stop"))
        self.b_restart = app.btn(r, "Restart", "refresh", "secondary", lambda: self.act("restart"),
                                 "Stop and start the Tor program: it reconnects to the Tor network from scratch (10-30 seconds).")
        self.b_new = app.btn(r, "New identity", "bolt", "secondary", lambda: self.act("newnym"),
                             "Tor keeps running and uses fresh circuits (a new path and exit) for new connections.")
        self.b_install = app.btn(r, "Install / update Tor", None, "secondary", lambda: self.act("install"))
        self.b_test = app.btn(r, "Test Tor", "check", "secondary", self.selftest,
                              "Checks that traffic leaves through Tor and that an onion site loads.")
        for b in (self.b_start, self.b_stop, self.b_restart, self.b_new, self.b_install, self.b_test):
            b.pack(side="left", padx=(0, 6))
        self.install_note = cc.note("", pady=(6, 0))
        self.test_note = cc.note("", muted=False, pady=(2, 6))
        self.mix_note = cc.note("", muted=False, pady=(2, 8))
        v_tor = self.f_check(cc, "tor_enabled", "Run the app's private Tor",
                             "Starts Tor in the background (installed for you if needed). Tick this first: onion sites, "
                             "Tor DNS and relays all need it.")
        v_onion = self.f_check(cc, "tor_onion", "Include .onion sites in the noise",
                               "Needs Tor above. Adds visits to real .onion websites, which never leave the Tor network. "
                               "If this is off, Tor runs but no onion sites are visited.")
        for var in (v_tor, v_onion):
            var.trace_add("write", lambda *_a: self._mix_text(v_tor.get(), v_onion.get()))
        self._mix_text(v_tor.get(), v_onion.get())
        self.f_check(cc, "tor_manage", "Let legalPrivacy manage Tor (recommended)",
                     "Untick to use an existing Tor at the addresses below instead.")
        r = cc.row((6, 0))
        cc.lbl(r, "SOCKS").pack(side="left")
        self.f_entry(r, "tor_socks", 20).pack(side="left", padx=(6, 14))
        cc.lbl(r, "Control").pack(side="left")
        self.f_entry(r, "tor_control", 20).pack(side="left", padx=6)

        ci = Card(f, app, "Circuits")
        ci.grid(row=3, column=0, sticky="ew", pady=(0, GAP))
        self.circ_head = ci.note("", pady=(0, 4))
        self.circ = ttk.Treeview(ci.body, columns=("id", "status", "purpose", "path"), show="headings", height=4,
                                 selectmode="none")
        for c, t, w in (("id", "ID", 50), ("status", "Status", 80), ("purpose", "Purpose", 140), ("path", "Path", 420)):
            self.circ.heading(c, text=t)
            self.circ.column(c, width=w, stretch=c == "path")
        self.circ.pack(fill="x")

        mid = ttk.Frame(f)
        mid.grid(row=4, column=0, sticky="ew")
        sd = Card(mid, app, "Onion seed sites")
        sd.note("One onion address per line. The recommended list is filled in; add, remove or edit freely. Every address "
                "is checked offline before use.")
        self.f_text(sd.body, "tor_seeds", 7, 50).pack(fill="both", expand=True)
        r = sd.row((6, 0))
        app.btn(r, "Reset to the recommended list", "refresh", "secondary", self.reset_seeds).pack(side="left")
        self.builtin_seeds: list[str] = []
        bd = Card(mid, app, "Bridges", help="Bridges are unlisted entry points into Tor. You only need them if your network "
                                            "blocks Tor or you do not want your provider to see that you use Tor. obfs4 "
                                            "disguises Tor as random-looking traffic; Snowflake looks like a video call; "
                                            "meek looks like ordinary visits to a big website (slow). The built-in ones are "
                                            "shared by many people, so they get blocked more often than your own.")
        self.bridge_var = self.f_radios(bd, "bridge_mode", [(v, lab) for v, lab in L.BRIDGE_CHOICES])
        self.f_text(bd.body, "tor_bridges", 4, 50).pack(fill="x", pady=(6, 0))
        self.f_check(bd, "bridge_auto", "If Tor cannot connect directly, try the built-in bridges by itself",
                     "obfs4, then Snowflake; on by default")
        r = bd.row((6, 0))
        bd.lbl(r, "Country").pack(side="left")
        self.country = tk.StringVar()
        ce = ttk.Entry(r, textvariable=self.country, width=4)
        ce.pack(side="left", padx=6)
        tip(ce, "Two-letter country code, e.g. ir, cn, ru. Leave empty to let the Tor Project detect it.")
        self.b_get = app.btn(r, "Get bridges that work here", "web", "secondary", self.get_bridges)
        self.b_get.pack(side="left")
        bd.note("Request private bridges at bridges.torproject.org, Telegram @GetBridgesBot, or email "
                "bridges@torproject.org (from Gmail or Riseup). Paste them above and choose “My own bridges”.", pady=(6, 0))
        self.bridge_now = bd.note("", pady=(2, 0))
        grid_cards(mid, [sd, bd], 2)

        self._build_dns(f, 5)
        self._build_relay(f, 6)

        lg = Card(f, app, "Tor log", "log")
        lg.grid(row=7, column=0, sticky="ew", pady=(0, GAP))
        self.log = tk.Text(lg.body, height=8, wrap="none", state="disabled", relief="flat", borderwidth=0, highlightthickness=1,
                           font=app.fonts["mono"], padx=8, pady=6)
        self.log.pack(fill="x")
        app.text_widgets.append(self.log)
        self.log_last = 0
        self.tor: dict = {}
        self.retheme()

    # -- Tor DNS (optional) --------------------------------------------------
    def _build_dns(self, f, row: int) -> None:
        app = self.app
        dc = Card(f, app, "Tor DNS (optional)", "web",
                  help="Tor can answer DNS lookups on a local port. Names are looked up by Tor exit relays, so this is a "
                       "deliberate, narrow use of exits for DNS only. The Tor lane for noise stays onion-only. Only A, AAAA "
                       "and PTR lookups work.")
        dc.grid(row=row, column=0, sticky="ew", pady=(0, GAP))
        self.dns_chk = self.f_check(dc, "tor_dns", "Answer DNS lookups through Tor",
                                    "Off by default. Needs the Tor that legalPrivacy manages. Changing it restarts that Tor.")
        slot = ttk.Frame(dc.body, style="CardBody.TFrame")      # fixed place for the parts that show and hide
        slot.pack(fill="x")
        self.dns_body = ttk.Frame(slot, style="CardBody.TFrame")
        self.dns_status = dc.lbl(self.dns_body, "")
        self.dns_status.pack(anchor="w", pady=(6, 0))
        r = ttk.Frame(self.dns_body, style="CardBody.TFrame")
        r.pack(fill="x", pady=(6, 2))
        self.dns_test_btn = app.btn(r, "Test", "check", "secondary", self.dns_test,
                                    "Sends one real lookup for example.com through Tor and shows the answer and how long it took.")
        self.dns_test_btn.pack(side="left")
        self.dns_out = ttk.Label(r, text="", style="CardMuted.TLabel", justify="left")
        self.dns_out.pack(side="left", padx=10)
        self.dns_lan_chk = self.f_check(dc, "tor_dns_lan", "Also share it with other devices on my network",
                                        "Off. Only on one private address that you pick below, never on the internet.")
        slot2 = ttk.Frame(dc.body, style="CardBody.TFrame")
        slot2.pack(fill="x")
        self.dns_lan_row = ttk.Frame(slot2, style="CardBody.TFrame")
        dc.lbl(self.dns_lan_row, "Address").pack(side="left")
        self.dns_addr = tk.StringVar()
        self.dns_addr_cb = ttk.Combobox(self.dns_lan_row, textvariable=self.dns_addr, state="readonly", width=26)
        self.dns_addr_cb.pack(side="left", padx=6)
        self.dns_addr_cb.bind("<<ComboboxSelected>>", lambda _e: app.edited())
        self._reg("tor_dns_addr", self.dns_addr.get, lambda x: self.dns_addr.set(str(x or "")))
        app.btn(self.dns_lan_row, "Refresh list", "refresh", "secondary", self.dns_refresh,
                "Look at this computer's addresses again.").pack(side="left")
        self.dns_warn = Banner(slot2, "Warning: anyone on that network can use your Tor exits for DNS, and you are "
                                        "responsible for what they do. Never expose this to the internet; it is not an open "
                                        "resolver for the internet. Only share it on a network you trust, such as your own home.",
                               "bad", host=slot2)
        dc.note("How to use it: your operating system sends DNS lookups to port 53, so it cannot use this port directly. "
                "For the whole computer you need a small local forwarder (for example dnsmasq or unbound) set up to forward "
                "to 127.0.0.1 and the port shown above, or an app that lets you set a DNS port yourself. The commands differ "
                "by system and have not been verified here, so none are given; follow your forwarder's own documentation. "
                "Tor DNS is slower than normal DNS and handles only A, AAAA and PTR lookups.", pady=(8, 0))
        self.dns_addrs: list[str] | None = None
        self.dns_chk.trace_add("write", lambda *_a: self._dns_layout())
        self.dns_lan_chk.trace_add("write", lambda *_a: self._dns_layout())

    def values(self) -> dict:
        v = super().values()
        if not v.get("tor_dns") or (v.get("tor_dns_lan") and not v.get("tor_dns_addr")):
            v["tor_dns_lan"] = False                  # sharing needs Tor DNS on, and a chosen private address
        return v

    def _dns_layout(self) -> None:
        on = bool(self.dns_chk.get())
        lan = on and bool(self.dns_lan_chk.get())
        for w, show in ((self.dns_body, on), (self.dns_lan_row, lan), (self.dns_warn, lan)):
            if show and not w.winfo_manager():
                w.pack(fill="x", pady=(4, 0))
            elif not show and w.winfo_manager():
                w.pack_forget()
        if lan and self.dns_addrs is None:
            self.dns_refresh()

    def dns_refresh(self) -> None:
        def done(r):
            self.dns_addrs = r.get("addresses") or []
            cur = self.dns_addr.get()
            vals = list(self.dns_addrs) + ([cur] if cur and cur not in self.dns_addrs else [])
            self.dns_addr_cb.configure(values=vals)
            if not self.dns_addr.get() and vals:
                self.dns_addr.set(vals[0])
                self.app.edited()
            if not vals:
                self.dns_out.configure(text="No private network address found on this computer.")
        self.app.work(self.app.ctl.tor_dns_addresses, done, lambda e: self.app.error("Tor DNS", e))

    def dns_test(self) -> None:
        self.dns_test_btn.state(["disabled"])
        self.dns_out.configure(text="Testing… the first lookup can take several seconds.")

        def done(r):
            self.dns_test_btn.state(["!disabled"])
            self.dns_out.configure(text=(f"✓ {r['name']} answered {', '.join(r['answers'])} in {r['ms']} ms" if r.get("ok")
                                         else f"✗ {r.get('error') or 'no answer'}"))

        def fail(e):
            self.dns_test_btn.state(["!disabled"])
            self.app.error("Tor DNS test", e)
        self.app.work(self.app.ctl.tor_dns_test, done, fail)

    def _update_dns(self, t: dict) -> None:
        d = t.get("dns") or {}
        if not d.get("on"):
            return
        where = f"{d.get('address')}:{d.get('port')} (UDP)" if d.get("port") else "chosen when Tor starts (this computer only)"
        who = f"other devices on your network ({d.get('address')})" if d.get("lan") else "this computer only"
        state = ("Needs the Tor that legalPrivacy manages" if not d.get("managed")
                 else "Listening" if d.get("ready") else "Waiting for Tor to be ready")
        self.dns_status.configure(text=f"Status: {state}    Address: {where}    Reachable from: {who}")

    # -- Relay (separate Tor process; practice mode by default) -----------
    CHECKS = (("address", "This computer has a public IP address, or my router forwards the ORPort to it."),
              ("always_on", "This computer stays on and connected most of the time."),
              ("bandwidth", "I am happy with the speed limit above and the traffic it can use each month."),
              ("not_exit", "I understand this is not an exit: it never reaches websites for anyone, and it cannot answer DNS."),
              ("public_ip", "I understand a relay's IP address is public by design."))

    def _build_relay(self, f, row: int) -> None:
        app = self.app
        rc = Card(f, app, "Contribute to Tor: run a relay (optional)", "tor")
        rc.grid(row=row, column=0, sticky="ew", pady=(0, GAP))
        self.relay_card = rc
        Banner(rc.body, "A relay passes other people's encrypted Tor traffic along, which helps the network. It is not an "
                        "exit: it never connects to websites for anyone, and legalPrivacy can never make it one. A relay or "
                        "bridge also does not provide DNS (only exit relays look up names). Relay addresses are public by "
                        "design: the Tor network publishes them in a list anyone can read. The relay runs as its own "
                        "separate Tor program; it starts with the app in practice mode (nothing published) unless you untick that.", "tor", host=rc.body).pack(fill="x", pady=(0, 6))
        self.r_inputs: list = []
        self.r_mode = tk.StringVar(value="middle")
        for val, txt, hint in (("middle", "Middle relay", "Listed publicly; carries traffic between other relays."),
                               ("bridge", "Bridge", "Not listed publicly; helps people whose network blocks Tor.")):
            self.r_inputs.append(rc.radio(self.r_mode, val, txt, hint, command=self._relay_changed))
        r = rc.row((8, 2))
        self.r_nick, self.r_bw, self.r_port, self.r_contact = (tk.StringVar() for _ in range(4))
        rc.lbl(r, "Nickname").pack(side="left")
        e1 = ttk.Entry(r, textvariable=self.r_nick, width=16)
        e1.pack(side="left", padx=(6, 14))
        tip(e1, "1 to 19 letters or digits.")
        rc.lbl(r, "Speed limit").pack(side="left")
        e2 = ttk.Spinbox(r, from_=0.1, to=1000, increment=0.5, width=7, textvariable=self.r_bw, command=self._relay_changed)
        e2.pack(side="left", padx=6)
        tip(e2, "The most the relay may send and receive each second, in megabytes.")
        rc.lbl(r, "MBytes per second", True).pack(side="left", padx=(0, 14))
        rc.lbl(r, "Port (ORPort)").pack(side="left")
        e3 = ttk.Spinbox(r, from_=1024, to=65535, width=7, textvariable=self.r_port, command=self._relay_changed)
        e3.pack(side="left", padx=6)
        self.r_est = rc.note("", pady=(2, 2))
        r = rc.row()
        rc.lbl(r, "Contact (optional)").pack(side="left")
        e4 = ttk.Entry(r, textvariable=self.r_contact, width=36)
        e4.pack(side="left", padx=6)
        tip(e4, "Shown publicly in the relay list if you add it, for example an email address.")
        self.r_inputs += [e1, e2, e3, e4]
        for v in (self.r_nick, self.r_bw, self.r_port, self.r_contact, self.r_mode):
            v.trace_add("write", lambda *_a: self._relay_changed())
        self.r_practice = tk.BooleanVar(value=True)
        self.r_inputs.append(rc.check(self.r_practice, "Practice mode (not published)",
                                      "The relay only listens on this computer and never announces itself, so nobody can use "
                                      "it. It still downloads Tor's public relay list like any Tor program. Needs no checklist. "
                                      "Untick it only when you are ready to join the network.", command=self._relay_changed))
        rc.heading("Before a public relay", "tick each one")
        self.r_checks: dict[str, tk.BooleanVar] = {}
        for key, txt in self.CHECKS:
            var = tk.BooleanVar(value=False)
            self.r_checks[key] = var
            self.r_inputs.append(rc.check(var, txt, command=self._relay_changed))
        rc.note("The settings file for the relay (read-only):", pady=(8, 2))
        self.r_torrc = tk.Text(rc.body, height=9, wrap="none", relief="flat", borderwidth=0, highlightthickness=1,
                               font=app.fonts["mono"], padx=8, pady=6, state="disabled")
        self.r_torrc.pack(fill="x")
        app.text_widgets.append(self.r_torrc)
        r = rc.row((8, 2))
        self.r_start = app.btn(r, "Start relay", "play", "tor", self.relay_start)
        self.r_stop = app.btn(r, "Stop relay", "stop", "secondary", self.relay_stop)
        self.r_start.pack(side="left", padx=(0, 6))
        self.r_stop.pack(side="left", padx=(0, 10))
        from .gui_theme import pill
        self.r_pill = pill(r, "Stopped", "off")
        self.r_pill.pack(side="left")
        self.r_msg = rc.note("", muted=False, pady=(4, 2))
        self.r_auto = tk.BooleanVar(value=True)
        self._r_loading = True
        rc.check(self.r_auto, "Start the relay when this app opens",
                 "On by default. Until you complete the checklist this is practice mode: nothing is published.", command=self.relay_autostart)
        self.r_note = rc.note("", pady=(2, 2))
        self.r_log = tk.Text(rc.body, height=7, wrap="none", state="disabled", relief="flat", borderwidth=0,
                             highlightthickness=1, font=app.fonts["mono"], padx=8, pady=6)
        self.r_log.pack(fill="x", pady=(4, 0))
        app.text_widgets.append(self.r_log)
        self.r_log.configure(state="normal")
        self.r_log.insert("end", "Nothing yet. The relay's own log appears here once it starts.\n")
        self.r_log.configure(state="disabled")
        rc.note("Router and firewall notes. All systems: a public relay must be reachable from the internet on its ORPort "
                "(TCP). Forward that port on your router to this computer, then allow it in the computer's firewall; router "
                "menus differ, so look for \"port forwarding\". Windows: allow the port in Windows Defender Firewall "
                "(Inbound Rules). macOS: if the firewall is on, allow incoming connections for the Tor program. Linux: allow "
                "the TCP port in your firewall (ufw, firewalld or nftables). The status shows \"reachable\" only after Tor "
                "itself tests the port from outside, which can take a while for a new relay.", pady=(8, 2))
        link = ttk.Label(rc.body, text="The Tor Project's relay documentation: community.torproject.org/relay",
                         style="CardMuted.TLabel", cursor="hand2")
        link.pack(anchor="w")
        link.bind("<Button-1>", lambda _e: __import__("webbrowser").open("https://community.torproject.org/relay/"))
        self._r_filled = False
        self._r_up = False
        self._r_prev = None

    def _relay_body(self) -> dict:
        try:
            bw = float(self.r_bw.get())
        except ValueError:
            bw = 0.0
        try:
            port = int(self.r_port.get())
        except ValueError:
            port = 0
        return {"mode": self.r_mode.get(), "nickname": self.r_nick.get(), "bandwidth_mb": bw, "or_port": port,
                "contact": self.r_contact.get(), "practice": bool(self.r_practice.get()),
                "checklist": {k: v.get() for k, v in self.r_checks.items()}}

    def _relay_changed(self) -> None:
        if not getattr(self, "_r_filled", False):
            return
        b = self._relay_body()
        self.r_est.configure(text=L.relay_estimate_text(b["bandwidth_mb"]))
        prev = self.app.ctl.relay_preview(b)
        self._set_torrc(prev["torrc"])
        self._relay_gate(prev["error"])

    def _set_torrc(self, text: str) -> None:
        self.r_torrc.configure(state="normal")
        self.r_torrc.delete("1.0", "end")
        self.r_torrc.insert("1.0", text)
        self.r_torrc.configure(state="disabled")

    def _relay_gate(self, error: str | None = None) -> None:
        b = self._relay_body()
        why = error or ""
        if not why and not getattr(self, "_r_tor_found", True):
            why = ("Tor is not installed yet. Press Start Tor above once (it installs the official bundle), "
                   "then come back.")
        elif not why and not b["practice"] and not all(b["checklist"].values()):
            why = "Tick every item on the checklist to start a public relay, or keep practice mode on."
        up = self._r_up
        self.r_start.state(["!disabled"] if not up and not why else ["disabled"])
        self.r_stop.state(["!disabled"] if up else ["disabled"])
        for w in self.r_inputs:
            try:
                w.state(["disabled"] if up else ["!disabled"])
            except (AttributeError, tk.TclError):
                pass
        if not up:
            self.r_msg.configure(text=why)

    def relay_start(self) -> None:
        body = self._relay_body()
        self.r_start.state(["disabled"])
        self.app.work(lambda: self.app.ctl.relay_start(body), done=lambda _r: self.app.poll_now(),
                      error=lambda e: (self.app.error("Relay", e), self._relay_gate()))

    def relay_stop(self) -> None:
        self.app.work(self.app.ctl.relay_stop, done=lambda _r: self.app.poll_now(),
                      error=lambda e: self.app.error("Relay", e))

    def relay_autostart(self) -> None:
        on = bool(self.r_auto.get())
        self.app.work(lambda: self.app.ctl.apply_config({"contribute": {"relay": {"autostart": on}}}),
                      error=lambda e: (self.r_auto.set(False), self.app.error("Relay", e)))
        self.app.flash("The relay will start when the app opens (a public relay only after you have started it once with "
                       "the checklist)." if on else "The relay will not start by itself.", 6000)

    def _update_relay(self) -> None:
        st = self.app.ctl.relay_state()
        s, status = st["settings"], st["status"]
        self._r_tor_found = st["tor_found"]
        up = status["state"] in ("starting", "running")
        if not self._r_filled or (up and not self._r_up):
            self._r_filled = False                   # load saved settings without triggering the change handler
            self.r_mode.set(s["mode"])
            self.r_nick.set(s["nickname"])
            self.r_bw.set(f"{s['bandwidth_mb']:g}")
            self.r_port.set(str(s["or_port"]))
            self.r_contact.set(s["contact"])
            self.r_practice.set(bool(s["practice"]))
            self.r_auto.set(bool(s["autostart"]))
            self._r_filled = True
            self.r_est.configure(text=L.relay_estimate_text(s["bandwidth_mb"]))
            self._set_torrc(st["torrc"])
        self._r_up = up
        tone = {"running": "ok", "starting": "warn", "error": "bad"}.get(status["state"], "off")
        from .gui_theme import set_pill
        label = {"stopped": "Stopped", "starting": "Starting…", "error": "Error",
                 "running": ("Running (practice, not published)" if status.get("practice")
                             else "Running, reachable" if status.get("reachable") else "Running")}[status["state"]]
        set_pill(self.r_pill, label, tone)
        self.r_note.configure(text=status.get("error") or status.get("hint") or (
            f"Relay fingerprint: {status['fingerprint']}" if status["state"] == "running" and status.get("fingerprint") else ""))
        if up:
            self._set_torrc(st["torrc"])
            self.r_msg.configure(text="")
        sig = (tuple(status["log"][-80:]),)
        if sig != self._r_prev:
            self._r_prev = sig
            self.r_log.configure(state="normal")
            self.r_log.delete("1.0", "end")
            self.r_log.insert("end", "\n".join(status["log"]) + "\n" if status["log"] else
                              "Nothing yet. The relay's own log appears here once it starts.\n")
            self.r_log.configure(state="disabled")
            self.r_log.see("end")
        self._relay_gate()

    def retheme(self) -> None:
        self.sf.retheme()
        p = self.app.pal
        self.log.configure(bg=p["log_bg"], fg=p["fg"], highlightbackground=p["border"], highlightcolor=p["border"])
        for w in (self.r_torrc, self.r_log):
            w.configure(bg=p["log_bg"], fg=p["fg"], highlightbackground=p["border"], highlightcolor=p["border"])

    # -- actions
    def act(self, action: str) -> None:
        self.app.work(lambda: self.app.ctl.tor_action(action), done=lambda _r: self.app.poll_now(),
                      error=lambda e: self.app.error("Tor", e))

    def selftest(self) -> None:
        self.test_note.configure(text="Testing Tor… this takes up to a minute.")
        self.app.work(self.app.ctl.tor_selftest, done=lambda _r: self.app.poll_now(), error=lambda e: self.app.error("Tor test", e))

    def reset_seeds(self) -> None:
        self.load({"tor_seeds": "\n".join(self.builtin_seeds)})
        self.app.edited()

    def get_bridges(self) -> None:
        if not messagebox.askokcancel("Get bridges", "Ask bridges.torproject.org for bridges that work in your country? "
                                      "This contacts that site from your connection.", parent=self.app.root):
            return
        self.b_get.state(["disabled"])
        country = self.country.get().strip()

        def done(r):
            self.b_get.state(["!disabled"])
            if r.get("ok"):
                self.app.flash(f"Saved {r['count']} bridge(s): {', '.join(r['types'])}. Restart Tor to use them.", 9000)
                self.app.resync_now()
            else:
                messagebox.showinfo("Get bridges", r.get("message", "No bridges were found."), parent=self.app.root)

        def fail(e):
            self.b_get.state(["!disabled"])
            self.app.error("Could not reach the bridge service", e)
        self.app.work(lambda: self.app.ctl.get_bridges(country), done, fail)

    # -- state
    def update_state(self, st: dict) -> None:
        self.builtin_seeds = [b["url"] for b in st.get("builtin_onion_seeds") or []]
        t = st.get("tor") or {}
        state = t.get("state") or "stopped"
        pct = int(t.get("bootstrap_pct") or 0)
        words = {"stopped": "Stopped", "installing": "Installing…", "starting": "Starting…",
                 "bootstrapping": "Connecting…", "ready": "Connected", "error": "Problem"}
        self.state_var.set(words.get(state, state))
        self.bar["value"] = (t.get("install_progress") or 0) * 100 if state == "installing" else (100 if state == "ready" else pct)
        self.sum_var.set((t.get("error") or ("Downloading and verifying the official Tor bundle…" if state == "installing"
                                              else t.get("bootstrap_summary") or "")) + (f"  ⚠ {t['hint']}" if t.get("hint") else ""))
        kvs = [("Mode", t.get("mode")), ("Version", t.get("version") or "—"), ("SOCKS", t.get("socks") or "—"),
               ("Control", t.get("control") or "—"), ("PID", t.get("pid") or "—"),
               ("Uptime", L.fmt_uptime(t.get("uptime"))), ("Downloaded", L.fmt_bytes(t.get("read"))),
               ("Uploaded", L.fmt_bytes(t.get("written"))), ("Program", t.get("binary") or "not installed")]
        sig = repr(kvs)
        if getattr(self, "_kv_sig", None) != sig:
            self._kv_sig = sig
            for w in self.kv.winfo_children():
                w.destroy()
            for i, (k, v) in enumerate(kvs):
                ttk.Label(self.kv, text=k, style="CardMuted.TLabel").grid(row=i, column=0, sticky="w", padx=(0, 14))
                ttk.Label(self.kv, text=str(v), style="Card.TLabel", wraplength=300, justify="left").grid(row=i, column=1, sticky="w")
        busy = state in ("starting", "bootstrapping", "installing")
        for b, on in ((self.b_start, not busy and state != "ready"), (self.b_stop, state != "stopped"),
                      (self.b_restart, state != "stopped" and not busy), (self.b_new, state == "ready" and bool(t.get("control"))),
                      (self.b_install, not busy)):
            b.state(["!disabled"] if on else ["disabled"])
        self.install_note.configure(text=(
            "Automatic install is not available on this platform; install Tor with your package manager."
            if not t.get("supported_platform") else "Official Tor bundle installed by legalPrivacy." if t.get("installed_bundle")
            else "Using Tor found on this computer." if t.get("binary")
            else "Tor is not installed yet; it will be downloaded automatically when needed."))
        self.test_note.configure(text=L.tor_test_text(t.get("selftest")))
        self._update_dns(t)
        self._update_relay()
        circs = t.get("circuits") or []
        self.circ_head.configure(text=f"{t.get('circuits_built') or 0} built. Purposes starting with HS_CLIENT are onion-service connections.")
        self.circ.delete(*self.circ.get_children())
        for c in circs:
            self.circ.insert("", "end", values=(c.get("id"), c.get("status"), c.get("purpose"), " → ".join(c.get("path") or [])))
        self.circ.configure(height=max(2, min(8, len(circs))))
        b = t.get("builtin") or {}
        cfg = (st.get("profile") or {}).get("transports", {}).get("tor", {}).get("bridge_mode", "off")
        self.bridge_now.configure(text=(
            f"Right now Tor is using the built-in {t['bridge_mode']} bridges because a direct connection did not work."
            if t.get("bridge_mode") and t["bridge_mode"] != cfg and state != "stopped"
            else f"Tor is using {t['bridges']} bridge(s)." if t.get("bridges") else
            f"Built in: obfs4 {b.get('obfs4', 0)}, Snowflake {b.get('snowflake', 0)}, meek {b.get('meek', 0)}."
            if b else "Install Tor first to see the built-in bridges."))
        evs = self.app.ctl.log.since(self.log_last, "debug", {"tor"}, 200)
        if evs:
            self.log_last = evs[-1]["id"]
            self.log.configure(state="normal")
            for e in evs:
                self.log.insert("end", L.fmt_log_line(e) + "\n")
            n = int(self.log.index("end-1c").split(".")[0])
            if n > 400:
                self.log.delete("1.0", f"{n - 400}.0")
            self.log.configure(state="disabled")
            self.log.see("end")


# ── Proof ───────────────────────────────────────────────────────────────────
class ProofTab(Tab):
    title, icon = "Proof", "proof"
    REFRESH_S = 15

    def __init__(self, nb, app):
        super().__init__(nb, app)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.sf = ScrollFrame(self, app)
        self.sf.grid(sticky="nsew")
        f = self.sf.inner
        f.columnconfigure(0, weight=1)
        self.wrap_labels: list = []

        cc = Card(f, app, "Is it working?", "proof",
                  help="Each line says what you want to see, what we actually saw, and whether that is working. Nothing here "
                       "changes your settings. “Run checks” contacts check.torproject.org once directly and once through "
                       "Tor (only if Tor is on) to compare the two addresses.")
        cc.grid(row=0, column=0, sticky="ew", pady=(0, GAP))
        self.run_btn = app.btn(cc.actions, "Run checks", "play", "primary", self.run_checks)
        self.run_btn.pack()
        self.headline = tk.StringVar(value="Checking…")
        ttk.Label(cc.body, textvariable=self.headline, style="CardH2.TLabel").pack(anchor="w", pady=(0, 6))
        self.checks = ttk.Frame(cc.body, style="CardBody.TFrame")
        self.checks.pack(fill="x")
        self.checks.columnconfigure(0, weight=1)

        self.charts: dict = {}
        self.verdicts: dict = {}
        for i, (key, title, cls, help_) in enumerate((
                ("intended", "1. Intended pattern (for reference)", IntendedChart,
                 "What your current settings are meant to produce: expected requests per hour of the day, from the same "
                 "planner the noise uses. The shaded band is the usual spread, the line the middle."),
                ("session", "2. This session: actual vs intended", SessionChart,
                 "Requests the noise really made in each 10 minutes over the last 6 hours, over the planned range for that "
                 "hour. Hours well above or below the plan are shaded red."),
                ("baseline", "3. Your baseline vs the noise, by hour of day", BaselineChart,
                 "Each bar is the share of that day's activity in each hour, so the shapes can be compared even though you "
                 "and the noise do different amounts."))):
            card = Card(f, app, title, "act", help=help_)
            card.grid(row=1 + i, column=0, sticky="ew", pady=(0, GAP))
            ch = cls(card.body, app.pal)
            ch.pack(fill="x")
            v = tk.StringVar()
            lb = ttk.Label(card.body, textvariable=v, style="Card.TLabel", justify="left")
            lb.pack(fill="x", anchor="w", pady=(6, 0))
            autowrap(lb, card.body, 6)
            self.charts[key], self.verdicts[key] = ch, v

        bc = Card(f, app, "Where “how you browse” comes from", "proof",
                  help="The comparisons need a picture of your own browsing. legalPrivacy uses the first of these that has "
                       "enough data: a browser recording you import, minutes it saw with the noise off, then your browser "
                       "history. With no data nothing is scored.")
        bc.grid(row=4, column=0, sticky="ew", pady=(0, GAP))
        self.base_var, self.har_var = tk.StringVar(), tk.StringVar()
        bl = ttk.Label(bc.body, textvariable=self.base_var, style="Card.TLabel", justify="left")
        bl.pack(fill="x", anchor="w")
        autowrap(bl, bc.body, 6)
        hl = ttk.Label(bc.body, textvariable=self.har_var, style="CardMuted.TLabel", justify="left")
        hl.pack(fill="x", anchor="w", pady=(8, 0))
        autowrap(hl, bc.body, 6)
        r = bc.row((8, 0))
        app.btn(r, "Import browser recording (.har)…", None, "secondary", self.import_har).pack(side="left")
        self.forget_btn = app.btn(r, "Forget it", None, "ghost", self.forget_har)
        self.forget_btn.pack(side="left", padx=6)

        tl = Card(f, app, "Last 6 hours, per minute", "act",
                  help="Bars count the different addresses connected in each minute, split by who opened them. Shaded "
                       "stripes are minutes when the noise was on.")
        tl.grid(row=5, column=0, sticky="ew", pady=(0, GAP))
        self.timeline = TimelineChart(tl.body, app.pal)
        self.timeline.pack(fill="x")
        self.obs_note = tl.note("", pady=(6, 0))
        self.onoff = ttk.Frame(tl.body, style="CardBody.TFrame")
        self.onoff.pack(fill="x", pady=(6, 0))

        cm = Card(f, app, "Does the noise look like you?", help="Compares the rhythm of the noise with your own traffic from "
                                                                 "the minutes when the noise was off. 100% means an observer "
                                                                 "could not tell them apart on that measure.")
        cm.grid(row=6, column=0, sticky="ew", pady=(0, GAP))
        self.cmp = ttk.Frame(cm.body, style="CardBody.TFrame")
        self.cmp.pack(fill="x")

        mp = Card(f, app, "Live network map", "web",
                  help="Like EtherApe: each bubble is a machine this computer is talking to right now.")
        mp.grid(row=7, column=0, sticky="ew", pady=(0, GAP))
        mp.note("The animated map needs a web view, so it lives in the web dashboard (the backup front end).")
        app.web_button(mp.body, "Open the network map in the web dashboard")

        tr = Card(f, app, "Browser address trace", "list",
                  help="Every address the noise browser's tabs showed recently, newest first, and what made it change. "
                       "If you ever see a tab flicker through addresses, this list shows what it was.")
        tr.grid(row=8, column=0, sticky="ew", pady=(0, GAP))
        self.trace_note = tr.note("")
        self.trace = ttk.Treeview(tr.body, columns=("time", "what", "site"), show="headings", height=5, selectmode="none")
        for c, t, w in (("time", "Time", 80), ("what", "What made it change", 200), ("site", "Site", 380)):
            self.trace.heading(c, text=t)
            self.trace.column(c, width=w, stretch=c == "site")
        self.trace.pack(fill="x")

        self._last = {"leak": None, "act": None, "obs": None, "trace": None}
        self._fetching = {"leak": False, "act": False, "obs": False, "trace": False}
        self._last_fetch = 0.0
        self._checks_sig = ""
        self.retheme()

    def retheme(self) -> None:
        self.sf.retheme()
        for ch in list(self.charts.values()) + [self.timeline]:
            ch.set_palette(self.app.pal)
        self._checks_sig = ""
        self._render_checks()

    # -- data
    def on_show(self) -> None:
        self.fetch(force=True)

    def update_state(self, st: dict) -> None:
        if self.app.current_tab() is not self:
            return
        leak_running = bool((self._last["leak"] or {}).get("running"))
        if leak_running or time.time() - self._last_fetch > self.REFRESH_S:
            self.fetch(force=False, leak_only=leak_running)

    def fetch(self, force: bool, leak_only: bool = False) -> None:
        self._last_fetch = time.time()
        ctl = self.app.ctl
        jobs = [("leak", lambda: ctl.leak_runner().state(), self._got_leak)]
        if not leak_only:
            jobs += [("act", ctl.activity_state, self._got_act), ("obs", ctl.observe_state, self._got_obs),
                     ("trace", ctl.browser_trace, self._got_trace)]
        for key, fn, cb in jobs:
            if not self._fetching[key]:
                self._fetching[key] = True
                self.app.work(fn, done=lambda d, key=key, cb=cb: (self._fetching.__setitem__(key, False), cb(d)),
                              error=lambda e, key=key: self._fetching.__setitem__(key, False))

    def _got_leak(self, data: dict) -> None:
        self._last["leak"] = data
        self._render_checks()

    def _got_act(self, data: dict) -> None:
        self._last["act"] = data
        self.charts["intended"].update_data(data["intended"])
        self.charts["session"].update_data(data["session"])
        self.charts["baseline"].update_data(data["baseline"])
        for k in ("intended", "session", "baseline"):
            self.verdicts[k].set(data[k].get("verdict", ""))
        self.base_var.set(L.baseline_sources_text(data["baseline"]))
        har = data.get("har") or {}
        if har.get("present"):
            self.har_var.set(f"Imported recording: {har['entries']:,} requests over {har['span_hours']:g} h, "
                             f"{har['sites']} top sites. Only times and site names were kept.")
            self.forget_btn.state(["!disabled"])
        else:
            self.har_var.set("No browser recording imported. In your browser's developer tools, open the Network tab, "
                             "browse as usual, then Save all as HAR and import it here.")
            self.forget_btn.state(["disabled"])

    def _got_obs(self, o: dict) -> None:
        self.timeline.update_data(o.get("timeline") or [])
        notes = [f"Noise is {'ON' if o.get('running') else 'OFF'} right now."]
        if not o.get("enabled"):
            notes.append("Watching is off. Turn on “Watch this computer's connection counts” in Settings.")
        elif not o.get("available"):
            notes.append("Connection counts are not available on this system.")
        if o.get("limited"):
            notes.append("This system only lets legalPrivacy see its own connections, so “your apps” stays empty.")
        self.obs_note.configure(text=" ".join(notes))
        for w in self.onoff.winfo_children():
            w.destroy()
        for r, row in enumerate(L.onoff_rows(o.get("onoff") or {})):
            for c, txt in enumerate(row):
                ttk.Label(self.onoff, text=txt, style="Card.TLabel" if r else "CardMuted.TLabel",
                          anchor="w" if c == 0 else "e").grid(row=r, column=c, sticky="ew", padx=(0, 18), pady=1)
        self.onoff.columnconfigure(0, weight=1)
        for w in self.cmp.winfo_children():
            w.destroy()
        for line, tone, frac in L.compare_lines(o.get("compare") or {}):
            row = ttk.Frame(self.cmp, style="CardBody.TFrame")
            row.pack(fill="x", pady=2)
            if frac is None:
                ttk.Label(row, text=line, style="Tone%s.TLabel" % tone, wraplength=700, justify="left").pack(anchor="w")
            else:
                name, pct = line
                ttk.Label(row, text=name, style="Card.TLabel", width=16).pack(side="left")
                pb = ttk.Progressbar(row, maximum=100, value=frac * 100)
                pb.pack(side="left", fill="x", expand=True, padx=8)
                ttk.Label(row, text=pct, style="Card.TLabel", width=8, anchor="e").pack(side="left")

    def _got_trace(self, d: dict) -> None:
        items = d.get("items") or []
        self.trace_note.configure(text=(
            "The noise browser is not running. Start the noise with a real browser to see its tabs here." if not d.get("running")
            else f"{len(items)} recent address changes; {d.get('blocked', 0)} jump(s) to other sites were blocked."))
        self.trace.delete(*self.trace.get_children())
        for it in items[:60]:
            self.trace.insert("", "end", values=L.trace_row(it))

    def _render_checks(self) -> None:
        data = self._last["leak"]
        if not data:
            return
        sig = json.dumps(data, sort_keys=True, default=str) + self.app.theme_name
        if sig == self._checks_sig:
            return
        self._checks_sig = sig
        p = self.app.pal
        for w in self.checks.winfo_children():
            w.destroy()
        summ = data.get("summary") or {}
        self.headline.set(("Checking…  " if data.get("running") else "") + (summ.get("headline") or "Is it working?")
                          + ("  (not tested over the network yet)" if data.get("preview") else ""))
        self.run_btn.state(["disabled"] if data.get("running") else ["!disabled"])
        if data.get("error"):
            ttk.Label(self.checks, text="The checks could not run: " + data["error"], style="Tonebad.TLabel").grid(row=0, column=0, sticky="w")
        for i, c in enumerate(data.get("checks") or []):
            title, want, saw, hint = L.check_lines(c)
            tone = {"ok": "ok", "bad": "bad", "info": "info"}.get(c.get("status"), "off")
            box = ttk.Frame(self.checks, style="Tone.TFrame", padding=(12, 8))
            box.grid(row=i, column=0, sticky="ew", pady=3)
            box.columnconfigure(0, weight=1)
            lab = ttk.Label(box, text=title, style=f"Pill{tone}.TLabel")
            lab.grid(row=0, column=0, sticky="w")
            wl = []
            for r, (txt, fg) in enumerate(((want, p["fg"]), (saw, p["fg"]), (hint, p["muted"])), 1):
                if txt:
                    lb = tk.Label(box, text=txt, fg=fg, bg=p["code"], justify="left", anchor="w", font=self.app.fonts["base"])
                    lb.grid(row=r, column=0, sticky="ew", pady=(3 if r == 1 else 0, 0))
                    wl.append(lb)
            autowrap(box, box, 24)
            box.bind("<Configure>", lambda e, wl=wl: [x.configure(wraplength=max(200, e.width - 30)) for x in wl])

    # -- actions
    def run_checks(self) -> None:
        self.run_btn.state(["disabled"])
        self.app.work(lambda: self.app.ctl.leak_runner().run(), done=lambda _r: self.fetch(True, leak_only=True),
                      error=lambda e: self.app.error("Checks", e))

    def import_har(self) -> None:
        path = filedialog.askopenfilename(parent=self.app.root, title="Choose a browser recording",
                                          filetypes=[("HAR files", "*.har *.json"), ("All files", "*.*")])
        if not path:
            return
        self.har_var.set("Reading the recording…")

        def go():
            import os
            if os.path.getsize(path) > 52 * 1024 * 1024:
                raise RuntimeError("That file is larger than 50 MB. Record a shorter session and try again.")
            with open(path, "rb") as fh:
                raw = fh.read()
            try:
                text = raw.decode("utf-8-sig")
            finally:
                raw = None
            return self.app.ctl.har_import({"text": text})

        def done(_r):
            self.fetch(True)
            self.app.flash("Recording imported. Only times and site names were kept.")

        def err(e):
            self.fetch(True)
            self.app.error("Import", e)
        self.app.work(go, done=done, error=err)

    def forget_har(self) -> None:
        if not messagebox.askokcancel("Forget recording", "Delete the imported recording's data?", parent=self.app.root):
            return
        self.app.work(lambda: self.app.ctl.har_forget("all"), done=lambda _r: self.fetch(True),
                      error=lambda e: self.app.error("Forget", e))
