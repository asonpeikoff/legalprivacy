"""My List, ML, Tools, Health and Help tabs of the native app."""
from __future__ import annotations

import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, ttk

from . import gui_fields as F
from . import gui_logic as L
from .gui_base import Tab
from .gui_charts import BaselineChart, Chart
from .gui_theme import Card, ScrollFrame, Sparkline, autowrap, pill, tip

GAP = 12
BLOG = "https://legalizingprivacy.substack.com"
FNAME = {"hour": "Hour of day", "weekday": "Weekday", "gap": "Rhythm (time between requests)",
         "popularity": "How popular the sites are", "revisit": "Revisiting the same sites", "ending": "Domain endings"}


def page(tab: Tab, app) -> ttk.Frame:
    tab.rowconfigure(0, weight=1)
    tab.columnconfigure(0, weight=1)
    tab.sf = ScrollFrame(tab, app)
    tab.sf.grid(sticky="nsew")
    tab.sf.inner.columnconfigure(0, weight=1)
    tab._r = 0
    return tab.sf.inner


def add_card(tab: Tab, app, title: str, icon: str | None = None, help: str = "") -> Card:
    c = Card(tab.sf.inner, app, title, icon, help)
    cols = getattr(tab, "_cols", 1)
    c.grid(row=tab._r // cols, column=tab._r % cols, sticky="new", pady=(0, GAP), padx=(0, GAP if cols > 1 and tab._r % cols == 0 else 0))
    tab._r += 1
    return c


def clean_site(x: str) -> str:
    x = x.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].split("?")[0]
    return x.removeprefix("www.")


# ── My List ─────────────────────────────────────────────────────────────────
class MyListTab(Tab):
    title, icon = "My List", "list"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        page(self, app)
        self.sites: list[str] = []
        self.weights: dict = {}
        self.found: list = []
        self.found_kind = "history"
        self._last_poll = 0.0
        self._ml: dict = {}
        c = add_card(self, app, "My List", "list")
        c.note("Your own sites. When this is on, page visits and DNS lookups come from your list, with a share of other sites "
               "mixed in, so the noise looks like your real interests.")
        self.f_check(c, "mylist_enabled", "Visit sites from My List")
        r = c.row()
        c.lbl(r, "Mix in other sites").pack(side="left")
        self.f_spin(r, "mylist_share", 0, 100, 5, 5).pack(side="left", padx=6)
        c.lbl(r, "%  (30% recommended: enough variety that the noise is not just your list)", True).pack(side="left")
        r = c.row((8, 4))
        self.add_var = tk.StringVar()
        e = ttk.Entry(r, textvariable=self.add_var)
        e.pack(side="left", fill="x", expand=True)
        tip(e, "Add sites: example.com, or paste many addresses at once")
        e.bind("<Return>", lambda _e: self.add_sites())
        app.btn(r, "Add", "plus", "primary", self.add_sites).pack(side="left", padx=(8, 0))
        self.tree = ttk.Treeview(c.body, columns=("n", "site", "often"), show="headings", height=6, selectmode="browse")
        for col, t, w in (("n", "#", 40), ("site", "Site", 300), ("often", "How often", 140)):
            self.tree.heading(col, text=t)
            self.tree.column(col, width=w, stretch=col == "site", anchor="e" if col == "n" else "w")
        self.tree.pack(fill="x")
        self.tree.bind("<<TreeviewSelect>>", self._select)
        self.empty = c.note("Your list is empty. Add sites above, or use “Find my sites” below to pick them from your browsing.", pady=(6, 0))
        r = c.row((8, 0))
        c.lbl(r, "How often for the selected site").pack(side="left")
        self.wvar = tk.DoubleVar(value=3)
        self.wscale = ttk.Scale(r, from_=1, to=10, variable=self.wvar, command=self._weight, style="Card.Horizontal.TScale", length=180)
        self.wscale.pack(side="left", padx=8)
        self.wlabel = c.lbl(r, "", False)
        self.wlabel.pack(side="left")
        app.btn(r, "Remove", None, "danger", self.remove).pack(side="right")
        self._reg("mylist_sites", lambda: list(self.sites), self._set_sites)
        self._reg("mylist_weights", lambda: dict(self.weights), self._set_weights)

        f = add_card(self, app, "Find my sites", "proof")
        f.note("Reads your browsers' history on this computer only. Nothing is sent anywhere. Only site names and visit counts "
               "are read, and nothing is kept until you add sites. Sites the safety filter blocks are left out.")
        self.browsers = f.note("", pady=(0, 6))
        r = f.row()
        f.lbl(r, "From history: last").pack(side="left")
        self.days = tk.StringVar(value="30")
        ttk.Spinbox(r, from_=1, to=365, width=5, textvariable=self.days).pack(side="left", padx=6)
        f.lbl(r, "days (30 recommended)", True).pack(side="left")
        self.b_scan = app.btn(r, "Scan my history", "refresh", "secondary", self.scan)
        self.b_rec = app.btn(r, "From my imported recording", "refresh", "secondary", self.recording)
        self.b_scan.pack(side="left", padx=10)
        r = f.row()
        f.lbl(r, "From bookmarks:").pack(side="left")
        self.b_bm = app.btn(r, "Import bookmarks from Firefox / Chrome", None, "primary", self.bookmarks)
        self.b_bm.pack(side="left", padx=10)
        r = f.row()
        f.lbl(r, "From a file:").pack(side="left")
        app.btn(r, "Choose a file…", None, "secondary", self.from_file,
                "A bookmarks export (.html), a network log (.har), Google Takeout history (BrowserHistory.json), or any list of "
                "addresses (.txt or .csv). Only the addresses are read.").pack(side="left", padx=10)
        r = f.row()
        f.lbl(r, "Or record: from now for").pack(side="left")
        self.hours = tk.StringVar(value="24 hours (recommended)")
        ttk.Combobox(r, state="readonly", width=22, textvariable=self.hours,
                     values=["12 hours", "24 hours (recommended)", "48 hours"]).pack(side="left", padx=6)
        self.b_watch = app.btn(r, "Start recording", "play", "secondary", self.watch_start)
        self.b_collect = app.btn(r, "Collect now", None, "secondary", self.watch_collect)
        self.b_cancel = app.btn(r, "Cancel", None, "ghost", self.watch_cancel)
        self.b_watch.pack(side="left", padx=(8, 0))
        self.watch_note = f.note("", pady=(4, 0))
        self.found_note = f.note("")
        self.ftree = ttk.Treeview(f.body, columns=("on", "site", "n"), show="headings", height=6, selectmode="none")
        for col, t, w in (("on", "Add", 50), ("site", "Site", 300), ("n", "Visits", 80)):
            self.ftree.heading(col, text=t)
            self.ftree.column(col, width=w, anchor="center" if col == "on" else "w")
        self.ftree.bind("<Button-1>", self._toggle_found)
        self.checked: set = set()
        self.add_found = app.btn(f.body, "Add the ticked sites to My List", "plus", "primary", self.add_checked)

    # -- list editing
    def _set_sites(self, sites) -> None:
        self.sites = list(sites or [])
        self.render()

    def _set_weights(self, w) -> None:
        self.weights = {k: float(v) for k, v in (w or {}).items()}
        self.render()

    def render(self) -> None:
        sel = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for i, s in enumerate(self.sites):
            self.tree.insert("", "end", iid=s, values=(i + 1, s, F.mylist_weight_label(self.weights.get(s, 3))))
        self.tree.configure(height=max(3, min(12, len(self.sites))))
        if self.sites:
            self.empty.pack_forget()
        elif not self.empty.winfo_ismapped():
            self.empty.pack(fill="x", anchor="w", pady=(6, 0))
        if sel and sel[0] in self.sites:
            self.tree.selection_set(sel[0])

    def add_sites(self, sites: list[str] | None = None, weights: dict | None = None) -> None:
        raw = sites if sites is not None else self.add_var.get().replace(",", " ").split()
        added = 0
        for x in raw:
            s = clean_site(x)
            if s and "." in s and s not in self.sites:
                self.sites.append(s)
                self.weights[s] = (weights or {}).get(s, 3)
                added += 1
        self.add_var.set("")
        self.render()
        if added:
            self.app.edited()
            self.app.flash(f"Added {added} site{'s' if added != 1 else ''}.")

    def _select(self, _e=None) -> None:
        sel = self.tree.selection()
        if sel:
            self.wvar.set(self.weights.get(sel[0], 3))
            self.wlabel.configure(text=F.mylist_weight_label(self.wvar.get()))

    def _weight(self, _v=None) -> None:
        sel = self.tree.selection()
        v = int(round(self.wvar.get()))
        self.wlabel.configure(text=F.mylist_weight_label(v))
        if sel and self.weights.get(sel[0]) != v:
            self.weights[sel[0]] = float(v)
            self.tree.set(sel[0], "often", F.mylist_weight_label(v))
            self.app.edited()

    def remove(self) -> None:
        sel = self.tree.selection()
        if sel:
            self.sites.remove(sel[0])
            self.weights.pop(sel[0], None)
            self.render()
            self.app.edited()

    # -- finding sites
    def _show_found(self, res: dict, kind: str) -> None:
        self.found, self.found_kind = res.get("sites") or [], kind
        errs = "; ".join(res.get("errors") or [])
        if not self.found:
            self.found_note.configure(text="No sites found." + (f" ({errs})" if errs else ""))
            self.ftree.pack_forget()
            self.add_found.pack_forget()
            return
        self.found_note.configure(text=f"Found {len(self.found)} sites"
                                       + (f" ({res['filtered']} left out by the safety filter)" if res.get("filtered") else "")
                                       + ". Click a row to tick or untick it, then add them." + (f" Could not read: {errs}" if errs else ""))
        self.checked = {x[0] for x in self.found[:25]}
        self.ftree.delete(*self.ftree.get_children())
        for d, n in self.found:
            self.ftree.insert("", "end", iid=d, values=("✓" if d in self.checked else "", d, n))
        self.ftree.pack(fill="x", pady=(4, 6))
        self.add_found.pack(anchor="w")

    def _toggle_found(self, e) -> None:
        iid = self.ftree.identify_row(e.y)
        if iid:
            self.checked ^= {iid}
            self.ftree.set(iid, "on", "✓" if iid in self.checked else "")

    def add_checked(self) -> None:
        n = len(self.found)
        w = {d: F.weight_from_rank(i, n, self.found_kind == "bookmarks") for i, (d, _c) in enumerate(self.found)}
        self.add_sites([d for d, _c in self.found if d in self.checked], w)

    def _finder(self, btn, fn, kind: str, busy: str) -> None:
        btn.state(["disabled"])
        self.found_note.configure(text=busy)
        self.app.work(fn, done=lambda r: (btn.state(["!disabled"]), self._show_found(r, kind)),
                      error=lambda e: (btn.state(["!disabled"]), self.found_note.configure(text=str(e))))

    def scan(self) -> None:
        days = float(self.days.get() or 30)
        self._finder(self.b_scan, lambda: self.app.ctl.mylist_scan(days), "history", "Reading your browser history…")

    def recording(self) -> None:
        self._finder(self.b_rec, self.app.ctl.mylist_from_recording, "history", "Reading your recording…")

    def bookmarks(self) -> None:
        self._finder(self.b_bm, lambda: self.app.ctl.mylist_bookmarks(None), "bookmarks", "Reading your bookmarks…")

    def from_file(self) -> None:
        path = filedialog.askopenfilename(parent=self.app.root, title="Choose a file with addresses")
        if not path:
            return

        def go():
            with open(path, "rb") as fh:
                text = fh.read(60_000_000).decode("utf-8", "ignore")
            return self.app.ctl.mylist_bookmarks(F.urls_from_text(text))
        self._finder(self.b_bm, go, "bookmarks", "Reading the file…")

    def _hours(self) -> float:
        return float(self.hours.get().split()[0])

    def watch_start(self) -> None:
        self.app.work(lambda: self.app.ctl.mylist_watch("start", self._hours()), done=lambda _r: self.refresh())

    def watch_cancel(self) -> None:
        self.app.work(lambda: self.app.ctl.mylist_watch("cancel"), done=lambda _r: self.refresh())

    def watch_collect(self) -> None:
        self.app.work(lambda: self.app.ctl.mylist_watch("collect"), done=lambda r: (self._show_found(r, "history"), self.refresh()),
                      error=lambda e: self.app.error("Recording", e))

    # -- polling
    def on_show(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        self.app.work(self.app.ctl.mylist_state, done=self._got_state)

    def update_state(self, st: dict) -> None:
        if self.app.current_tab() is self and time.time() - self._last_poll > 5:
            self._last_poll = time.time()
            self.refresh()

    def _got_state(self, d: dict) -> None:
        self.browsers.configure(text=("Browsers found: " + ", ".join(d["browsers"])) if d.get("browsers")
                                else "No browser history found on this computer.")
        now = time.time()
        if d.get("watch_started"):
            if d.get("watch_done"):
                self.watch_note.configure(text="Recording finished. Press “Collect now” to see the sites it found.")
            else:
                left = max(0, d["watch_ends"] - now)
                self.watch_note.configure(text=f"Recording your sites until {L.clock12(d['watch_ends'], day=True)} "
                                               f"({L.fmt_uptime(left)} left). Browse as usual.")
            self.b_watch.pack_forget()
            self.b_collect.pack(side="left", padx=(8, 0))
            self.b_cancel.pack(side="left")
        else:
            self.watch_note.configure(text="")
            self.b_collect.pack_forget()
            self.b_cancel.pack_forget()
            self.b_watch.pack(side="left", padx=(8, 0))


# ── ML ──────────────────────────────────────────────────────────────────────
class RocChart(Chart):
    def _plot(self, pts) -> None:
        x0, y0, x1, y1 = self.box()
        self.create_rectangle(x0, y0, x1, y1, outline=self.pal["grid"])
        self.create_line(x0, y1, x1, y0, fill=self.pal["muted"], dash=(3, 3))
        line = [c for p in pts for c in (x0 + p[0] * (x1 - x0), y1 - p[1] * (y1 - y0))]
        if len(line) >= 4:
            self.create_line(*line, fill=self.pal["noise"], width=2)
        for t in (0, 0.5, 1):
            self.create_text(x0 + t * (x1 - x0), y1 + 12, text=f"{int(t * 100)}%", fill=self.pal["muted"], font=("TkDefaultFont", 8))
            self.create_text(x0 - 6, y1 - t * (y1 - y0), text=f"{int(t * 100)}%", anchor="e", fill=self.pal["muted"], font=("TkDefaultFont", 8))


class MLTab(Tab):
    title, icon = "ML", "ml"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        page(self, app)
        self.last: dict | None = None
        c = add_card(self, app, "Can your traffic be told apart from the noise?", "ml",
                     help="A classifier tries to separate your real browsing (your browsers' history, read on this computer "
                          "only) from the noise, using only what your ISP or DNS provider could see: the hour, weekday, "
                          "rhythm, how popular each site is and revisits. 50% means it cannot tell; 100% means it always can.")
        r = c.row()
        c.lbl(r, "Look at the last").pack(side="left")
        self.days = tk.StringVar(value="14")
        ttk.Spinbox(r, from_=2, to=60, width=5, textvariable=self.days).pack(side="left", padx=6)
        c.lbl(r, "days (14 recommended)", True).pack(side="left")
        self.b_run = app.btn(r, "Run test", "play", "primary", self.run)
        self.b_run.pack(side="left", padx=(12, 6))
        self.b_demo = app.btn(r, "Try the demo", None, "secondary", lambda: self.run(demo=True),
                              "Compare the noise your current settings would make with a made-up typical person, "
                              "so you can see what this tab shows without using your own history.")
        self.b_demo.pack(side="left")
        self.f_check(c, "ml_auto", "Run automatically once a day", "Off by default.")
        self.warn = c.note("", pady=(4, 0))
        self.base = c.note("", pady=(2, 4))
        self.head = ttk.Frame(c.body, style="CardBody.TFrame")
        self.head.pack(fill="x")
        self.auc = tk.Label(self.head, text="", font=app.fonts["kpi"], bg=app.pal["panel"])
        self.verdict = ttk.Label(self.head, text="", style="Card.TLabel", justify="left", wraplength=700)
        self.kpis = ttk.Frame(c.body, style="CardBody.TFrame")
        self.kpis.pack(fill="x", pady=(8, 0))
        self.empty = c.note("No test yet. Press “Run test”: it reads your browser history, simulates the noise from your current "
                            "settings and shows how easily the two can be told apart.", pady=(6, 0))
        self.body_cards: list = []
        rc = add_card(self, app, "ROC curve", help="Cross-validated (5 folds). The dashed line is guessing.")
        self.roc = RocChart(rc.body, app.pal, 220)
        self.roc.pack(fill="x")
        fc = add_card(self, app, "Which signals give it away", help="Each signal's AUC on its own. 50% = no help to an observer.")
        self.feat = ttk.Frame(fc.body, style="CardBody.TFrame")
        self.feat.pack(fill="x")
        hc = add_card(self, app, "When you browse vs when the noise runs")
        self.hours_chart = BaselineChart(hc.body, app.pal, 170)
        self.hours_chart.pack(fill="x")
        cc = add_card(self, app, "Confusion matrix", help="Noise is the positive class; threshold at even odds.")
        self.cm = ttk.Frame(cc.body, style="CardBody.TFrame")
        self.cm.pack(anchor="w")
        tc = add_card(self, app, "Biggest giveaways, and what to change")
        self.tells = ttk.Frame(tc.body, style="CardBody.TFrame")
        self.tells.pack(fill="x")
        gc = add_card(self, app, "Specific values that give it away", help="Values seen far more often in one stream than the other.")
        self.giv = ttk.Treeview(gc.body, columns=("sig", "val", "you", "noise", "leans"), show="headings", height=5, selectmode="none")
        for col, t, w in (("sig", "Signal", 200), ("val", "Value", 120), ("you", "You", 70), ("noise", "Noise", 70), ("leans", "Leans", 160)):
            self.giv.heading(col, text=t)
            self.giv.column(col, width=w, stretch=col == "leans")
        self.giv.pack(fill="x")
        self.body_cards = [rc, fc, hc, cc, tc, gc]
        for b in self.body_cards:
            b.grid_remove()
        tr = add_card(self, app, "Score over time", help="Lower is better. Scores only; no browsing data is kept.")
        self.trend = Sparkline(tr.body, app, 80)
        self.trend.unit = "%"
        self.trend.pack(fill="x")
        self.trend_note = tr.note("No runs yet.", pady=(4, 0))
        pc = add_card(self, app, "Would this look like noise?")
        pc.note("Uses the last test's model. Enter a site and a time.")
        r = pc.row()
        self.site = tk.StringVar()
        ttk.Entry(r, textvariable=self.site, width=28).pack(side="left")
        self.day = tk.StringVar(value="Wed")
        ttk.Combobox(r, state="readonly", width=6, textvariable=self.day, values=["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]).pack(side="left", padx=6)
        self.hour = tk.StringVar(value="21:00")
        ttk.Combobox(r, state="readonly", width=7, textvariable=self.hour, values=[f"{h:02d}:00" for h in range(24)]).pack(side="left")
        app.btn(r, "Predict", None, "secondary", self.predict).pack(side="left", padx=8)
        self.pred = pc.note("", muted=False, pady=(6, 0))

    def retheme(self) -> None:
        self.sf.retheme()
        for ch in (self.roc, self.hours_chart):
            ch.set_palette(self.app.pal)
        self.trend.redraw()
        self.auc.configure(bg=self.app.pal["panel"])
        if self.last:
            self.render(self.last)

    def on_show(self) -> None:
        self.app.work(self.app.ctl.ml_state, self._got_state)

    def _got_state(self, m: dict) -> None:
        self.base.configure(text=(m.get("baseline") or {}).get("status", ""))
        self.trend.set_values([h[1] for h in m.get("history") or []])
        hist = m.get("history") or []
        self.trend_note.configure(text=f"Last: {hist[-1][1]}%, lower is better. {len(hist)} run(s)." if hist else "No runs yet.")
        if m.get("last") and self.last is None:
            self.render(m["last"])

    def run(self, demo: bool = False) -> None:
        self.b_run.state(["disabled"])
        self.b_demo.state(["disabled"])
        self.empty.configure(text="Making up a typical person and simulating the noise… a few seconds." if demo
                             else "Reading your history and simulating the noise… a few seconds.")
        days = float(self.days.get() or 14)

        def done(d):
            self.b_run.state(["!disabled"])
            self.b_demo.state(["!disabled"])
            self.render(d)
            self.on_show()

        def fail(e):
            self.b_run.state(["!disabled"])
            self.b_demo.state(["!disabled"])
            self.empty.configure(text=str(e))
        self.app.work(lambda: self.app.ctl.selftest(days, demo=demo), done, fail)

    def render(self, d: dict) -> None:
        self.last = d
        p = self.app.pal
        warn = list(d.get("warnings") or []) + ["Could not read: " + e for e in d.get("errors") or []]
        self.warn.configure(text="\n".join(warn))
        self.base.configure(text=(d.get("baseline") or {}).get("status", ""))
        for w in self.kpis.winfo_children():
            w.destroy()
        if d.get("error"):
            self.empty.configure(text=f"{d['error']} ({d.get('real_visits', 0)} of your visits found)")
            self.auc.pack_forget()
            self.verdict.pack_forget()
            for b in self.body_cards:
                b.grid_remove()
            return
        self.empty.configure(text="")
        col = p["ok"] if d["score"] < 60 else p["warn"] if d["score"] < 75 else p["bad"]
        self.auc.configure(text=f"{d['auc']}%", fg=col)
        self.auc.pack(side="left")
        self.verdict.configure(text=f"{d['verdict']}\nROC AUC · 95% interval {d['ci95'][0]}-{d['ci95'][1]}% · {d['compared']} of your visits "
                                    f"vs {d['compared']} noise events ({d['noise_source']}) · last {d['days']:g} days")
        self.verdict.pack(side="left", padx=14)
        g = d.get("strong") or {}
        strong = ([("Stronger observer (AUC)", f"{g['auc']}%"),
                   ("Future events only", "—" if g.get("forward_auc") is None else f"{g['forward_auc']}%"),
                   ("Caught at 1% false alarms", f"{g['tpr_at_1pct_fpr']}%"),
                   ("Caught at 0.1% false alarms", f"{g['tpr_at_01pct_fpr']}%"),
                   ("Right if 1 in 100 is noise", f"{g['precision_at_prevalence']}%")] if g else [])
        for k, v in (("Accuracy", f"{d['accuracy']}%"), ("Precision", f"{d['precision']}%"), ("Recall", f"{d['recall']}%"),
                     ("F1", f"{d['f1']}%"), ("Log loss", d["log_loss"]), ("Fold AUCs", " · ".join(str(x) for x in d["folds"])),
                     *strong):
            box = ttk.Frame(self.kpis, style="Card.TFrame", padding=(10, 6))
            box.pack(side="left", padx=(0, 8))
            ttk.Label(box, text=str(v), style="Card.TLabel", font=self.app.fonts["bold"]).pack()
            ttk.Label(box, text=k, style="CardMuted.TLabel").pack()
        for b in self.body_cards:
            b.grid()
        self.roc.update_data(d["roc"])
        for w in self.feat.winfo_children():
            w.destroy()
        for f, v in d["per_feature"].items():
            row = ttk.Frame(self.feat, style="CardBody.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=FNAME.get(f, f), style="Card.TLabel", width=30).pack(side="left")
            ttk.Progressbar(row, maximum=50, value=max(0, v - 50), length=240).pack(side="left", padx=8)
            ttk.Label(row, text=f"{v}%", style="Card.TLabel").pack(side="left")
        you, noi = d["hours"]["you"], d["hours"]["noise"]
        sy, sn = (sum(you) or 1), (sum(noi) or 1)
        self.hours_chart.update_data({"you": [x / sy for x in you], "noise": [x / sn for x in noi], "state": "ok"})
        for w in self.cm.winfo_children():
            w.destroy()
        c = d["confusion"]
        for r, row in enumerate((("", "predicted you", "predicted noise"), ("really you", c["tn"], c["fp"]), ("really noise", c["fn"], c["tp"]))):
            for k, txt in enumerate(row):
                ttk.Label(self.cm, text=str(txt), style="CardMuted.TLabel" if r == 0 or k == 0 else "Card.TLabel").grid(
                    row=r, column=k, padx=14, pady=2, sticky="w")
        for w in self.tells.winfo_children():
            w.destroy()
        if not d["tells"]:
            ttk.Label(self.tells, text="No single signal stands out.", style="Card.TLabel").pack(anchor="w")
        for t in d["tells"]:
            lb = ttk.Label(self.tells, text=f"{FNAME.get(t['feature'], t['feature'])} ({t['auc']}%): {t['advice']}",
                           style="Card.TLabel", justify="left")
            lb.pack(fill="x", anchor="w", pady=2)
            autowrap(lb, self.tells, 8)
        self.giv.delete(*self.giv.get_children())
        for g in d["giveaways"]:
            ratio = f"{g['ratio']}×" if g["ratio"] >= 1 else f"{round(1 / g['ratio'], 1)}×"
            self.giv.insert("", "end", values=(FNAME.get(g["feature"], g["feature"]), g["value"], g["you"], g["noise"], f"{g['leans']} ({ratio})"))

    def predict(self) -> None:
        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        site, wd, hr = self.site.get(), days.index(self.day.get()), int(self.hour.get()[:2])

        def done(d):
            self.pred.configure(text=f"{d['noise_probability']}% likely to be noise: {d['site']} on {days[d['weekday']]} at {d['hour']:02d}:00")
        self.app.work(lambda: self.app.ctl.ml_predict(site, hr, wd), done, lambda e: self.pred.configure(text=str(e)))


# ── Tools ───────────────────────────────────────────────────────────────────
class ToolsTab(Tab):
    title, icon = "Tools", "tools"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        self._cols = 2
        page(self, app).columnconfigure(1, weight=1)
        self._speed_job = None
        c = add_card(self, app, "Privacy check", "proof")
        c.note("What actually protects you, checked on this computer only. Nothing is sent anywhere.")
        self.priv = self._tool(c, "Run privacy check", self.privacy)
        c = add_card(self, app, "DNS leak check", "proof")
        c.note("Shows which DNS servers your computer is set to use (often just a router, VPN or Qubes network qube "
               "forwarding for you) and which resolver really answered a lookup. Each click makes two small lookups.")
        self.dns = self._tool(c, "Run DNS check", self.dnscheck)
        self.link(c, "For the authoritative external test: dnsleaktest.com", "https://www.dnsleaktest.com/")
        c = add_card(self, app, "Speed test")
        c.note("Downloads about 10 MB and uploads 2 MB once, over the normal internet (not Tor), through your clearnet proxy if "
               "you set one. Runs only when you click.")
        self.speed = self._tool(c, "Run speed test", self.speedtest)
        c = add_card(self, app, "How much data will this use?", "act")
        c.note("A rough estimate from your current settings (amount, mix, real browser, low-data mode, active hours, cap). Real pages vary a lot.")
        self.est = self._tool(c, "Estimate", self.estimate)
        c = add_card(self, app, "MAC address", "proof")
        c.note("Wi-Fi and LAN operators can log your network card's hardware address. This shows what each physical interface "
               "uses now. Changing it needs administrator rights, so run it in a terminal: sudo legalprivacy mac randomize "
               "--all (docs/MAC.md). On Qubes OS or any VM, run it where the physical card is (sys-net).")
        self.mac = self._tool(c, "Check MAC addresses", self.macstatus)
        c = add_card(self, app, "Live log")
        c.note("The live log is kept in memory only. Nothing is written to disk, and it is cleared when legalPrivacy quits.")
        r = c.row()
        app.btn(r, "Clear live log now", None, "secondary", self.clear_log).pack(side="left")
        c = add_card(self, app, "Related checks")
        c.note("Outside links, opened in your browser only when you click them.")
        c.note("To check that your traffic really leaves through Tor, use Test Tor on the Tor tab: it asks "
               "check.torproject.org through the app's own Tor. (Opening that page in a normal browser can only say no.)")
        self.link(c, "About OpenNIC resolvers (opennicproject.org)", "https://www.opennicproject.org/")
        c = add_card(self, app, "Files")
        c.note(f"Config file: {app.ctl.profile_path}")
        c.note("No log file is kept. The only file legalPrivacy writes is that config file.")

    def link(self, card: Card, text: str, url: str) -> None:
        b = self.app.btn(card.body, text, None, "link", lambda: webbrowser.open(url))
        b.pack(anchor="w")

    def _tool(self, card: Card, label: str, fn):
        r = card.row()
        b = self.app.btn(r, label, "play", "secondary", fn)
        b.pack(side="left")
        out = ttk.Frame(card.body, style="CardBody.TFrame")
        out.pack(fill="x", pady=(8, 0))
        out.btn = b
        return out

    @staticmethod
    def _text(out, text: str, muted: bool = False) -> None:
        for w in out.winfo_children():
            w.destroy()
        lb = ttk.Label(out, text=text, style="CardMuted.TLabel" if muted else "Card.TLabel", justify="left")
        lb.pack(fill="x", anchor="w")
        autowrap(lb, out, 6)

    def _run(self, out, fn, show, busy: str = "Working…") -> None:
        out.btn.state(["disabled"])
        self._text(out, busy, True)

        def done(d):
            out.btn.state(["!disabled"])
            show(d)

        def fail(e):
            out.btn.state(["!disabled"])
            self._text(out, str(e))
        self.app.work(fn, done, fail)

    def estimate(self) -> None:
        self._run(self.est, self.app.ctl.estimate, lambda d: self._text(self.est, F.estimate_text(d)))

    def _rows(self, out, rows: list[tuple]) -> None:
        for w in out.winfo_children():
            w.destroy()
        for tone, name, detail, advice in rows:
            row = ttk.Frame(out, style="CardBody.TFrame")
            row.pack(fill="x", pady=3)
            pl = pill(row, name, tone)
            pl.grid(row=0, column=0, sticky="nw", padx=(0, 10))
            lb = ttk.Label(row, text=detail + (f"\n{advice}" if advice else ""), style="Card.TLabel", justify="left")
            lb.grid(row=0, column=1, sticky="w")
            row.columnconfigure(1, weight=1)
            lb.bind("<Configure>", lambda e: None)
            autowrap(lb, row, 260)

    def privacy(self) -> None:
        tone = {"ok": "ok", "warn": "warn", "info": "info"}
        self._run(self.priv, self.app.ctl.privacy_check,
                  lambda checks: self._rows(self.priv, [(tone.get(c["status"], "off"), c["name"], c["detail"], c.get("advice", "")) for c in checks]))

    def dnscheck(self) -> None:
        def show(d):
            rows = [("info", r["ip"], str(r["verdict"]), "") for r in d.get("resolvers") or []]
            eg = d.get("egress_resolver") or {}
            if eg.get("ip"):
                tail = {True: " (one of your chosen resolvers)", False: " (not one of your chosen resolvers)"}.get(eg.get("is_chosen"), "")
                rows.append(("ok", "Answered by", f"{eg['ip']}" + (f" ({eg['name']})" if eg.get("name") else "") + tail,
                             "This resolver sees your lookups, however many forwarders sit in front of it."))
            if d.get("note"):
                rows.append(("warn" if d.get("qubes") else "off", "Note", d["note"], ""))
            if rows:
                self._rows(self.dns, rows)
            else:
                self._text(self.dns, "No resolver found in your system settings.")
        self._run(self.dns, self.app.ctl.resolvers_check, show)

    def macstatus(self) -> None:
        def show(d):
            rows = [("ok" if i["spoofed"] else "info", i["iface"],
                     f"now {i['current']}, factory {i['permanent']}" + (" (default route)" if i["default_route"] else ""), "")
                    for i in d["interfaces"]]
            if rows:
                self._rows(self.mac, rows)
            else:
                self._text(self.mac, "No physical network interface here" +
                           (" (only a Xen virtual one: a Qubes qube; the physical card is in sys-net)."
                            if d["environment"]["xen_virtual_interfaces"] else "."))
        self._run(self.mac, self.app.ctl.mac_status, show)

    def speedtest(self) -> None:
        self.speed.btn.state(["disabled"])
        self._text(self.speed, "Starting…", True)

        self.app.work(self.app.ctl.speed_start, lambda st: self._speed_state(st), lambda e: self._text(self.speed, str(e)))

    def _speed_state(self, st: dict) -> None:
        if st.get("state") == "running":
            self._text(self.speed, st.get("progress") or "Running…", True)
            self.app.root.after(1000, lambda: self.app.work(self.app.ctl.speed_status, self._speed_state))
            return
        self.speed.btn.state(["!disabled"])
        res = st.get("result")
        if not res:
            self._text(self.speed, "No result yet.", True)
            return
        def mb(v):
            return "failed" if v is None else f"{v} Mbit/s"
        txt = f"Download {mb(res['down_mbps'])}, upload {mb(res['up_mbps'])}."
        if res.get("errors"):
            txt += " " + "; ".join(res["errors"])
        self._text(self.speed, txt)

    def clear_log(self) -> None:
        self.app.ctl.log.clear()
        self.app.flash("Live log cleared.")


# ── Health ──────────────────────────────────────────────────────────────────
class HealthTab(Tab):
    title, icon = "Health", "health"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        page(self, app)
        c = add_card(self, app, "Health checks", "health", help="Self-checks of the libraries, files, Tor and the browser, in plain language.")
        self.b_run = app.btn(c.actions, "Run health checks", "play", "primary", self.run)
        self.b_run.pack()
        self.out = ttk.Frame(c.body, style="CardBody.TFrame")
        self.out.pack(fill="x")
        ttk.Label(self.out, text="Press “Run health checks”.", style="CardMuted.TLabel").pack(anchor="w")

    def run(self) -> None:
        self.b_run.state(["disabled"])

        def done(checks):
            self.b_run.state(["!disabled"])
            for w in self.out.winfo_children():
                w.destroy()
            tone = {"ok": "ok", "warn": "warn", "fail": "bad", "info": "info"}
            for ch in checks:
                row = ttk.Frame(self.out, style="CardBody.TFrame")
                row.pack(fill="x", pady=3)
                pill(row, {"ok": "✓ ok", "warn": "! warn", "fail": "✗ fail", "info": "ℹ info"}.get(ch["status"], ch["status"]),
                     tone.get(ch["status"], "off")).grid(row=0, column=0, sticky="nw", padx=(0, 10))
                ttk.Label(row, text=ch["name"], style="Card.TLabel", font=self.app.fonts["bold"], width=34).grid(row=0, column=1, sticky="nw")
                lb = ttk.Label(row, text=ch["detail"], style="CardMuted.TLabel", justify="left")
                lb.grid(row=0, column=2, sticky="w")
                row.columnconfigure(2, weight=1)
                autowrap(lb, row, 420)
                fix = ch.get("fix")
                if fix:
                    self.app.btn(row, fix["label"], None, "secondary",
                                 lambda f=fix: self.apply_fix(f), "Make this change now.").grid(row=1, column=2, sticky="w", pady=(4, 0))
        self.app.work(self.app.ctl.doctor, done, lambda e: (self.b_run.state(["!disabled"]), self.app.error("Health", e)))

    def apply_fix(self, fix: dict) -> None:
        """One-click change from a recommendation, then run the checks again."""
        self.app.work(lambda: self.app.ctl.apply_config(fix["config"]),
                      done=lambda _r: (self.app.flash(fix["label"] + ": done. Restart Tor to apply it."), self.run()),
                      error=lambda e: self.app.error("Health", e))


# ── Help ────────────────────────────────────────────────────────────────────
class HelpTab(Tab):
    title, icon = "Help", "help"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        page(self, app)
        c = add_card(self, app, "What this does", "help")
        for head, text in (
                ("", "legalPrivacy makes believable searches, page visits and DNS lookups in the background, so that bulk "
                     "analysis of your real browsing tells much less about you. Every request shows in Activity; everything the "
                     "app and Tor report is in Live Log. Both are kept in memory only and cleared when you quit."),
                ("Activity vs Live Log.", "Activity lists each request the noise made and what happened on it. Live Log is "
                                          "everything the app says, including starts and stops, Tor's own messages and warnings."),
                ("Getting started.", "Everything already has the recommended setting. Press Start; the first action comes "
                                     "within seconds. Settings save themselves."),
                ("Look like yourself.", "Add the sites you really use on My List, then check the ML tab: it shows how easily "
                                        "your traffic can be told apart from the noise, and which settings help."),
                ("Tor (optional).", "Off by default. With Tor on, legalPrivacy can visit .onion sites through its own private "
                                    "Tor, which it downloads, checks and starts for you. Many .onion sites are offline at any "
                                    "moment; those are skipped for a while, which is normal."),
                ("Remote machines.", "The Remote tab runs the noise on other computers you own or are authorised to use, over SSH "
                                     "(user@host[:port] with a password or a private key). The app copies one small file into "
                                     "~/.cache/legalprivacy on that machine, runs it, shows its log, and deletes it when you remove "
                                     "the machine. Needs paramiko here and Python 3 there; no root and no display. The first time, "
                                     "you must confirm the machine's host key fingerprint; a changed key is refused. Passwords are "
                                     "kept in memory only."),
                ("Contribute to Tor.", "“legalprivacy relay gen” writes a middle-relay or bridge configuration; it never runs "
                                       "an exit. The Tor tab has two optional cards, both off by default: Tor DNS (Tor answers "
                                       "A, AAAA and PTR lookups on a local port; exit relays resolve the names, so it is slower "
                                       "and is a deliberate, narrow use of exits for DNS only) and Contribute to Tor: run a "
                                       "relay (a middle relay or bridge as a separate Tor program; start with Practice mode, "
                                       "which publishes nothing). A relay is not an exit and does not provide DNS."),
                ("Antivirus (optional).", "The Security tab manages the ClamAV you installed yourself, offline-first. Only "
                                          "freshclam, the signature updater, ever contacts the internet, and only when you press "
                                          "Update and confirm. Scans use clamscan with this app's own signature folder, with "
                                          "the network removed where the system allows (Linux) and the scanner watched for any "
                                          "connection everywhere; a connection marks the scan NOT OFFLINE and stops it. Nothing "
                                          "is ever deleted or moved except by your explicit Quarantine click."),
                ("Keyboard.", "F5 Start, F6 Pause or Resume, F7 Stop, Ctrl+1 to Ctrl+9 jump between tabs, Ctrl+Q quit. Tab and "
                              "Shift+Tab move between controls; Space presses a button.")):
            lb = ttk.Label(c.body, text=(head + " " if head else "") + text, style="Card.TLabel", justify="left")
            lb.pack(fill="x", anchor="w", pady=(0, 8))
            autowrap(lb, c.body, 6)
        c = add_card(self, app, "Named after a blog")
        lb = ttk.Label(c.body, style="Card.TLabel", justify="left",
                       text="legalPrivacy is named in homage to Legalizing Privacy by Amy Peikoff, writing about why and how to "
                            "legalize privacy, using the principles of private property and freedom of contract.")
        lb.pack(fill="x", anchor="w")
        autowrap(lb, c.body, 6)
        r = c.row((8, 0))
        for text, url in (("Legalizing Privacy", BLOG), ("About the blog", BLOG + "/about"), ("Archive", BLOG + "/archive")):
            app.btn(r, text, "web", "secondary", lambda u=url: webbrowser.open(u)).pack(side="left", padx=(0, 6))
        c = add_card(self, app, "Web dashboard (backup)", "web")
        c.note("The web dashboard has the same controls in a browser tab, and a few things that need a web view, like the "
               "animated network map. It runs on this computer only.")
        app.web_button(c.body, "Open the web dashboard")
