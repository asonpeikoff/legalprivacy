"""The Settings tab of the native app: one scrolling page of cards that mirrors the web dashboard's Settings
(DNS, user agent, extras, persona/interests/household, own activity, search engines, general, realism and
sources, accounts, panic). Every control saves by itself through the app's live-apply."""
from __future__ import annotations

import ipaddress
import tkinter as tk
from tkinter import messagebox, ttk

from . import gui_fields as F
from . import gui_logic as L
from .gui_base import Tab
from .gui_theme import Banner, Card, MixBar, ScrollFrame, pill, set_pill

GAP = 12
HOURS = [(h, f"{h:02d}:00") for h in range(24)]
ACCOUNTS = [("google", "Google", "Gmail inbox, a Google search, YouTube"),
            ("microsoft", "Microsoft (Outlook)", "Outlook inbox and calendar, Bing, microsoft.com")]
SECTIONS = [("DNS", "dns"), ("User agent", "ua"), ("Behaviour", "extras"), ("Persona", "persona"),
            ("Realism", "realism"), ("Accounts", "accounts"), ("General", "general"), ("Panic", "panic")]


class SettingsTab(Tab):
    title, icon = "Settings", "set"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)
        nav = ttk.Frame(self, padding=(18, 8, 18, 0))
        nav.grid(row=0, column=0, sticky="ew")
        ttk.Label(nav, text="Jump to", style="Muted.TLabel").pack(side="left", padx=(0, 8))
        self.sf = ScrollFrame(self, app)
        self.sf.grid(row=1, column=0, sticky="nsew")
        self.cards: dict = {}
        f = self.sf.inner
        f.columnconfigure(0, weight=1)
        self.saved_lbl = ttk.Label(f, text="Settings save by themselves a moment after you change them.", style="Muted.TLabel")
        self.saved_lbl.grid(row=0, column=0, sticky="w", pady=(0, GAP))
        self._row = 1
        self.res: list[dict] = []
        self.dns_report: dict = {}
        self.ua_lib: list[dict] = []
        self.interest: dict = {}
        self._tor_on = False
        self.acc_ui: dict = {}
        self.build_dns()
        self.build_ua()
        self.build_extras()
        self.build_persona()
        self.build_realism()
        self.build_accounts()
        self.build_general()
        self.build_logo()
        self.build_panic()
        for label, key in SECTIONS:
            b = app.btn(nav, label, None, "seg", lambda k=key: self.sf.scroll_to(self.cards[k]))
            b.pack(side="left", padx=(0, 4))
        self._reg("dns_resolvers", lambda: [dict(r) for r in self.res], self._set_resolvers)
        self._reg("accounts", self._get_accounts, self._set_accounts)
        self._reg("search_engines", self._get_search, self._set_search)
        self._reg("interest_list", self._get_themes, self._set_themes)
        self._reg("ua_pin", self._get_ua_pin, self._set_ua_pin)
        self._reg("ua_choice", lambda: self.ua_choice.get(), lambda x: self.ua_choice.set(x))
        self._reg("cookie_value", lambda: float(self.cookie_value.get()), lambda x: self.cookie_value.set(f"{x:g}"))
        self._reg("cookie_unit", lambda: self.cookie_unit.get(), lambda x: self.cookie_unit.set(x))
        app.after_idle_job(self.fetch_static)

    # -- layout helper
    def card(self, key: str, title: str, icon: str | None = None, help: str = "") -> Card:
        c = Card(self.sf.inner, self.app, title, icon, help)
        c.grid(row=self._row, column=0, sticky="ew", pady=(0, GAP))
        self._row += 1
        self.cards[key] = c
        return c

    # ── DNS ────────────────────────────────────────────────────────────────
    def build_dns(self) -> None:
        c = self.card("dns", "DNS lookups", "web")
        c.note("In Activity and the Live Log each lookup shows the site looked up and which resolver answered.")
        self.f_radios(c, "dns_mode", [
            ("system", "Your normal DNS", "Whatever your router, ISP, VPN or system already uses, so the noise lands exactly "
                                          "where your real lookups do."),
            ("secure", "Secure resolvers only", "Only the resolvers listed below."),
            ("mix", "Mix (recommended)", "Switch between the two in random 10-60 minute blocks.")])
        r = c.row()
        c.lbl(r, "In mix mode, spend").pack(side="left")
        self.f_spin(r, "dns_share", 0, 100, 5, 5).pack(side="left", padx=6)
        c.lbl(r, "% of the time on your normal DNS").pack(side="left")
        self.sys_note = c.note("Your normal DNS: press “Check now” to see which servers this computer uses.", pady=(6, 2))
        self.warn = Banner(c.body, "", "warn", host=c.body)
        c.heading("Resolvers", "the exact IPs used in Secure / Mix mode")
        r = c.row()
        self.b_check = self.app.btn(r, "Check now", "refresh", "secondary", self.check_dns)
        self.b_check.pack(side="left")
        self.app.btn(r, "Reset to recommended", None, "ghost", self.reset_resolvers).pack(side="left", padx=6)
        cols = ("on", "name", "ip", "role", "note", "status")
        self.rtree = ttk.Treeview(c.body, columns=cols, show="headings", height=4, selectmode="browse")
        for col, t, w in (("on", "On", 40), ("name", "Name", 130), ("ip", "IP address", 120), ("role", "Role", 70),
                          ("note", "Note", 230), ("status", "Status", 220)):
            self.rtree.heading(col, text=t)
            self.rtree.column(col, width=w, anchor="center" if col == "on" else "w", stretch=col in ("note", "status"))
        self.rtree.pack(fill="x", pady=(4, 6))
        self.rtree.bind("<<TreeviewSelect>>", self._res_select)
        self.rtree.bind("<Double-1>", self._res_toggle)
        self.empty_res = c.note("No resolvers. Add one below, or Reset to recommended.")
        self.r_name, self.r_ip, self.r_role, self.r_note = tk.StringVar(), tk.StringVar(), tk.StringVar(value="primary"), tk.StringVar()
        r = c.row()
        for lab, var, w in (("Name", self.r_name, 14), ("IP", self.r_ip, 16)):
            c.lbl(r, lab, True).pack(side="left")
            ttk.Entry(r, textvariable=var, width=w).pack(side="left", padx=(4, 10))
        ttk.Combobox(r, state="readonly", width=9, textvariable=self.r_role, values=["primary", "fallback"]).pack(side="left", padx=(0, 10))
        c.lbl(r, "Note", True).pack(side="left")
        ttk.Entry(r, textvariable=self.r_note, width=22).pack(side="left", padx=4)
        r = c.row()
        self.app.btn(r, "Add as new", "plus", "secondary", self.res_add).pack(side="left")
        self.app.btn(r, "Update selected", None, "secondary", self.res_update).pack(side="left", padx=6)
        self.app.btn(r, "Remove selected", None, "danger", self.res_remove).pack(side="left")
        c.note("Double-click a row to switch it on or off.", pady=(2, 0))
        r = c.row((6, 0))
        c.lbl(r, "A server slower than").pack(side="left")
        self.f_spin(r, "dns_slow", 50, 3000, 50, 6).pack(side="left", padx=6)
        c.lbl(r, "ms counts as not fast.").pack(side="left")
        c.heading("Extras", "optional, added as primaries")
        self.f_check(c, "dns_opennic", "OpenNIC servers", "Servers that pass OpenNIC's checks, keep no logs (preferred) or "
                                                           "anonymized logs, and offer DNSCrypt, DoH or DoT.")
        self.opennic_note = c.note("", pady=(0, 2))
        self.f_check(c, "dns_quad9", "Quad9", "9.9.9.9 and 149.112.112.112 (blocks malware domains, DNSSEC)")
        r = c.row((6, 0))
        c.lbl(r, "Your own resolvers").pack(side="left")
        self.f_entry(r, "dns_custom", 40, "optional, e.g. 1.2.3.4, 5.6.7.8").pack(side="left", padx=8)

    def _set_resolvers(self, rows) -> None:
        self.res = [dict(r) for r in rows or []]
        self.render_res()

    def render_res(self) -> None:
        sel = self.rtree.selection()
        self.rtree.delete(*self.rtree.get_children())
        by = {h["ip"]: h for h in (self.dns_report.get("resolvers") or [])}
        for i, r in enumerate(self.res):
            txt, _tone, _tip = F.resolver_verdict(by.get(r.get("ip")))
            self.rtree.insert("", "end", iid=str(i), values=("✓" if r.get("enabled", True) else "", r.get("name", ""),
                                                             r.get("ip", ""), r.get("role", "primary"), r.get("note", ""), txt))
        self.rtree.configure(height=max(2, min(8, len(self.res))))
        if self.res:
            self.empty_res.pack_forget()
        elif not self.empty_res.winfo_ismapped():
            self.empty_res.pack(fill="x", anchor="w")
        if sel and sel[0] in self.rtree.get_children():
            self.rtree.selection_set(sel[0])

    def _res_select(self, _e=None) -> None:
        sel = self.rtree.selection()
        if sel:
            r = self.res[int(sel[0])]
            self.r_name.set(r.get("name", ""))
            self.r_ip.set(r.get("ip", ""))
            self.r_role.set(r.get("role", "primary"))
            self.r_note.set(r.get("note", ""))

    def _res_toggle(self, e) -> None:
        iid = self.rtree.identify_row(e.y)
        if iid:
            r = self.res[int(iid)]
            r["enabled"] = not r.get("enabled", True)
            self.render_res()
            self.app.edited()

    def _res_from_form(self) -> dict | None:
        ip = self.r_ip.get().strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            messagebox.showwarning("Resolver", f"“{ip}” is not an IP address.", parent=self.app.root)
            return None
        return {"ip": ip, "name": self.r_name.get().strip() or ip, "role": self.r_role.get(), "enabled": True,
                "note": self.r_note.get().strip()}

    def res_add(self) -> None:
        r = self._res_from_form()
        if r:
            self.res.append(r)
            self.render_res()
            self.app.edited()

    def res_update(self) -> None:
        sel = self.rtree.selection()
        r = self._res_from_form() if sel else None
        if r:
            r["enabled"] = self.res[int(sel[0])].get("enabled", True)
            self.res[int(sel[0])] = r
            self.render_res()
            self.app.edited()

    def res_remove(self) -> None:
        sel = self.rtree.selection()
        if sel:
            del self.res[int(sel[0])]
            self.render_res()
            self.app.edited()

    def reset_resolvers(self) -> None:
        if not messagebox.askokcancel("Resolvers", "Replace the resolver list with the recommended one?", parent=self.app.root):
            return
        from .config import RECOMMENDED_RESOLVERS
        self.res = [dict(r) for r in RECOMMENDED_RESOLVERS]
        self.render_res()
        self.app.edited()

    def check_dns(self) -> None:
        self.b_check.state(["disabled"])
        self.app.work(self.app.ctl.check_dns, done=lambda _r: self.app.poll_now())

    # ── user agent ─────────────────────────────────────────────────────────
    def build_ua(self) -> None:
        c = self.card("ua", "User agent", "web", help="The user agent is the line every browser sends that says what browser "
                                                     "and system it is. Noise that claims a different browser than yours can "
                                                     "stand out. This sets how the plain-HTTP noise sends it; the real "
                                                     "browser always sends its own.")
        c.note("Mix (recommended) sends your own browser's user agent most of the time and a random one the rest, so the "
               "noise looks like you and also like other machines; it keeps working when your browser randomises its own "
               "user agent with an add-on. Your own only always looks like you. Random changes the browser the noise claims to be every hour or day (it adds a second browser on "
               "your connection). One fixed library entry is an easy pattern: only pick it for a specific reason.")
        self.ua_choice = tk.StringVar()
        self.ua_choice.trace_add("write", self._var_changed)
        for val, lab in F.UA_CHOICES:
            c.radio(self.ua_choice, val, lab)
        r = c.row((8, 2))
        c.lbl(r, "Mix: share that uses my own browser's (%)").pack(side="left")
        self.f_spin(r, "ua_own_share", 0, 100, 5, 5).pack(side="left", padx=6)
        r = c.row((8, 2))
        c.lbl(r, "Your browser's user agent").pack(side="left")
        self.f_entry(r, "own_ua", 46, "paste it, or press Detect").pack(side="left", padx=8, fill="x", expand=True)
        r = c.row()
        self.b_detect = self.app.btn(r, "Detect from my browser", "refresh", "secondary", self.detect_ua,
                                     "Starts your installed Chrome/Chromium briefly, headless, to read it.")
        self.b_detect.pack(side="left")
        self.ua_note = c.lbl(r, "", True)
        self.ua_note.pack(side="left", padx=8)
        r = c.row((8, 0))
        c.lbl(r, "Library entry").pack(side="left")
        self.ua_var = tk.StringVar()
        self.ua_box = ttk.Combobox(r, state="readonly", width=60, textvariable=self.ua_var, values=[])
        self.ua_box.pack(side="left", padx=8)
        self.ua_box.bind("<<ComboboxSelected>>", lambda _e: (self.ua_choice.set("lib"), self.app.edited()))
        self.ua_count = c.note("", pady=(4, 0))
        self.ua_applies = c.note("", pady=(0, 0))

    def _get_ua_pin(self) -> str:
        for e in self.ua_lib:
            if self._ua_label(e) == self.ua_var.get():
                return e["id"]
        return "own"

    def _set_ua_pin(self, x) -> None:
        for e in self.ua_lib:
            if e["id"] == x:
                self.ua_var.set(self._ua_label(e))
                return
        self.ua_var.set("")

    @staticmethod
    def _ua_label(e: dict) -> str:
        return f"{e['group']} · {e['platform']} · {e['release']} · {e['share']}%  —  {e['ua'][:60]}"

    def detect_ua(self) -> None:
        self.ua_note.configure(text="Starting your browser briefly…")
        self.b_detect.state(["disabled"])

        def done(d):
            self.b_detect.state(["!disabled"])
            if d.get("error"):
                self.ua_note.configure(text=d["error"])
            else:
                self.ua_note.configure(text="Detected.")
                self.load({"own_ua": d["ua"]})
                self.app.edited()
        self.app.work(self.app.ctl.ua_detect, done, lambda e: (self.b_detect.state(["!disabled"]), self.ua_note.configure(text=str(e))))

    # ── behaviour extras ───────────────────────────────────────────────────
    def build_extras(self) -> None:
        c = self.card("extras", "Behaviour and extras", "set", help="Optional extras. None of them changes anything unless "
                                                                    "you turn it on.")
        self.f_check(c, "active_hours", "Only make noise during these hours",
                     "Off by default. Noise outside your waking hours can look odd, so this helps if your days are regular.")
        r = c.row()
        c.lbl(r, "from").pack(side="left")
        self.f_combo(r, "active_from", HOURS, 7).pack(side="left", padx=6)
        c.lbl(r, "to").pack(side="left")
        self.f_combo(r, "active_to", HOURS, 7).pack(side="left", padx=6)
        c.lbl(r, "your local time", True).pack(side="left")
        self.f_check(c, "browser_dns", "Look sites up like a browser does",
                     "Recommended. Also asks for IPv6 (AAAA) and HTTPS records, not just the address.")
        self.f_check(c, "dns_bursts", "Follow lookups with a page's burst of lookups",
                     "Recommended. A real page load asks for its fonts, scripts and other sites a few tens of milliseconds "
                     "apart; single lookups on their own look unlike that.")
        self.f_check(c, "keep_alive", "Keep it running",
                     "Recommended. If the noise stops on its own, pauses itself or gets stuck, it is started or woken again "
                     "within about a minute, so it can run for weeks untouched. A pause you press yourself is never undone, "
                     "and your daily data limit (if you set one) still holds until midnight.")
        self.f_check(c, "file_transfers", "File transfers",
                     "Recommended. Now and then the noise downloads a real public file and throws it away (mostly photos, sometimes "
                     "a video, zip, document or track) from the Internet Archive's free collections, or uploads a random-sized "
                     "block of random bytes to a speed-test server (never anything of yours). Each download is capped at 20 MB. "
                     "Skipped in low-data mode.")
        self.f_check(c, "duck_chat", "Chat noise on duck.ai",
                     "Off by default. Now and then, in a long session, the real-browser lane has a short made-up chat on duck.ai "
                     "(one topic, one to four messages of different lengths, typed like a person). The questions never come from "
                     "you. Switching it on accepts duck.ai's terms screen for you (its Privacy Policy and Terms of Service), and "
                     "duck.ai may limit or block automated use.")
        self.f_check(c, "typos", "More typos in searches", "Off by default. A few searches always have a small slip; this "
                                                            "makes it about 1 in 9.")
        self.f_check(c, "polite", "Polite mode", "Off by default. Never the same site twice within a minute.")
        self.f_check(c, "low_data", "Low-data mode", "Off by default. The real browser skips images, video and fonts. Saves "
                                                     "data, but real browsers load images, so it looks less real.")
        r = c.row((8, 2))
        c.lbl(r, "Popular sites come from").pack(side="left")
        self.f_combo(r, "site_list", [("both", "Tranco, re-ranked by real Chrome browsing (recommended)"),
                                      ("tranco", "Tranco only")], 48).pack(side="left", padx=8)
        r = c.row()
        c.lbl(r, "Daily data cap").pack(side="left")
        self.f_spin(r, "data_cap", 0, 100000, 10, 8, float).pack(side="left", padx=6)
        c.lbl(r, "MB  (0 = no cap, recommended unless your data is metered)", True).pack(side="left")
        c.heading("Your own activity", "reads only your computer's total traffic counters, never what is in it")
        self.f_radios(c, "activity", [("off", "Ignore it (default)"),
                                      ("backoff", "Pause while I'm busy", "Stop noise while you use more than the speed below, "
                                                                          "so it never slows you down."),
                                      ("follow", "Mostly when I'm active", "Not recommended: after 10 idle minutes most noise waits "
                                                                           "until you are back, which also shows when "
                                                                           "you are at the computer and when you are not.")])
        r = c.row()
        c.lbl(r, "Busy means more than").pack(side="left")
        self.f_spin(r, "busy_kbps", 10, 100000, 50, 8).pack(side="left", padx=6)
        c.lbl(r, "kbit/s  (400 recommended)", True).pack(side="left")
        self.f_check(c, "metrics", "Publish numbers for a monitoring dashboard",
                     "Off by default; most people never need this. For people who already run a tool such as "
                     "Prometheus or Grafana: adds a page at /metrics?t=<your dashboard token> in the web dashboard "
                     "with counts like hits and failures. Nothing leaves this computer.")
        c.heading("Search engines", "always adds up to 100%; every engine also has a hard limit of 20 searches an hour")
        self.se_mix = MixBar(c.body, self.app, [], self.app.edited)
        self.se_mix.pack(fill="x")
        self.se_touched = False
        self.se_mix_user = self.se_mix.on_change
        self.se_mix.on_change = self._se_touched
        r = c.row((6, 0))
        self.app.btn(r, "Back to defaults", None, "secondary", self.se_defaults).pack(side="left")
        c.lbl(r, "  Defaults recommended: mostly Google and DuckDuckGo, like real people.", True).pack(side="left")

    def _se_touched(self) -> None:
        self.se_touched = True
        self.app.edited()

    def _get_search(self) -> dict:
        return self.se_mix.values() if self.se_touched else {}

    def _set_search(self, custom) -> None:
        from .controller import ENGINE_NAMES, SEARCH_WEIGHTS
        defaults = dict(zip(ENGINE_NAMES, SEARCH_WEIGHTS))
        self.se_touched = bool(custom)
        names = list(ENGINE_NAMES)
        items = [{"key": n, "label": n, "value": (custom.get(n, 0) if custom else defaults.get(n, 0))} for n in names]
        if [i["key"] for i in self.se_mix.items] != names:
            self.se_mix.set_items(items)
        else:
            self.se_mix.set_values({i["key"]: i["value"] for i in items})

    def se_defaults(self) -> None:
        self._set_search({})
        self.app.edited()

    # ── persona, interests, household ──────────────────────────────────────
    def build_persona(self) -> None:
        c = self.card("persona", "Persona, interests and household", "list")
        c.heading("Persona", "who the noise mostly looks like")
        r = c.row()
        c.lbl(r, "Persona").pack(side="left")
        self.pers_var = tk.StringVar()
        self.pers_box = ttk.Combobox(r, state="readonly", width=34, textvariable=self.pers_var, values=["Nobody in particular (neutral)"])
        self.pers_box.pack(side="left", padx=8)
        self.pers_box.bind("<<ComboboxSelected>>", lambda _e: (self._persona_changed(), self.app.edited()))
        c.lbl(r, "pick the one closest to you", True).pack(side="left")
        self._reg("persona", self._get_persona, self._set_persona)
        r = c.row()
        c.lbl(r, "How closely it is followed").pack(side="left")
        self.persona_pct = c.lbl(r, "", False)
        self.f_scale(r, "persona_share", 10, 95, 5, lambda v: self.persona_pct.configure(text=f"{int(v)}%")).pack(side="left", padx=8)
        self.persona_pct.pack(side="left")
        c.lbl(r, "  (90% recommended)", True).pack(side="left")
        self.pers_mix = c.note("", pady=(2, 2))
        r = c.row()
        c.lbl(r, "Package installs").pack(side="left")
        self.f_combo(r, "packages", [("auto", "Automatic: on for Default mix, Data scientist and Developer (recommended)"), ("on", "On"),
                                     ("off", "Off")], 54).pack(side="left", padx=8)
        c.note("Real pip install / download / uninstall of popular packages (and npm, if you have it), the way someone who "
               "codes talks to PyPI and npm. It happens in legalPrivacy's own separate environment, never in yours: only "
               "ready-built packages, nothing is ever run, and what is installed is removed again.")
        c.heading("Interests", "a person has a few steady interests, not random everything")
        self.f_check(c, "interests", "Follow a few themes at a time", "Off by default. A share of visits and searches stays on "
                                                                      "the active themes, which change every so often.")
        r = c.row()
        c.lbl(r, "Themes at once").pack(side="left")
        self.f_spin(r, "interest_active", 1, 12, 1, 4).pack(side="left", padx=6)
        c.lbl(r, "· change every").pack(side="left")
        self.f_spin(r, "interest_days", 1, 365, 1, 5).pack(side="left", padx=6)
        c.lbl(r, "days  (3 themes, every 10 days recommended)", True).pack(side="left")
        r = c.row()
        c.lbl(r, "Share that follows the themes").pack(side="left")
        self.interest_pct = c.lbl(r, "")
        self.f_scale(r, "interest_share", 0, 100, 10, lambda v: self.interest_pct.configure(text=f"{int(v)}%")).pack(side="left", padx=8)
        self.interest_pct.pack(side="left")
        c.lbl(r, "  (30% recommended)", True).pack(side="left")
        self.theme_frame = ttk.Frame(c.body, style="CardBody.TFrame")
        self.theme_frame.pack(fill="x", pady=(4, 0))
        self.theme_vars: dict = {}
        self.interest_now = c.note("", pady=(4, 0))
        c.heading("Household", "so the noise does not tell how many people live with you")
        r = c.row()
        self.f_check(c, "household", "Noise from a virtual household", "Off by default. Each person has their own phone or "
                                                                       "computer, browser and usual hours; you are one of "
                                                                       "them. Redrawn every 30-90 days.")
        r = c.row()
        c.lbl(r, "Household size").pack(side="left")
        self.f_combo(r, "household_size", [(n, str(n)) for n in (2, 3, 4, 5)], 4).pack(side="left", padx=8)
        c.lbl(r, "people", True).pack(side="left")
        self.household_now = c.note("", pady=(2, 0))

    def _get_persona(self) -> str:
        v = self.pers_var.get()
        return "" if v.startswith("Nobody") or not v else v.replace(" (default)", "")

    def _set_persona(self, x) -> None:
        self.pers_var.set(x if x else "Nobody in particular (neutral)")
        self._persona_changed()

    def _persona_changed(self) -> None:
        m = (self.interest.get("personas") or {}).get(self._get_persona())
        self.pers_mix.configure(text=("Mostly: " + " · ".join(f"{k} {round(v * 100)}%" for k, v in m.items()) +
                                      ". A persona takes the place of rotating Interests.") if m else "")

    def _get_themes(self) -> list:
        themes = list(self.theme_vars)
        on = [t for t, v in self.theme_vars.items() if v.get()]
        return [] if (not themes or len(on) == len(themes)) else on

    def _set_themes(self, allowed) -> None:
        for t, v in self.theme_vars.items():
            v.set(not allowed or t in allowed)
        self._pending_themes = list(allowed or [])

    # ── realism and sources ────────────────────────────────────────────────
    def build_realism(self) -> None:
        c = self.card("realism", "Realism and sources", "proof")
        r = c.row()
        c.lbl(r, "Browse with a real browser").pack(side="left")
        self.f_combo(r, "browser", [("auto", "Auto (recommended)"), ("on", "Always"), ("off", "Off: plain HTTP")], 22).pack(side="left", padx=8)
        self.browser_info = c.lbl(r, "", True)
        self.browser_info.pack(side="left")
        c.note("A real Chrome/Edge/Chromium scrolls, pauses to read, moves the mouse, clicks or taps search results and now "
               "and then downloads a file (discarded). Plain HTTP cannot do any of that and is easier to spot.")
        r = c.row()
        c.lbl(r, "Browser engine").pack(side="left")
        self.f_combo(r, "engine", [("mine", "Your own Firefox, with your add-ons (recommended)"),
                                   ("mix", "The app's own browsers, Chromium and Firefox mixed"),
                                   ("auto", "The app's own browser, the same kind as yours"),
                                   ("chromium", "The app's own Chromium only"), ("firefox", "The app's own Firefox only")],
                     44).pack(side="left", padx=8)
        c.note("Your own Firefox: the Firefox installed here, with the profile it opens by default, on a private copy "
               "(settings, add-ons and bookmarks; never logins, cookies or history). Fingerprint blockers and user-agent "
               "switchers keep working. With User agent set to Mix, the part that isn't your own user agent, and phone "
               "visits, run in the app's own browsers, which vary canvas, WebGL, audio, fonts and window size themselves. "
               "Windows are never maximised.")
        r = c.row()
        c.lbl(r, "Browser window").pack(side="left")
        self.f_combo(r, "window", L.WINDOW_CHOICES, 34).pack(side="left", padx=8)
        r = c.row()
        c.lbl(r, "Keep the noise browser's cookies").pack(side="left")
        self.cookie_value, self.cookie_unit = tk.StringVar(value="1"), tk.StringVar(value="hours")
        sp = ttk.Spinbox(r, from_=0, to=365, increment=1, width=6, textvariable=self.cookie_value, command=self.app.edited)
        sp.pack(side="left", padx=8)
        self.cookie_value.trace_add("write", self._var_changed)
        cb = ttk.Combobox(r, state="readonly", width=7, textvariable=self.cookie_unit, values=["hours", "days"])
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda _e: self.app.edited())
        c.lbl(r, "  then fresh cookies (0 = never keep any)", True).pack(side="left")
        self.f_check(c, "cookie_vary", "Vary it a little", "Recommended. Each jar lives 60-140% of that time, so wipes are not on a fixed beat.")
        c.note("Hidden runs the same Chrome code as a normal window, and what your ISP or DNS provider sees is identical. "
               "Off-screen uses a real window and real graphics where no screen shows it: a little more realistic to a site's "
               "own scripts, but uses more CPU and memory. Visible is for watching.")
        c.heading("Where searches come from", "mixed so no one list dominates")
        self.f_check(c, "q_live", "Live trends", "Google Trends, Wikipedia most-read, BBC headlines")
        self.f_check(c, "q_dataset", "Real past searches", "MS MARCO (Bing) and GooAQ (Google autocomplete), fresh random sample")
        self.f_check(c, "q_builtin", "Built-in topics", "Kept a small minority")
        self.f_check(c, "q_words", "Occasional dictionary word", "“define …”")
        self.ftree = ttk.Treeview(c.body, columns=("src", "items", "from", "upd", "status"), show="headings", height=4, selectmode="none")
        for col, t, w in (("src", "Source", 200), ("items", "Items", 70), ("from", "From", 150), ("upd", "Updated", 80), ("status", "Status", 220)):
            self.ftree.heading(col, text=t)
            self.ftree.column(col, width=w, stretch=col in ("from", "status"), anchor="e" if col == "items" else "w")
        self.ftree.pack(fill="x", pady=(8, 4))
        c.note("These lists ship with legalPrivacy, so it never has to contact Google Trends, Wikipedia, BBC, Hugging Face or "
               "Tranco on your behalf. Refreshing is optional; once every few months is plenty.")
        self.f_check(c, "auto_refresh_sources", "Refresh automatically when the lists are about 3 months old",
                     "Contacts those sites from your connection.")
        r = c.row((6, 0))
        self.app.btn(r, "Refresh sources now", "refresh", "secondary", self.refresh_feeds).pack(side="left")

    def refresh_feeds(self) -> None:
        if messagebox.askokcancel("Refresh sources", "Download fresh lists now from Google Trends, Wikipedia, BBC, Hugging "
                                  "Face and Tranco? This contacts those sites from your connection.", parent=self.app.root):
            self.app.work(self.app.ctl.refresh_feeds, done=lambda _r: self.app.flash("Refreshing sources in the background…"))

    # ── accounts ───────────────────────────────────────────────────────────
    def build_accounts(self) -> None:
        c = self.card("accounts", "Accounts (optional, off by default)", "proof",
                      help="Lets the noise browser browse while signed in to your own Google and Microsoft accounts, so the "
                           "noise looks like a logged-in person. You sign in yourself, in a normal browser window; "
                           "legalPrivacy never sees, stores or types your password or a code. Signed-in visits only load and "
                           "scroll a few pages; they never click, send, delete or change anything, and never go through Tor. "
                           "Panic (medium and hard) deletes these sessions. A robot-check page or “too many requests” pauses "
                           "that account for a random while.")
        Banner(c.body, "Please read: these are your real accounts. The searches and visits become part of that account's "
                       "history and affect its ads and recommendations. Google or Microsoft may ask you to verify, or "
                       "restrict, an account that looks automated. A spare account is safer.", "warn", host=c.body).pack(fill="x", pady=(0, 8))
        self.no_display = c.note("This computer has no display, so a sign-in window cannot open here. Sign in from a computer with a screen.")
        self.no_display.pack_forget()
        for pid, name, what in ACCOUNTS:
            box = ttk.Frame(c.body, style="Card.TFrame", padding=12)
            box.pack(fill="x", pady=4)
            head = ttk.Frame(box, style="CardBody.TFrame")
            head.pack(fill="x")
            ttk.Label(head, text=name, style="Card.TLabel", font=self.app.fonts["bold"]).pack(side="left")
            st = pill(head, "…", "off")
            st.pack(side="left", padx=10)
            ttk.Label(head, text=what, style="CardMuted.TLabel").pack(side="left")
            msg = ttk.Label(box, text="", style="CardMuted.TLabel")
            msg.pack(anchor="w", pady=(4, 0))
            r = ttk.Frame(box, style="CardBody.TFrame")
            r.pack(fill="x", pady=6)
            b_in = self.app.btn(r, "Sign in", None, "secondary", lambda p=pid: self.acc_do("signin", p))
            b_rs = self.app.btn(r, "Resume now", None, "secondary", lambda p=pid: self.acc_do("resume", p))
            b_fg = self.app.btn(r, "Forget", None, "danger", lambda p=pid: self.acc_forget(p))
            b_in.pack(side="left", padx=(0, 6))
            en, hr, dy, ch = tk.BooleanVar(), tk.StringVar(value="3"), tk.StringVar(value="12"), tk.StringVar(value="pause")
            for v in (en, hr, dy, ch):
                v.trace_add("write", self._var_changed)
            cb = ttk.Checkbutton(box, text="Use this account (works only while it is signed in and the noise is running)", variable=en, style="Card.TCheckbutton")
            cb.pack(anchor="w")
            r2 = ttk.Frame(box, style="CardBody.TFrame")
            r2.pack(fill="x", pady=(4, 0))
            ttk.Label(r2, text="Signed-in visits at most", style="Card.TLabel").pack(side="left")
            ttk.Spinbox(r2, from_=1, to=10, width=4, textvariable=hr, command=self.app.edited).pack(side="left", padx=4)
            ttk.Label(r2, text="an hour and", style="Card.TLabel").pack(side="left")
            ttk.Spinbox(r2, from_=1, to=100, width=4, textvariable=dy, command=self.app.edited).pack(side="left", padx=4)
            ttk.Label(r2, text="a day", style="Card.TLabel").pack(side="left")
            r3 = ttk.Frame(box, style="CardBody.TFrame")
            r3.pack(fill="x", pady=(4, 0))
            ttk.Label(r3, text="After a robot check or “too many requests” page", style="Card.TLabel").pack(side="left")
            self.f_acc_combo(r3, ch)
            self.acc_ui[pid] = {"pill": st, "msg": msg, "in": b_in, "rs": b_rs, "fg": b_fg, "en": en, "hr": hr, "dy": dy, "ch": ch,
                                "cb": cb, "label": name}

    def f_acc_combo(self, parent, var) -> None:
        opts = {"pause": "Pause for a random while (recommended)", "continue": "Keep going (not recommended)"}
        cb = ttk.Combobox(parent, state="readonly", width=36, values=list(opts.values()))
        cb.pack(side="left", padx=8)
        cb.set(opts[var.get()])
        cb.bind("<<ComboboxSelected>>", lambda _e: (var.set("continue" if cb.get().startswith("Keep") else "pause"), self.app.edited()))
        var.trace_add("write", lambda *_a: cb.set(opts.get(var.get(), opts["pause"])))

    def _get_accounts(self) -> dict:
        out = {}
        for pid, u in self.acc_ui.items():
            out[pid] = {"enabled": bool(u["en"].get()), "per_hour": min(10, max(1, int(float(u["hr"].get() or 3)))),
                        "per_day": min(100, max(1, int(float(u["dy"].get() or 12)))), "on_challenge": u["ch"].get()}
        return out

    def _set_accounts(self, d) -> None:
        for pid, u in self.acc_ui.items():
            a = (d or {}).get(pid) or {}
            u["en"].set(bool(a.get("enabled")))
            u["hr"].set(str(a.get("per_hour", 3)))
            u["dy"].set(str(a.get("per_day", 12)))
            u["ch"].set(a.get("on_challenge", "pause"))

    def acc_do(self, action: str, pid: str) -> None:
        if action == "signin":
            self.app.flash("A sign-in window is opening on this computer…")
        self.app.work(lambda: self.app.ctl.accounts_action(action, pid), done=lambda _r: self.app.poll_now(),
                      error=lambda e: self.app.error("Accounts", e))

    def acc_forget(self, pid: str) -> None:
        if messagebox.askokcancel("Forget account", "Delete the saved session for this account? You would have to sign in "
                                  "again. Nothing in the account itself changes.", parent=self.app.root):
            self.acc_do("forget", pid)

    # ── general ────────────────────────────────────────────────────────────
    def build_general(self) -> None:
        c = self.card("general", "General", "set")
        r = c.row()
        c.lbl(r, "Clearnet proxy").pack(side="left")
        self.f_entry(r, "proxy", 40, "optional: http:// or socks5://…").pack(side="left", padx=8)
        self.f_check(c, "clearnet_enabled", "Clearnet noise enabled")
        self.f_check(c, "autostart", "Start the noise by itself when this app opens")
        self.f_check(c, "clear_logs_on_restart", "Each time noise starts, clear old Live Log and Activity entries",
                     "Recommended. They are kept in memory only and always cleared when legalPrivacy quits.")
        r = c.row()
        c.lbl(r, "Clear entries older than").pack(side="left")
        self.f_spin(r, "log_keep_days", 0, 365, 1, 5).pack(side="left", padx=8)
        c.lbl(r, "days  (0 = clear everything)", True).pack(side="left")
        c.heading("Testing only", "leave this at 1 for real use")
        r = c.row()
        c.lbl(r, "Time compression").pack(side="left")
        self.f_spin(r, "speed", 0.01, 20, 0.5, 7, float).pack(side="left", padx=8)
        c.lbl(r, "×  makes every wait this many times shorter, to watch a day's behaviour quickly. It does not "
                 "change how much noise an hour: the level does.", True).pack(side="left")
        self.f_check(c, "observe", "Watch this computer's connection counts for the Proof tab",
                     "Local only; never leaves this computer.")
        self.path_note = c.note("", pady=(6, 0))

    # ── logo ───────────────────────────────────────────────────────────────
    def build_logo(self) -> None:
        from .gui import TRAD_LOGOS, load_prefs
        c = self.card("logo", "Logo", "set")
        p = load_prefs()
        labels = {k: lab for k, lab, _f in TRAD_LOGOS}
        r = c.row()
        c.lbl(r, "Header logo").pack(side="left")
        self.logo_pick = tk.StringVar(value=labels.get(p.get("logo", ""), labels[""]))
        self.logo_follow = tk.BooleanVar(value=bool(p.get("logo_follow")))
        box = ttk.Combobox(r, textvariable=self.logo_pick, values=[lab for _k, lab, _f in TRAD_LOGOS], state="readonly", width=30)
        box.pack(side="left", padx=8)

        def apply(_e=None) -> None:
            key = next((k for k, lab, _f in TRAD_LOGOS if lab == self.logo_pick.get()), "")
            self.app.set_logo(key, self.logo_follow.get())
        box.bind("<<ComboboxSelected>>", apply)
        ttk.Checkbutton(c.body, text="Change the logo as I change tabs", variable=self.logo_follow, command=apply).pack(
            anchor="w", pady=(4, 0))

    # ── panic ──────────────────────────────────────────────────────────────
    def build_panic(self) -> None:
        c = self.card("panic", "Panic", "bolt", help="Stops the noise right away. Medium also clears the log and the noise "
                                                     "browser's cookies, and deletes any signed-in account sessions. Hard also "
                                                     "stops Tor and deletes what legalPrivacy recorded about connections and "
                                                     "its log files. Your settings are never deleted.")
        c.note("Stop now, and optionally leave nothing behind. Your settings are never deleted.")
        r = c.row()
        for lvl, label, tip_ in (("soft", "Panic: stop", "Stops the noise."),
                                 ("medium", "Panic: stop + clear", "Also clears the log and the noise browser's cookies."),
                                 ("hard", "Panic: stop + erase everything", "Also stops Tor and deletes Proof data and log files.")):
            col = ttk.Frame(r, style="CardBody.TFrame")
            col.pack(side="left", padx=(0, 22), anchor="n")
            self.app.btn(col, label, "bolt", "danger", lambda lv=lvl: self.panic(lv), tip_).pack(anchor="w")
            ttk.Label(col, text=tip_, style="CardMuted.TLabel", wraplength=220, justify="left").pack(anchor="w", pady=(2, 0))

    def panic(self, level: str) -> None:
        what = {"soft": "Stop the noise now?",
                "medium": "Stop the noise, clear the live log and delete the noise browser's cookies and any signed-in "
                          "account sessions?",
                "hard": "Stop the noise and Tor, and delete everything legalPrivacy recorded (Proof data, cookies, logs)? "
                        "Your settings stay."}[level]
        if not messagebox.askokcancel("Panic", what, icon="warning", default="cancel", parent=self.app.root):
            return
        self.app.work(lambda: self.app.ctl.panic(level),
                      done=lambda r: (self.app.poll_now(), messagebox.showinfo(
                          "Panic done", "\n".join("• " + d for d in r["done"]), parent=self.app.root)),
                      error=lambda e: self.app.error("Panic", e))

    # ── load and values ────────────────────────────────────────────────────
    def load(self, v: dict) -> None:
        super().load(v)
        self._tor_on = bool(v.get("tor_enabled"))
        self.path_note.configure(text=f"Config file: {self.app.ctl.profile_path}. No log file is kept; this is the only file legalPrivacy writes.")

    def fetch_static(self) -> None:
        """Library and interests lists are read once, off the main thread."""
        ctl = self.app.ctl
        self.app.work(ctl.interests_state, self._got_interests)
        self.app.work(ctl.ua_state, self._got_ua)

    def _got_interests(self, d: dict) -> None:
        self.interest = d
        keep = self._get_persona() or self.app.ctl.profile.extras.persona
        self.pers_box.configure(values=["Nobody in particular (neutral)"] + [n + (" (default)" if n == "Default mix" else "") for n in d["personas"]])
        self._set_persona(keep)
        allowed = list(self.app.ctl.profile.extras.interest_list)
        for w in self.theme_frame.winfo_children():
            w.destroy()
        self.theme_vars = {}
        ttk.Label(self.theme_frame, text="Allowed themes (only used when Persona is Nobody in particular; "
                  "My own corners = sites from your own life)", style="CardMuted.TLabel").grid(row=0, column=0, sticky="w", columnspan=4)
        for i, t in enumerate(d["themes"]):
            var = tk.BooleanVar(value=(not allowed or t in allowed))
            var.trace_add("write", self._var_changed)
            self.theme_vars[t] = var
            ttk.Checkbutton(self.theme_frame, text=t, variable=var, style="Card.TCheckbutton").grid(row=1 + i // 4, column=i % 4, sticky="w", padx=(0, 14))
        self.interest_now.configure(text=("Active right now: " + ", ".join(d["active"])) if d.get("active") and not d.get("persona") else "")
        self.household_now.configure(text=("Your household right now: " + " · ".join(d["household"])) if d.get("household") else "")

    def _got_ua(self, d: dict) -> None:
        self.ua_lib = d.get("library") or []
        self.ua_box.configure(values=[self._ua_label(e) for e in self.ua_lib])
        self.ua_count.configure(text=f"{len(self.ua_lib)} entries in the library. Shares are how often each is picked when random "
                                     "(modelled from release age, not measured).")
        self.ua_applies.configure(text=d.get("applies_to", ""))
        self._set_ua_pin(self.app.ctl.profile.identity.ua_pin)

    def update_state(self, st: dict) -> None:
        dns = st.get("dns") or {}
        self.dns_report = dns
        self.render_res()
        self.b_check.configure(text="Checking…" if dns.get("checking") else "Check now")
        self.b_check.state(["disabled"] if dns.get("checking") else ["!disabled"])
        sy = dns.get("system") or []
        self.sys_note.configure(text=("Your normal DNS right now: " + ", ".join(x["ip"] + (f" ({x['what']})" if x.get("what") else "") for x in sy))
                                if sy else "Your normal DNS: press “Check now” to see which servers this computer uses.")
        if dns.get("intercepted"):
            self.warn.configure(text="Your network appears to intercept DNS. Every resolver was really answered by the same "
                                     "machine, so lookups do not reach the servers listed. A VPN usually fixes this; until "
                                     "then “Your normal DNS” is the honest choice.")
            self.warn.pack(fill="x", pady=(0, 6), after=self.sys_note)
        else:
            self.warn.pack_forget()
        op = st.get("opennic") or []
        self.opennic_note.configure(text=f"{len(op)} servers in the current OpenNIC directory. Lookups to them are ordinary "
                                         "(unencrypted) DNS, like most lookups; the encryption requirement is a quality bar "
                                         "for the servers.")
        b = st.get("browser") or {}
        self.browser_info.configure(text=("✓ using " + str(b.get("detail", "")).replace("\\", "/").split("/")[-1]) if b.get("active")
                                    else "off" if b.get("setting") == "off" else "⚠ " + str(b.get("detail", "")))
        rows = [L.feed_row(f) for f in st.get("feeds") or []]
        sig = repr(rows)
        if getattr(self, "_feed_sig", None) != sig:
            self._feed_sig = sig
            self.ftree.delete(*self.ftree.get_children())
            for r in rows:
                self.ftree.insert("", "end", values=r)
            self.ftree.configure(height=max(2, len(rows)))
        acc = st.get("accounts") or {}
        self.no_display.pack_forget() if acc.get("display", True) else self.no_display.pack(fill="x", anchor="w", pady=(0, 6))
        for pid, u in self.acc_ui.items():
            a = (acc.get("accounts") or {}).get(pid)
            if not a:
                continue
            text, tone = F.account_status_text(a)
            set_pill(u["pill"], text, tone)
            u["msg"].configure(text=F.account_note(a))
            si = (a.get("signin") or {}).get("state")
            busy = si in ("starting", "waiting", "saving")
            u["in"].state(["disabled"] if busy or not acc.get("display", True) else ["!disabled"])
            u["in"].configure(text="Sign in" if a["state"] == "signed_out" else "Sign in again")
            u["fg"].state(["disabled"] if a["state"] == "signed_out" else ["!disabled"])
            u["rs"].state(["!disabled"] if a["state"] == "needs_attention" else ["disabled"])
            u["rs"].pack(side="left", padx=(0, 6)) if a["state"] == "needs_attention" else u["rs"].pack_forget()
            u["fg"].pack(side="left") if a["state"] != "signed_out" else u["fg"].pack_forget()
            u["cb"].state(["disabled"] if a["state"] in ("signed_out", "needs_signin") else ["!disabled"])

    def retheme(self) -> None:
        self.sf.retheme()
        self.se_mix.retheme()
