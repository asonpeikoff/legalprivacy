"""Native "Remote" tab: run the noise on other computers you own, over SSH. Same features as the web dashboard's Remote
tab: add (user@host[:port] with a password or a private key), test connection, trust a host key, start, stop, remove,
and a status line and log for every machine. Needs tkinter; the logic lives in remoterun.py."""
from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .gui_base import Tab
from .gui_more import add_card, page
from .gui_theme import Banner, pill, set_pill, tip
from .remoterun import STATE_LABELS, counts_text, facts_text

POLL_MS = 2500
INTENSITY_LABELS = [("light", "Light (about 10 actions an hour)"), ("normal", "Normal (about 30)"),
                    ("busy", "Busy (about 80)")]
BROWSER_LABELS = [("auto", "Headless browser if installed"), ("off", "Plain HTTP only")]


class RemoteTab(Tab):
    title, icon = "Remote", "tor"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        page(self, app)
        self._cards: dict[str, dict] = {}
        self._polling = False
        self._build_add(app)
        self.list_card = add_card(self, app, "Your remote machines", "tor")
        self.empty = self.list_card.note("No remote machines yet. Add one above.")
        self.missing = None

    # ── the "add" card ──────────────────────────────────────────────────────
    def _build_add(self, app) -> None:
        c = add_card(self, app, "Remote machines", "tor",
                     help="Runs the same kind of noise (page visits, searches, DNS lookups, downloads) on other computers "
                          "you log in to over SSH. The app copies one small file into a private folder in your account on "
                          "that computer (~/.cache/legalprivacy), starts it, shows its log here, and deletes the folder "
                          "when you remove the machine. No root, no service, no display needed: a headless Linux server "
                          "works (a headless browser is used if one is installed, otherwise plain HTTP). Each machine "
                          "draws its own random identities, rhythm, daily peak, budgets and sites. It stops when this "
                          "app closes or the connection drops. The machine needs Python 3.")
        Banner(c.body, "Only add computers you own or are authorised to use. This app logs in to them and makes web, "
                       "search, DNS and download traffic from them.", "warn", host=c.body).pack(fill="x", pady=(0, 6))
        self.miss_host = c.body
        self.secret_note = c.note("", pady=(0, 6))
        self.v_target, self.v_label = tk.StringVar(), tk.StringVar()
        r = c.row()
        c.lbl(r, "Connection").pack(side="left")
        e = ttk.Entry(r, textvariable=self.v_target, width=32)
        e.pack(side="left", padx=(6, 12))
        tip(e, "user@host or user@host:port  (an IPv6 address goes in brackets: user@[::1]:22)")
        c.lbl(r, "Name (optional)").pack(side="left")
        ttk.Entry(r, textvariable=self.v_label, width=22).pack(side="left", padx=(6, 0))
        self.v_auth = tk.StringVar(value="password")
        r = c.row()
        for val, txt in (("key", "Private key (preferred)"), ("password", "Password")):
            ttk.Radiobutton(r, text=txt, value=val, variable=self.v_auth, style="Card.TRadiobutton",
                            command=self._auth_changed).pack(side="left", padx=(0, 14))
        self.v_pass, self.v_key, self.v_phrase = tk.StringVar(), tk.StringVar(), tk.StringVar()
        holder = c.row()
        self.r_pass = ttk.Frame(holder, style="CardBody.TFrame")
        self.r_key = ttk.Frame(holder, style="CardBody.TFrame")
        c.lbl(self.r_pass, "Password").pack(side="left")
        ttk.Entry(self.r_pass, textvariable=self.v_pass, show="•", width=30).pack(side="left", padx=(6, 0))
        c.lbl(self.r_key, "Private key file").pack(side="left")
        ttk.Entry(self.r_key, textvariable=self.v_key, width=34).pack(side="left", padx=(6, 6))
        app.btn(self.r_key, "Browse…", None, "secondary", self._browse_key).pack(side="left", padx=(0, 10))
        c.lbl(self.r_key, "Passphrase (if any)").pack(side="left")
        ttk.Entry(self.r_key, textvariable=self.v_phrase, show="•", width=18).pack(side="left", padx=(6, 0))
        c.heading("What this machine does")
        self.v_int, self.v_browser = tk.StringVar(value="normal"), tk.StringVar(value="auto")
        self.v_mb = tk.StringVar(value="200")
        r = c.row()
        c.lbl(r, "Intensity").pack(side="left")
        self.cb_int = ttk.Combobox(r, state="readonly", width=30, values=[t for _v, t in INTENSITY_LABELS])
        self.cb_int.set(dict(INTENSITY_LABELS)["normal"])
        self.cb_int.pack(side="left", padx=(6, 12))
        c.lbl(r, "Browser").pack(side="left")
        self.cb_browser = ttk.Combobox(r, state="readonly", width=28, values=[t for _v, t in BROWSER_LABELS])
        self.cb_browser.set(dict(BROWSER_LABELS)["auto"])
        self.cb_browser.pack(side="left", padx=(6, 12))
        c.lbl(r, "Daily data limit (MB)").pack(side="left")
        ttk.Spinbox(r, from_=1, to=2000, width=6, textvariable=self.v_mb).pack(side="left", padx=(6, 0))
        self.lanes = {k: tk.BooleanVar(value=True) for k in ("visits", "searches", "dns", "downloads")}
        r = c.row()
        for k, txt in (("visits", "Page visits"), ("searches", "Searches"), ("dns", "DNS lookups"),
                       ("downloads", "Downloads (read and thrown away, never saved)")):
            ttk.Checkbutton(r, text=txt, variable=self.lanes[k], style="Card.TCheckbutton").pack(side="left", padx=(0, 14))
        self.v_dry = tk.BooleanVar(value=False)
        c.check(self.v_dry, "Dry run", "Makes no network traffic at all; it only checks that the machine can run the noise.")
        c.note("Extra download addresses (optional, one https:// address per line; links found on visited pages are used too):",
               pady=(4, 2))
        self.t_urls = tk.Text(c.body, height=2, wrap="none", relief="flat", borderwidth=0, highlightthickness=1,
                              font=app.fonts["mono"], padx=6, pady=4)
        self.t_urls.pack(fill="x")
        app.text_widgets.append(self.t_urls)
        self.v_own = tk.BooleanVar(value=False)
        c.check(self.v_own, "This computer is mine, or I am authorised to use it.")
        r = c.row((8, 2))
        app.btn(r, "Add machine", "play", "primary", self.add).pack(side="left")
        self._auth_changed()

    def _auth_changed(self) -> None:
        key = self.v_auth.get() == "key"
        self.r_key.pack_forget()
        self.r_pass.pack_forget()
        (self.r_key if key else self.r_pass).pack(fill="x")

    def _browse_key(self) -> None:
        p = filedialog.askopenfilename(title="Private key file", parent=self.app.root)
        if p:
            self.v_key.set(p)

    def _settings(self) -> dict:
        by_label = {t: v for v, t in INTENSITY_LABELS}
        by_browser = {t: v for v, t in BROWSER_LABELS}
        try:
            mb = int(float(self.v_mb.get()))
        except ValueError:
            mb = 200
        return {"intensity": by_label.get(self.cb_int.get(), "normal"), "browser": by_browser.get(self.cb_browser.get(), "auto"),
                "max_mb_per_day": mb, **{k: v.get() for k, v in self.lanes.items()}, "dry_run": bool(self.v_dry.get()),
                "download_urls": [u.strip() for u in self.t_urls.get("1.0", "end-1c").splitlines() if u.strip()]}

    def add(self) -> None:
        body = {"target": self.v_target.get(), "label": self.v_label.get(), "auth": self.v_auth.get(),
                "password": self.v_pass.get(), "key_path": self.v_key.get(), "passphrase": self.v_phrase.get(),
                "authorised": bool(self.v_own.get()), "settings": self._settings()}

        def done(_r):
            self.v_pass.set("")
            self.v_phrase.set("")
            self.v_target.set("")
            self.v_label.set("")
            self.app.flash("Machine added. Press Test connection.")
            self.refresh()
        self.app.work(lambda: self.app.ctl.remote_add(body), done, lambda e: self.app.error("Remote machines", e))

    # ── polling ─────────────────────────────────────────────────────────────
    def on_show(self) -> None:
        if not self._polling:
            self._polling = True
            self._tick()

    def _tick(self) -> None:
        if getattr(self.app, "closing", False) or not self.winfo_exists():
            self._polling = False
            return
        if self.winfo_ismapped():
            self.refresh()
        self.after(POLL_MS, self._tick)

    def refresh(self) -> None:
        self.app.work(self.app.ctl.remote_state, self._render, lambda _e: None)

    def _render(self, st: dict) -> None:
        self.secret_note.configure(text=st["secret_note"])
        if not st["available"] and self.missing is None:
            self.missing = Banner(self.miss_host, "Remote machines need the 'paramiko' package, which is not installed. "
                                  "Install it with:  pip install \"paramiko>=3.4\"  (or  pip install legalprivacy[remote]) "
                                  "and restart the app.", "bad", host=self.miss_host)
            self.missing.pack(fill="x", pady=(0, 6), after=self.secret_note)
        elif st["available"] and self.missing is not None:
            self.missing.destroy()
            self.missing = None
        ids = {m["id"] for m in st["machines"]}
        for mid in [i for i in self._cards if i not in ids]:
            self._cards.pop(mid)["frame"].destroy()
        if st["machines"]:
            self.empty.pack_forget()
        else:
            self.empty.pack(fill="x", anchor="w")
        for m in st["machines"]:
            w = self._cards.get(m["id"]) or self._make_card(m)
            self._fill(w, m)

    # ── one machine ─────────────────────────────────────────────────────────
    def _make_card(self, m: dict) -> dict:
        app, body = self.app, self.list_card.body
        fr = ttk.Frame(body, style="CardBody.TFrame", padding=(0, 8))
        fr.pack(fill="x", pady=(6, 0))
        w: dict = {"frame": fr, "id": m["id"]}
        top = ttk.Frame(fr, style="CardBody.TFrame")
        top.pack(fill="x")
        w["title"] = ttk.Label(top, text="", style="Card.TLabel", font=app.fonts["bold"])
        w["title"].pack(side="left")
        w["pill"] = pill(top, "", "off")
        w["pill"].pack(side="left", padx=(10, 0))
        w["b_remove"] = app.btn(top, "Remove", None, "secondary", lambda i=m["id"]: self.remove(i))
        w["b_stop"] = app.btn(top, "Stop", "stop", "secondary", lambda i=m["id"]: self.act("stop", i))
        w["b_start"] = app.btn(top, "Start", "play", "primary", lambda i=m["id"]: self.act("start", i))
        w["b_test"] = app.btn(top, "Test connection", None, "secondary", lambda i=m["id"]: self.test(i))
        for b in (w["b_remove"], w["b_stop"], w["b_start"], w["b_test"]):
            b.pack(side="right", padx=(6, 0))
        w["facts"] = ttk.Label(fr, text="", style="CardMuted.TLabel", justify="left")
        w["facts"].pack(fill="x", anchor="w")
        w["err"] = ttk.Label(fr, text="", style="Card.TLabel", justify="left")
        w["err"].pack(fill="x", anchor="w")
        w["trust"] = ttk.Frame(fr, style="CardBody.TFrame")
        w["trust_lbl"] = Banner(w["trust"], "", "warn", host=fr)
        w["trust_lbl"].pack(fill="x")
        w["b_trust"] = app.btn(w["trust"], "Trust this fingerprint", "play", "primary", lambda i=m["id"]: self.trust(i))
        w["b_trust"].pack(anchor="w", pady=(4, 0))
        w["secrets"] = ttk.Frame(fr, style="CardBody.TFrame")
        ttk.Label(w["secrets"], text="Password (kept in memory only)", style="CardMuted.TLabel").pack(side="left")
        w["pw"] = tk.StringVar()
        ttk.Entry(w["secrets"], textvariable=w["pw"], show="•", width=22).pack(side="left", padx=(6, 10))
        ttk.Label(w["secrets"], text="Key passphrase", style="CardMuted.TLabel").pack(side="left")
        w["ph"] = tk.StringVar()
        ttk.Entry(w["secrets"], textvariable=w["ph"], show="•", width=18).pack(side="left", padx=(6, 0))
        w["counts"] = ttk.Label(fr, text="", style="CardMuted.TLabel")
        w["counts"].pack(fill="x", anchor="w")
        w["log"] = tk.Text(fr, height=7, wrap="none", state="disabled", relief="flat", borderwidth=0, highlightthickness=1,
                           font=app.fonts["mono"], padx=8, pady=6)
        w["log"].pack(fill="x", pady=(4, 0))
        app.text_widgets.append(w["log"])
        w["b_forget"] = app.btn(fr, "Forget host key", None, "secondary", lambda i=m["id"]: self.act("forget_key", i))
        w["b_forget"].pack(anchor="w", pady=(6, 0))
        ttk.Separator(fr, orient="horizontal").pack(fill="x", pady=(8, 0))
        self._cards[m["id"]] = w
        return w

    def _fill(self, w: dict, m: dict) -> None:
        label, tone = STATE_LABELS.get(m["state"], (m["state"], "off"))
        w["title"].configure(text=(f"{m['label']} · " if m["label"] and m["label"] != m["target"] else "") + m["target"])
        set_pill(w["pill"], label, tone)
        w["facts"].configure(text=facts_text(m))
        w["err"].configure(text=m["error"] or "")
        busy = m["state"] in ("starting", "running", "stopping", "testing")
        w["b_start"].state(["disabled"] if busy else ["!disabled"])
        w["b_test"].state(["disabled"] if busy else ["!disabled"])
        w["b_stop"].state(["!disabled"] if m["state"] in ("starting", "running") else ["disabled"])
        w["b_remove"].state(["disabled"] if m["state"] == "stopping" else ["!disabled"])
        w["b_forget"].state(["disabled"] if (busy or not m["host_key"]) else ["!disabled"])
        pk = m["pending_key"]
        if pk:
            w["trust_lbl"].configure(text=(
                f"First time seeing this machine. Check that its host key fingerprint is exactly {pk['fingerprint']} "
                f"({pk['type']}). On the machine: {pk['check']} . "
                "Nothing, not even your password, has been sent yet."))
            w["pending"] = pk["fingerprint"]
            if not w["trust"].winfo_ismapped():
                w["trust"].pack(fill="x", pady=(4, 0), after=w["err"])
        else:
            w["trust"].pack_forget()
            w["pending"] = None
        if m["has_secret"] or busy:
            w["secrets"].pack_forget()
        elif not w["secrets"].winfo_ismapped():
            w["secrets"].pack(fill="x", pady=(4, 0), after=w["err"])
        w["counts"].configure(text=counts_text(m))
        lg = w["log"]
        text = "\n".join(m["log"]) or "Nothing yet. The runner's log appears here."
        if text != w.get("_text"):
            w["_text"] = text
            stick = lg.yview()[1] >= 0.99
            lg.configure(state="normal")
            lg.delete("1.0", "end")
            lg.insert("1.0", text)
            lg.configure(state="disabled")
            if stick:
                lg.see("end")

    # ── actions (each runs off the UI thread) ───────────────────────────────
    def _secrets(self, mid: str) -> dict:
        w = self._cards.get(mid) or {}
        out = {}
        if w.get("pw") is not None and w["pw"].get():
            out["password"] = w["pw"].get()
        if w.get("ph") is not None and w["ph"].get():
            out["passphrase"] = w["ph"].get()
        return out

    def _after(self, _r=None) -> None:
        self.refresh()

    def act(self, what: str, mid: str) -> None:
        body = {"id": mid, **self._secrets(mid)}
        fn = getattr(self.app.ctl, "remote_" + what)
        self.app.work(lambda: fn(body), self._after, lambda e: (self.app.error("Remote machines", e), self.refresh()))

    def test(self, mid: str) -> None:
        body = {"id": mid, **self._secrets(mid)}

        def done(r):
            self.app.flash(r["message"])
            self.refresh()
        self.app.work(lambda: self.app.ctl.remote_test(body), done, lambda e: (self.app.error("Remote machines", e), self.refresh()))

    def trust(self, mid: str) -> None:
        fp = (self._cards.get(mid) or {}).get("pending")
        if not fp:
            return
        self.app.work(lambda: self.app.ctl.remote_trust({"id": mid, "fingerprint": fp}),
                      lambda _r: (self.app.flash("Trusted. Press Test connection or Start."), self.refresh()),
                      lambda e: self.app.error("Remote machines", e))

    def remove(self, mid: str) -> None:
        if not messagebox.askyesno("Remove machine", "Remove this machine? The runner is stopped and its folder on the "
                                   "machine is deleted (this needs the password or key to be available).",
                                   parent=self.app.root):
            return
        body = {"id": mid, "wipe": True, **self._secrets(mid)}

        def done(r):
            self.app.flash(r.get("note") or "Removed.")
            self.refresh()
        self.app.work(lambda: self.app.ctl.remote_remove(body), done, lambda e: self.app.error("Remote machines", e))
