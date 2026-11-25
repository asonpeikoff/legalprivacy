"""Security tab of the native app: the optional, offline-first ClamAV manager (see av.py)."""
from __future__ import annotations

import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import av as A
from .gui_base import Tab
from .gui_more import add_card, page
from .gui_theme import autowrap, pill, set_pill

UPDATE_CONFIRM = ("Update signatures now?\n\nThis is the ONLY thing in this feature that connects to the internet. It will:\n\n"
                  "  1. look up a DNS TXT record at current.cvd.clamav.net, then\n"
                  "  2. download signature files over HTTPS from database.clamav.net.\n\n"
                  "It runs ClamAV's own freshclam once, with a minimal generated config, into this app's own signature "
                  "folder. Nothing else is contacted, and it never runs by itself.")
QUARANTINE_CONFIRM = ("Move this file into legalPrivacy's quarantine folder?\n\n{path}\n\nIt is removed from where it is now "
                      "and kept there, unreadable as a program, until you restore or delete it. You can restore it from the "
                      "Quarantine list at any time.")


def _ago(days) -> str:
    if days is None:
        return ""
    return "today" if days < 1 else f"{days:.0f} days old"


def verdict_of(last: dict | None) -> tuple[str, str]:
    """(text, tone) for the 'did the scanner stay offline' pill."""
    if not last or last.get("connections") is None:
        return "No scan yet", "off"
    n = last.get("connections", 0)
    if n:
        return f"NOT OFFLINE: scanner connections: {n}", "bad"
    how = "network removed" if last.get("isolated") else "connections watched"
    return f"Stayed offline: scanner connections: 0 ({how})", "ok"


class SecurityTab(Tab):
    title, icon = "Antivirus", "scan"

    def __init__(self, nb, app):
        super().__init__(nb, app)
        page(self, app)
        self.st: dict = {}
        self._sigs: dict = {}
        self._poll_job = None
        self.paths: list[str] = []
        self.verdict = tk.StringVar(value="No scan yet")
        self.status = tk.StringVar(value="")

        # 1. the programs
        c = add_card(self, app, "ClamAV on this computer", "scan",
                     "legalPrivacy never bundles ClamAV. It only runs the copy you installed.")
        self.tools_box = ttk.Frame(c.body, style="CardBody.TFrame")
        self.tools_box.pack(fill="x")
        self.install_lbl = c.note("", muted=False)
        self.notes_lbl = c.note("")
        r = c.row((6, 0))
        app.btn(r, "Detect again", "refresh", "secondary", lambda: self.refresh(True),
                "Look for clamscan, clamdscan, freshclam and sigtool again").pack(side="left")
        app.btn(r, "ClamAV documentation", "web", "secondary",
                lambda: self._open(A.DOCS_URL)).pack(side="left", padx=(6, 0))

        # 2. offline, enforced and proven
        c = add_card(self, app, "Stays offline", "proof",
                     "What contacts the internet, how that is prevented, and how it is checked.")
        c.note("Only freshclam, ClamAV's signature updater, is documented as contacting the internet (a DNS TXT check at "
               "current.cvd.clamav.net, then an HTTPS download from database.clamav.net). It runs only when you press "
               "Update. Scans use clamscan with this app's own signature folder, never freshclam or the system's ClamAV "
               "settings.")
        r = c.row()
        self.iso_pill = pill(r, "Checking…", "off")
        self.iso_pill.pack(side="left", padx=(0, 10))
        self.iso_lbl = ttk.Label(r, text="", style="Card.TLabel", justify="left")
        self.iso_lbl.pack(side="left", fill="x", expand=True)
        autowrap(self.iso_lbl, c.body, 150)
        c.note("On every system the scanner and anything it starts are watched about every 100 ms for any connection "
               "that is not to this computer itself, or for a DNS lookup helper. If one appears, the scan is marked NOT "
               "OFFLINE and the scanner is stopped.")
        app.btn(c.row((4, 0)), "Check isolation again", "refresh", "secondary", self.reprobe,
                "Probe once more which network-removal method works here").pack(side="left")

        # 3. signatures
        c = add_card(self, app, "Signatures", "scan")
        self.db_note = c.note("")
        cols = ("name", "version", "sigs", "size", "age")
        self.db_tree = ttk.Treeview(c.body, columns=cols, show="headings", height=3, selectmode="none")
        for col, t, w in (("name", "File", 150), ("version", "Version", 80), ("sigs", "Signatures", 100),
                          ("size", "Size", 90), ("age", "Age", 100)):
            self.db_tree.heading(col, text=t)
            self.db_tree.column(col, width=w, anchor="w", stretch=col == "name")
        self.db_tree.pack(fill="x", pady=(4, 6))
        self.db_empty = c.note("No signature files yet. Import .cvd/.cld files you downloaded yourself, or use Update.")
        r = c.row((4, 0))
        self.b_update = app.btn(r, "Update signatures (contacts ClamAV's servers)", "refresh", "secondary", self.update,
                                "Runs freshclam once. Asks you to confirm first. The only time anything connects.")
        self.b_update.pack(side="left")
        self.b_import = app.btn(r, "Import signature files…", "plus", "secondary", self.import_files,
                                "Choose main/daily/bytecode .cvd or .cld files. Each is verified before it is used. "
                                "Nothing is contacted.")
        self.b_import.pack(side="left", padx=(6, 0))
        c.note("Import verifies each file (sigtool must report a valid digital signature, and clamscan must load it) before "
               "it is copied into the app's own folder; files that fail are rejected.", pady=(6, 0))
        self.upd_lbl = c.note("")

        # 4. scan
        c = add_card(self, app, "Scan", "scan")
        c.note("Choose folders or files. Nothing is ever deleted, moved or changed by a scan.")
        self.path_list = tk.Listbox(c.body, height=3, selectmode="extended", relief="flat", highlightthickness=1,
                                    font=app.fonts["base"], activestyle="none")
        app.field_texts.append(self.path_list)
        self.path_list.pack(fill="x", pady=(2, 4))
        r = c.row()
        app.btn(r, "Add folder…", "plus", "secondary", self.add_folder).pack(side="left")
        app.btn(r, "Add file…", "plus", "secondary", self.add_file).pack(side="left", padx=(6, 0))
        app.btn(r, "Remove selected", None, "ghost", self.remove_paths).pack(side="left", padx=(6, 0))
        r = c.row((8, 2))
        self.b_scan = app.btn(r, "Start scan", "play", "primary", self.scan)
        self.b_scan.pack(side="left")
        self.b_stop = app.btn(r, "Stop", "stop", "secondary", self.stop)
        self.b_stop.pack(side="left", padx=(6, 0))
        self.b_stop.state(["disabled"])
        self.progress = ttk.Progressbar(r, mode="indeterminate", length=140)
        self.progress.pack(side="left", padx=(12, 0))
        r = c.row((6, 2))
        self.verdict_pill = pill(r, "No scan yet", "off")
        self.verdict_pill.pack(side="left", padx=(0, 10))
        self.status_lbl = ttk.Label(r, textvariable=self.status, style="CardMuted.TLabel", justify="left")
        self.status_lbl.pack(side="left", fill="x", expand=True)
        autowrap(self.status_lbl, c.body, 220)
        self.results = ttk.Treeview(c.body, columns=("path", "sig", "size"), show="headings", height=5, selectmode="browse")
        for col, t, w in (("path", "Path", 380), ("sig", "Signature", 180), ("size", "Size", 80)):
            self.results.heading(col, text=t)
            self.results.column(col, width=w, anchor="e" if col == "size" else "w", stretch=col == "path")
        self.results.pack(fill="x", pady=(6, 4))
        self.res_empty = c.note("Nothing found yet. Infected files appear here after a scan.")
        r = c.row()
        self.b_copy = app.btn(r, "Copy path", None, "secondary", self.copy_path, "Copy the selected file's path")
        self.b_copy.pack(side="left")
        self.b_quar = app.btn(r, "Quarantine selected…", None, "secondary", self.quarantine,
                              "Move the selected file into this app's quarantine folder (asks first; reversible)")
        self.b_quar.pack(side="left", padx=(6, 0))

        # 5. self-test
        c = add_card(self, app, "Self-test (EICAR)", "check")
        c.note("Writes the standard, harmless EICAR antivirus test string to a temporary file, scans it with this app's "
               "signatures, shows whether it was detected, and deletes it. Your own antivirus may react to that file.")
        self.b_self = app.btn(c.row(), "Run the self-test", "play", "secondary", self.selftest)
        self.b_self.pack(side="left")
        self.self_lbl = c.note("", muted=False, pady=(6, 0))

        # 6. quarantine
        c = add_card(self, app, "Quarantine", "list")
        self.q_tree = ttk.Treeview(c.body, columns=("orig", "sig", "when"), show="headings", height=3, selectmode="browse")
        for col, t, w in (("orig", "Original place", 380), ("sig", "Signature", 160), ("when", "When", 130)):
            self.q_tree.heading(col, text=t)
            self.q_tree.column(col, width=w, anchor="w", stretch=col == "orig")
        self.q_tree.pack(fill="x", pady=(0, 4))
        self.q_empty = c.note("Nothing in quarantine.")
        r = c.row()
        app.btn(r, "Restore", None, "secondary", self.restore, "Put the selected file back where it came from").pack(side="left")
        app.btn(r, "Delete permanently…", None, "secondary", self.delete_q).pack(side="left", padx=(6, 0))

        # 7. log
        c = add_card(self, app, "Antivirus log", "log")
        self.log = tk.Text(c.body, height=8, wrap="word", state="disabled", relief="flat", highlightthickness=1,
                           font=app.fonts["mono"], padx=8, pady=6)
        self.log.pack(fill="x")
        app.text_widgets.append(self.log)
        self._log_seq = -1
        c.note("The scanner's results, and freshclam's output while an update runs. Panic (hard) deletes the quarantine "
               "and scan results; your own files and the signature files stay.", pady=(6, 0))

    # -- plumbing
    @staticmethod
    def _open(url: str) -> None:
        import webbrowser
        webbrowser.open(url)

    def on_show(self) -> None:
        self.refresh()

    def refresh(self, redetect: bool = False) -> None:
        self.app.work(lambda: self.app.ctl.av_state(redetect), self._got, lambda e: self.status.set(str(e)))

    def _act(self, action: str, body: dict | None = None) -> None:
        self.app.work(lambda: self.app.ctl.av_action(action, body or {}), self._got,
                      lambda e: self.app.error("Antivirus", e))

    def _later(self) -> None:
        if self._poll_job is not None:
            return
        self._poll_job = self.app.root.after(700, self._tick)

    def _tick(self) -> None:
        self._poll_job = None
        if not self.app.closing:
            self.refresh()

    # -- rendering
    def _got(self, st: dict) -> None:
        self.st = st
        busy = st.get("busy")
        self._render_tools(st)
        iso = st.get("isolation") or {}
        set_pill(self.iso_pill, "Network removed" if iso.get("isolated") else "Detection only",
                 "ok" if iso.get("isolated") else "warn")
        self.iso_lbl.configure(text=iso.get("label", ""))
        db = st.get("db") or {}
        self.db_note.configure(text="Signature folder (owned by this app; the system's ClamAV settings are never read or "
                                    f"changed): {db.get('dir', '')}")
        self.db_tree.delete(*self.db_tree.get_children())
        for f in db.get("files", []):
            self.db_tree.insert("", "end", values=(f["name"], f.get("version", ""), f.get("signatures", ""),
                                                   A.human_size(f["size"]), _ago(f["age_days"])))
        self._show(self.db_empty, not db.get("files"))
        self.b_update.state(["!disabled"] if st.get("can_update") and not busy else ["disabled"])
        self.b_import.state(["disabled"] if busy else ["!disabled"])
        self.b_self.state(["!disabled"] if st.get("can_scan") and not busy else ["disabled"])
        self.b_scan.state(["!disabled"] if st.get("can_scan") and not busy else ["disabled"])
        self.b_stop.state(["!disabled"] if busy in ("scan", "selftest", "update") else ["disabled"])
        up = st.get("update") or {}
        imp = st.get("import") or {}
        txt = ""
        if busy == "update":
            txt = "Updating… (freshclam is running; its output is in the log below)"
        elif busy == "import":
            txt = "Verifying the files…"
        elif imp.get("when") and (not up.get("when") or imp["when"] > up["when"]):
            txt = f"Imported: {', '.join(imp.get('imported') or []) or 'nothing'}." + "".join(
                f"\nRejected {r['path']}: {r['reason']}" for r in imp.get("rejected", []))
        elif up.get("text"):
            txt = up["text"]
        self.upd_lbl.configure(text=txt)
        self._render_scan(st, busy)
        s = st.get("selftest") or {}
        self.self_lbl.configure(text=("Running the self-test…" if busy == "selftest" else s.get("text", "")))
        self._render_quarantine(st.get("quarantine") or [])
        self._render_log(st.get("log") or [], st.get("log_seq", 0))
        if busy:
            self.progress.start(60)
            self._later()
        else:
            self.progress.stop()

    @staticmethod
    def _show(widget, on: bool) -> None:
        if on and not widget.winfo_ismapped():
            widget.pack(fill="x", anchor="w")
        elif not on and widget.winfo_ismapped():
            widget.pack_forget()

    def _render_tools(self, st: dict) -> None:
        sig = repr((st.get("tools"), st.get("install"), st.get("notes"), self.app.theme_name))
        if sig == self._sigs.get("tools"):
            return
        self._sigs["tools"] = sig
        for w in self.tools_box.winfo_children():
            w.destroy()
        for name in A.TOOLS:
            t = (st.get("tools") or {}).get(name) or {}
            row = ttk.Frame(self.tools_box, style="CardBody.TFrame")
            row.pack(fill="x", pady=2)
            pill(row, name, "ok" if t.get("path") else "off").grid(row=0, column=0, sticky="w", padx=(0, 10))
            if t.get("path"):
                extra = t.get("version") or ("version not asked: only the Update button ever runs it" if name == "freshclam" else "")
                if name == "clamdscan":
                    extra = (extra + " " if extra else "") + "(found, never used)"
                text = f"{t['path']}   {extra}".strip()
            else:
                text = "not found"
            ttk.Label(row, text=text, style="Card.TLabel", justify="left").grid(row=0, column=1, sticky="w")
        ins = st.get("install")
        self.install_lbl.configure(text=("ClamAV is not installed.\n" + "\n".join(ins["lines"])) if ins else "")
        self.notes_lbl.configure(text="\n".join(st.get("notes") or []))
        self._show(self.install_lbl, bool(ins))
        self._show(self.notes_lbl, bool(st.get("notes")))

    def _render_scan(self, st: dict, busy) -> None:
        last = st.get("last_scan")
        live = st.get("scan") or {}
        proof = st.get("proof")
        shown = last
        if busy in ("scan", "selftest"):
            text, tone = "Scanning…", "info"
            self.status.set(f"{live.get('found', 0)} found so far · {live.get('elapsed', 0)} s · connections watched "
                            "continuously (clamscan prints only infected files, so there is no per-file progress)")
        else:
            text, tone = verdict_of(proof)
            self.status.set(self._summary(shown))
        self.verdict.set(text)
        set_pill(self.verdict_pill, text, tone)
        self.results.delete(*self.results.get_children())
        for i in (last or {}).get("infected", [])[:2000]:
            self.results.insert("", "end", values=(i["path"], i["signature"], A.human_size(i.get("size"))))
        have = bool((last or {}).get("infected"))
        self._show(self.res_empty, not have)
        self.b_copy.state(["!disabled"] if have else ["disabled"])
        self.b_quar.state(["!disabled"] if have and not busy else ["disabled"])

    @staticmethod
    def _summary(r: dict | None) -> str:
        if not r:
            return ""
        s = r.get("summary") or {}
        bits = [r.get("verdict", ""), f"{len(r.get('infected', []))} infected"]
        if s.get("scanned"):
            bits.append(f"{s['scanned']} files scanned")
        if r.get("errors"):
            bits.append(f"{len(r['errors']) + r.get('more_errors', 0)} could not be read")
        bits.append(f"{r.get('elapsed', 0)} s")
        if r.get("not_offline"):
            bits.append("details: " + "; ".join(r.get("connection_details") or []))
        return " · ".join(b for b in bits if b)

    def _render_quarantine(self, items: list) -> None:
        sig = repr(items)
        if sig == self._sigs.get("q"):
            return
        self._sigs["q"] = sig
        from .gui_logic import clock12
        self.q_tree.delete(*self.q_tree.get_children())
        for q in items:
            when = time.strftime("%Y-%m-%d ", time.localtime(q["when"])) + clock12(q["when"])
            self.q_tree.insert("", "end", iid=q["id"], values=(q["original"], q["signature"], when))
        self._show(self.q_empty, not items)

    def _render_log(self, lines: list, seq: int) -> None:
        if seq == self._log_seq:
            return
        self._log_seq = seq
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.insert("end", "\n".join(f"{x['t']}  {x['text']}" for x in lines))
        self.log.configure(state="disabled")
        self.log.see("end")

    def retheme(self) -> None:
        self._sigs.clear()
        if self.st:
            self._got(self.st)

    # -- actions
    def reprobe(self) -> None:
        self._act("probe")

    def update(self) -> None:
        if messagebox.askokcancel("Update signatures", UPDATE_CONFIRM, parent=self.app.root, icon="warning"):
            self._act("update", {"confirmed": True})

    def import_files(self) -> None:
        names = filedialog.askopenfilenames(parent=self.app.root, title="Choose signature files (main, daily, bytecode)",
                                            filetypes=[("ClamAV databases", "*.cvd *.cld"), ("All files", "*")])
        if names:
            self._act("import", {"paths": list(names)})

    def set_paths(self, paths: list[str]) -> None:
        self.paths = list(dict.fromkeys(paths))
        self.path_list.delete(0, "end")
        for p in self.paths:
            self.path_list.insert("end", p)

    def add_folder(self) -> None:
        d = filedialog.askdirectory(parent=self.app.root, title="Folder to scan")
        if d:
            self.set_paths(self.paths + [d])

    def add_file(self) -> None:
        f = filedialog.askopenfilenames(parent=self.app.root, title="Files to scan")
        if f:
            self.set_paths(self.paths + list(f))

    def remove_paths(self) -> None:
        drop = {self.path_list.get(i) for i in self.path_list.curselection()}
        self.set_paths([p for p in self.paths if p not in drop])

    def scan(self) -> None:
        if not self.paths:
            messagebox.showinfo("Scan", "Add at least one folder or file to scan first.", parent=self.app.root)
            return
        self._act("scan", {"paths": self.paths})

    def stop(self) -> None:
        self._act("stop")

    def _picked(self) -> str | None:
        sel = self.results.selection()
        return self.results.item(sel[0], "values")[0] if sel else None

    def copy_path(self) -> None:
        p = self._picked()
        if p:
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append(p)
            self.app.flash("Path copied")

    def quarantine(self) -> None:
        p = self._picked()
        if p and messagebox.askokcancel("Quarantine", QUARANTINE_CONFIRM.format(path=p), parent=self.app.root, icon="warning"):
            self._act("quarantine", {"path": p})

    def selftest(self) -> None:
        if messagebox.askokcancel("Self-test", "This writes the harmless EICAR test string to a temporary file and scans "
                                  "it. Your own antivirus may react to that file. Continue?", parent=self.app.root):
            self._act("selftest")

    def _picked_q(self) -> str | None:
        sel = self.q_tree.selection()
        return sel[0] if sel else None

    def restore(self) -> None:
        q = self._picked_q()
        if q:
            self._act("restore", {"id": q})

    def delete_q(self) -> None:
        q = self._picked_q()
        if q and messagebox.askokcancel("Delete permanently", "Delete the selected quarantined file for good? This cannot "
                                        "be undone.", parent=self.app.root, icon="warning"):
            self._act("delete", {"id": q})
