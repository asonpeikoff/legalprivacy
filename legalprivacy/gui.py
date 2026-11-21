"""Native desktop app for legalPrivacy: a Tk window that talks to the Controller directly, in this process.

No browser, no web view and no HTTP. Tkinter/ttk only (the standard library); the web dashboard
(legalprivacy/webui.py) stays as the backup front end and can be opened from the File menu.

    legalprivacy-gui            or            python -m legalprivacy.gui

Threads: the Tk main thread never waits on the controller. State is fetched by a worker thread once a
second and slow actions (Start, Stop, checks, imports, Tor, Panic) run in worker threads; their results
come back through a queue that the main thread drains from an `after` poll.
"""
from __future__ import annotations

import json
import socket
import sys
import threading
import webbrowser
from dataclasses import asdict

from . import __version__
from . import gui_logic as L

TITLE = "legalPrivacy"
BLOG = "https://legalizingprivacy.substack.com"
NO_TK_MESSAGE = (
    "The legalPrivacy desktop app needs Tk (Python's built-in GUI toolkit), and this Python does not have it.\n"
    "  Windows / macOS: install Python from python.org (Tk is included).\n"
    "  Debian / Ubuntu: sudo apt install python3-tk\n"
    "  Fedora: sudo dnf install python3-tkinter\n"
    "Opening the web dashboard in your browser instead.")
LOCK_PORT = 47653                                    # loopback port held while the desktop app is open


# ── small drawing helpers ───────────────────────────────────────────────────
def make_logo(tk, size: int, bg: str, fg: str):
    """A simple waveform icon, drawn into a PhotoImage with no image files."""
    img = tk.PhotoImage(width=size, height=size)
    img.put(bg, to=(0, 0, size, size))
    heights = [0.22, 0.45, 0.78, 0.5, 0.92, 0.38, 0.62, 0.3]
    n = len(heights)
    unit = size / (n * 2 + 1)
    for i, h in enumerate(heights):
        x0 = int(round(unit * (2 * i + 1)))
        x1 = max(x0 + 1, int(round(unit * (2 * i + 2))))
        bar = max(2, int(size * 0.8 * h))
        y0 = (size - bar) // 2
        img.put(fg, to=(x0, y0, x1, y0 + bar))
    return img


def claim_instance(port: int = LOCK_PORT):
    """Hold a loopback port while this desktop app is open, so a second copy notices. Returns the socket,
    or None when another copy holds it. (Any other failure is treated as 'no lock available': carry on.)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        s.listen(1)
        return s
    except OSError as exc:
        s.close()
        import errno
        return None if exc.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1), 10048) else False


def _prefs_path():
    from .paths import app_dir
    return app_dir() / "gui.json"


def load_prefs() -> dict:
    try:
        return json.loads(_prefs_path().read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_prefs(p: dict) -> None:
    try:
        _prefs_path().write_text(json.dumps(p), encoding="utf-8")
    except Exception:
        pass


# colour of an icon next to text, by button kind
ICON_TONE = {"primary": "accent_fg", "tor": "#ffffff", "danger": "bad", "secondary": "fg", "ghost": "muted",
             "link": "info", "seg": "muted"}
BUTTON_STYLE = {"primary": "Primary.TButton", "secondary": "TButton", "danger": "Danger.TButton", "tor": "Tor.TButton",
                "ghost": "Ghost.TButton", "link": "Link.TButton", "seg": "Seg.TButton"}


def build_app_class():
    """Import tkinter lazily so `import legalprivacy.gui` works (and is testable) without Tk."""
    import tkinter as tk
    from tkinter import messagebox, ttk

    from . import gui_theme as T
    from .gui_more import HealthTab, HelpTab, MLTab, MyListTab, ToolsTab
    from .gui_security import SecurityTab
    from .gui_settings import SettingsTab
    from .gui_tabs import ActivityTab, DashboardTab, LogTab, ProofTab, TorTab

    TABS = [DashboardTab, ActivityTab, LogTab, TorTab, SettingsTab, MyListTab, MLTab, ProofTab, SecurityTab, ToolsTab,
            HealthTab, HelpTab]

    class App:
        def __init__(self, root: tk.Tk, ctl, web_port: int = 8765):
            self.root, self.ctl, self.web_port = root, ctl, web_port
            self.q = L.UiQueue()
            self.web = None
            self.state: dict = {}
            self.loading = False
            self.closing = False
            self._state_busy = False
            self._apply_text, self._apply_tone, self._applying, self._apply_err = "", "off", False, None
            self.text_widgets: list = []
            self.field_texts: list = []
            self._icons: dict = {}
            self._tracked: list = []
            prefs = load_prefs()
            self.theme_name = "dark" if prefs.get("theme") == "dark" else "light"
            self.pal = L.PALETTES[self.theme_name]
            self.fonts = T.init_fonts(root)
            self.scale = T.ui_scale(root)
            T.Tooltip.app = self
            self._style = ttk.Style(root)
            try:
                self._style.theme_use("clam")
            except tk.TclError:
                pass
            root.title(TITLE)
            root.minsize(940, 640)
            root.geometry("1080x760")
            self.logo_big = make_logo(tk, 64, "#1d2733", "#4cc07d")
            self.logo_small = make_logo(tk, 28 * self.scale, "#1d2733", "#4cc07d")
            try:
                root.iconphoto(True, self.logo_big)
            except tk.TclError:
                pass
            self.live = L.LiveApply(ctl, self._collect, self.q.post, self._report, root.after, root.after_cancel)
            self._build()
            self.apply_theme()
            self._bind_keys()
            self.loading = True
            vals = L.profile_values(ctl.profile, ctl.app)
            for t in self.tabs:
                t.load(vals)
            self.loading = False
            self._loaded_vals = vals
            root.protocol("WM_DELETE_WINDOW", self.quit_app)
            self.pump()
            self.tick()

        # -- icons and buttons
        def icon(self, name: str, tone: str = "fg"):
            color = self.pal.get(tone, tone)
            key = (name, color, self.scale)
            if key not in self._icons:
                self._icons[key] = T.make_icon(self.root, name, color, self.scale)
            return self._icons[key]

        def track_icon(self, widget, name: str, tone: str) -> None:
            self._tracked.append((widget, name, tone))

        def btn(self, parent, text: str, icon: str | None = None, kind: str = "secondary", command=None, tooltip: str = ""):
            b = ttk.Button(parent, text=text, style=BUTTON_STYLE.get(kind, "TButton"), command=command, takefocus=True)
            if icon:
                b.configure(image=self.icon(icon, ICON_TONE.get(kind, "fg")), compound="left")
                self.track_icon(b, icon, ICON_TONE.get(kind, "fg"))
            T.tip(b, tooltip)
            return b

        def web_button(self, parent, text: str = "Open in the web dashboard"):
            b = self.btn(parent, text, "web", "secondary", self.open_web,
                         "Opens the same settings in the web dashboard (the backup front end) in your browser.")
            b.pack(anchor="w", pady=(2, 0))
            return b

        def after_idle_job(self, fn) -> None:
            self.root.after(80, fn)

        # -- theme
        def apply_theme(self) -> None:
            T.apply_theme(self.root, self._style, self.pal, self.fonts)
            self._icons.clear()
            for w, name, tone in list(self._tracked):
                try:
                    w.configure(image=self.icon(name, tone))
                except tk.TclError:
                    self._tracked.remove((w, name, tone))
            if hasattr(self, "nb"):
                for t in self.tabs:
                    self.nb.tab(t, image=self.icon(t.icon, "muted"))
            for group, bg in ((self.text_widgets, self.pal["log_bg"]), (self.field_texts, self.pal["field"])):
                for tw in group:
                    try:
                        tw.configure(bg=bg, fg=self.pal["fg"], insertbackground=self.pal["fg"],
                                     highlightbackground=self.pal["border"], highlightcolor=self.pal["accent"],
                                     selectbackground=self.pal["select"], selectforeground=self.pal["fg"])
                    except tk.TclError:
                        pass
            for t in getattr(self, "tabs", []):
                t.retheme()
            if hasattr(self, "light"):
                self._paint_light()
            if hasattr(self, "logo_lbl"):
                self.logo_lbl.configure(image=self.logo_small)

        def set_theme(self, name: str) -> None:
            self.theme_name = name
            self.pal = L.PALETTES[name]
            self.apply_theme()
            p = load_prefs()
            p["theme"] = name
            save_prefs(p)

        # -- layout
        def _build(self) -> None:
            r = self.root
            r.columnconfigure(0, weight=1)
            r.rowconfigure(1, weight=1)
            hd = ttk.Frame(r, style="Header.TFrame", padding=(16, 10))
            hd.grid(row=0, column=0, sticky="ew")
            hd.columnconfigure(6, weight=1)
            self.logo_lbl = ttk.Label(hd, image=self.logo_small, style="Header.TLabel")
            self.logo_lbl.grid(row=0, column=0, padx=(0, 10))
            ttk.Label(hd, text=TITLE, style="HeaderH1.TLabel").grid(row=0, column=1, padx=(0, 20))
            self.b_start = self.btn(hd, "Start", "play", "primary", self.do_start, "Start the noise  (F5)")
            self.b_pause = self.btn(hd, "Pause", "pause", "secondary", self.do_pause, "Pause or resume the noise  (F6)")
            self.b_stop = self.btn(hd, "Stop", "stop", "secondary", self.do_stop, "Stop the noise  (F7)")
            for i, b in enumerate((self.b_start, self.b_pause, self.b_stop)):
                b.grid(row=0, column=2 + i, padx=(0, 6))
            lf = ttk.Frame(hd, style="Header.TFrame")
            lf.grid(row=0, column=5, sticky="w", padx=(10, 0))
            self.light = tk.Canvas(lf, width=14, height=14, highlightthickness=0, bd=0)
            self.light.pack(side="left")
            self.status_var = tk.StringVar(value="Stopped")
            ttk.Label(lf, textvariable=self.status_var, style="Header.TLabel", font=self.fonts["bold"]).pack(side="left", padx=(6, 0))
            chips = ttk.Frame(hd, style="Header.TFrame")
            chips.grid(row=0, column=7, sticky="e")
            self.tor_chip = ttk.Label(chips, text="Tor: off", style="Pilloff.TLabel")
            self.tor_chip.pack(side="left", padx=(0, 6))
            T.tip(self.tor_chip, "Whether Tor (used only for .onion noise) is connected")
            ttk.Separator(r, orient="horizontal").grid(row=0, column=0, sticky="sew")

            self.nb = ttk.Notebook(r)
            self.nb.grid(row=1, column=0, sticky="nsew")
            self.nb.enable_traversal()
            self.tabs = []
            for cls in TABS:
                t = cls(self.nb, self)
                self.nb.add(t, text=" " + t.title, image=self.icon(t.icon, "muted"), compound="left")
                self.tabs.append(t)
            self.nb.bind("<<NotebookTabChanged>>", lambda _e: self._tab_changed())
            self.nb.bind("<Configure>", lambda _e: self._fit_tabs(), add="+")

            ttk.Separator(r, orient="horizontal").grid(row=2, column=0, sticky="ew")
            sb = ttk.Frame(r, style="Header.TFrame", padding=(16, 6))
            sb.grid(row=3, column=0, sticky="ew")
            sb.columnconfigure(0, weight=1)
            self.msg_var, self.apply_var = tk.StringVar(), tk.StringVar()
            ttk.Label(sb, textvariable=self.msg_var, style="HeaderMuted.TLabel").grid(row=0, column=0, sticky="w")
            self.apply_lbl = ttk.Label(sb, textvariable=self.apply_var, style="Header.TLabel", font=self.fonts["bold"])
            self.apply_lbl.grid(row=0, column=1, sticky="e", padx=(0, 10))
            # "are the running settings the saved ones?" lives in the status bar, next to the live-apply message
            self.set_chip = ttk.Label(sb, text="Settings saved", style="Pilloff.TLabel")
            self.set_chip.grid(row=0, column=2, sticky="e")
            T.tip(self.set_chip, "The running noise is using exactly the settings you saved. The time shows how long ago they last took effect.")

            menu = tk.Menu(r)
            fm = tk.Menu(menu, tearoff=0)
            fm.add_command(label="Open the web dashboard (backup)", command=self.open_web)
            fm.add_separator()
            fm.add_command(label="Quit", accelerator="Ctrl+Q", command=self.quit_app)
            menu.add_cascade(label="File", menu=fm)
            vm = tk.Menu(menu, tearoff=0)
            self.dark_var = tk.BooleanVar(value=self.theme_name == "dark")
            vm.add_checkbutton(label="Dark mode", variable=self.dark_var,
                               command=lambda: self.set_theme("dark" if self.dark_var.get() else "light"))
            menu.add_cascade(label="View", menu=vm)
            hm = tk.Menu(menu, tearoff=0)
            hm.add_command(label="About legalPrivacy", command=self.about)
            hm.add_command(label="Read the blog we are named after (Legalizing Privacy)",
                           command=lambda: webbrowser.open(BLOG))
            menu.add_cascade(label="Help", menu=hm)
            r.configure(menu=menu)

        def _bind_keys(self) -> None:
            r = self.root
            r.bind("<F5>", lambda _e: self.do_start())
            r.bind("<F6>", lambda _e: self.do_pause())
            r.bind("<F7>", lambda _e: self.do_stop())
            r.bind("<Control-q>", lambda _e: self.quit_app())
            for i in range(1, 10):
                r.bind(f"<Control-Key-{i}>", lambda _e, i=i: self.nb.select(i - 1))

        def _fit_tabs(self) -> None:
            """Never truncate a tab label: when all labels do not fit, only the selected tab keeps its text."""
            try:
                avail = self.nb.winfo_width()
                if avail < 100:
                    return
                f = self.fonts["base"]
                fx = T.dpi_factor(self.root)
                icon, pad = 12 * self.scale + 6, 2 * 9 * fx + 4
                need = sum(f.measure(" " + t.title) + icon + pad for t in self.tabs) + 24 * fx
                compact = need > avail
                if compact == getattr(self, "_compact_tabs", None) and not compact:
                    return
                self._compact_tabs = compact
                sel = self.nb.select()
                for t in self.tabs:
                    keep = (not compact) or str(t) == str(sel)
                    self.nb.tab(t, text=(" " + t.title) if keep else "")
            except tk.TclError:
                pass

        def _tab_changed(self) -> None:
            if getattr(self, "_compact_tabs", False):
                self._fit_tabs()
            try:
                self.current_tab().on_show()
            except (tk.TclError, IndexError):
                pass

        def current_tab(self):
            return self.tabs[self.nb.index(self.nb.select())]

        # -- threads
        def work(self, fn, done=None, error=None) -> None:
            L.run_in_thread(fn, self.q.post, done, error)

        def pump(self) -> None:
            self.q.drain()
            if not self.closing or not self.q.empty():
                self.root.after(100, self.pump)

        def error(self, what: str, exc) -> None:
            messagebox.showerror(what, str(exc) or exc.__class__.__name__, parent=self.root)

        def flash(self, text: str, ms: int = 5000) -> None:
            self.msg_var.set(text)
            self.root.after(ms, lambda: self.msg_var.set("") if self.msg_var.get() == text else None)

        # -- polling
        def poll_now(self) -> None:
            self._fetch_state()

        def tick(self) -> None:
            if self.closing:
                return
            self._fetch_state()
            if self.web is not None and self.web.quit_event.is_set():       # Quit pressed in the web dashboard
                self.quit_app()
                return
            self.root.after(1000, self.tick)

        def _fetch_state(self) -> None:
            if self._state_busy:
                return
            self._state_busy = True

            def done(st):
                self._state_busy = False
                self.on_state(st)

            def failed(exc):
                self._state_busy = False
                self.flash(f"Could not read the state: {exc}")
            self.work(self.ctl.state, done, failed)

        def on_state(self, st: dict) -> None:
            self.state = st
            kind, text = L.run_status(st)
            self.status_var.set(text)
            self._light_kind = kind
            self._paint_light()
            bs = L.button_states(st)
            for key, b in (("start", self.b_start), ("pause", self.b_pause), ("stop", self.b_stop)):
                b.state(["!disabled"] if bs[key] and not self.closing else ["disabled"])
            paused = bool(st.get("paused"))
            self.b_pause.configure(text=L.pause_label(st), image=self.icon("play" if paused else "pause", ICON_TONE["secondary"]))
            ttxt, ttone = L.tor_chip(st.get("tor"), bool((st.get("profile") or {}).get("transports", {}).get("tor", {}).get("enabled")))
            self.tor_chip.configure(text=ttxt, style="Pill" + {"ok": "tor"}.get(ttone, ttone) + ".TLabel")
            self._paint_settings_chip()
            for t in self.tabs:
                t.update_state(st)
            self._resync()

        def _paint_light(self) -> None:
            kind = getattr(self, "_light_kind", "stopped")
            col = {"running": self.pal["ok"], "paused": self.pal["warn"], "stopped": self.pal["muted"]}[kind]
            self.light.configure(bg=self.pal["panel"])
            self.light.delete("all")
            self.light.create_oval(1, 1, 13, 13, fill=col, outline="")

        def _paint_settings_chip(self) -> None:
            text, tone = L.settings_chip(self.state.get("settings"), self._applying, self._apply_err)
            self.set_chip.configure(text=text, style=f"Pill{tone}.TLabel")
            self.apply_var.set(self._apply_text)
            self.apply_lbl.configure(foreground=self.pal.get({"ok": "ok", "warn": "warn", "bad": "bad"}.get(self._apply_tone, "muted"),
                                                             self.pal["muted"]))

        # -- live apply
        def edited(self) -> None:
            if not self.loading:
                self.live.changed()

        def _collect(self) -> dict:
            v: dict = {}
            for t in self.tabs:
                v.update(t.values())
            self._last_edit = v
            return {"config": L.build_config_payload(v, asdict(self.ctl.profile.rate)), "app": L.app_flags(v)}

        def _report(self, kind: str, text: str, tone: str) -> None:
            self._applying = kind == "applying"
            self._apply_err = text if kind == "error" else None
            self._apply_text, self._apply_tone = ("" if kind == "error" else text), tone
            if kind == "error":
                self.flash("Not saved: " + text, 9000)
            elif kind == "done":                                   # let the message fade after a while
                shown = self._apply_text
                self.root.after(12000, lambda: self._fade(shown))
            self._paint_settings_chip()

        def _fade(self, shown: str) -> None:
            if self._apply_text == shown and not self._applying:
                self._apply_text = ""
                self._paint_settings_chip()

        def resync_now(self) -> None:
            self._loaded_vals = None
            self._resync()

        def _resync(self) -> None:
            """If settings changed somewhere else (the backup web dashboard), show them here too."""
            if self.live.debounce.pending or self.live.busy:
                return
            vals = L.profile_values(self.ctl.profile, self.ctl.app)
            if vals != self._loaded_vals:
                self._loaded_vals = vals
                self.loading = True
                try:
                    for t in self.tabs:
                        t.load(vals)
                finally:
                    self.loading = False

        # -- run control
        def do_start(self) -> None:
            if str(self.b_start.cget("state")) == "disabled":
                return
            self.b_start.state(["disabled"])
            self.work(self.ctl.start, done=lambda _r: self.poll_now(), error=self._start_failed)

        def _start_failed(self, exc) -> None:
            self.poll_now()
            self.error("Could not start", exc)

        def do_pause(self) -> None:
            if str(self.b_pause.cget("state")) == "disabled":
                return
            paused = bool(self.state.get("paused"))
            self.work(lambda: self.ctl.pause(not paused), done=lambda _r: self.poll_now())

        def do_stop(self) -> None:
            if str(self.b_stop.cget("state")) == "disabled":
                return
            self.b_stop.state(["disabled"])
            self.work(self.ctl.stop, done=lambda _r: self.poll_now(), error=lambda e: self.error("Stop", e))

        # -- menu actions
        def open_web(self) -> None:
            def go():
                if self.web is None:
                    from .webui import UIServer
                    srv = UIServer(self.ctl, self.web_port)
                    threading.Thread(target=srv.serve_forever, daemon=True, name="webui-main").start()
                    self.web = srv
                return self.web.url

            def opened(url):
                if not webbrowser.open(url):
                    self.flash("Could not open a browser. The link is: " + url, 20000)
                else:
                    self.flash("Opened the web dashboard in your browser.")
            self.work(go, opened, lambda e: self.error("Web dashboard", e))

        def about(self) -> None:
            messagebox.showinfo(
                "About legalPrivacy",
                f"legalPrivacy {__version__}\n\nPrivacy noise generator with optional Tor/onion mode.\n"
                "This is the native desktop app; the web dashboard is available from the File menu.\n\n"
                "Named in homage to the blog Legalizing Privacy by Amy Peikoff:\nhttps://legalizingprivacy.substack.com\n\n"
                "Everything runs on this computer.", parent=self.root)

        def quit_app(self) -> None:
            if self.closing:
                return
            self.closing = True
            self.msg_var.set("Stopping…")
            for b in (self.b_start, self.b_pause, self.b_stop):
                b.state(["disabled"])
            if self.web is not None:
                self.web.quit_event.set()

            def stop():
                self.ctl.stop(stop_tor=True)
            self.work(stop, done=lambda _r: self._destroy(), error=lambda _e: self._destroy())
            self.root.after(20000, self._destroy)               # never hang on exit

        def _destroy(self) -> None:
            try:
                self.root.destroy()
            except tk.TclError:
                pass

    return App


def _make_dpi_aware() -> None:
    """On Windows, ask for real pixels so the window is sharp on high-density screens."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass


def main(profile_path: str | None = None, port: int | None = None) -> int:
    from .paths import ensure_utf8_console
    ensure_utf8_console()
    from .webui import run_ui, running_instance, start_services
    try:
        import tkinter as tk
        from tkinter import messagebox
    except ImportError:
        print(NO_TK_MESSAGE, file=sys.stderr)
        return run_ui(profile_path, port)
    _make_dpi_aware()
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"Could not open a window ({exc}). Opening the web dashboard in your browser instead.",
              file=sys.stderr)
        return run_ui(profile_path, port)
    root.withdraw()
    from .controller import Controller
    ctl = Controller(profile_path)
    want = port if port is not None else int(ctl.app.get("port", 8765))
    other = running_instance(want) if port is None else None
    lock = claim_instance() if not other else None
    if other or lock is None:
        if other and messagebox.askyesno(
                TITLE, "legalPrivacy is already running (a web dashboard is open).\n\nStarting a second copy "
                       "would run two noise generators on the same data.\n\nOpen the running one in your "
                       "browser instead?", parent=root):
            webbrowser.open(other)
        elif not other:
            messagebox.showinfo(TITLE, "legalPrivacy is already open in another window.", parent=root)
        root.destroy()
        return 0
    App = build_app_class()
    app = App(root, ctl, want)
    root.deiconify()
    first_run = ctl.first_run
    start_services(ctl)
    if first_run:
        from .gui_wizard import show_wizard
        root.after(500, lambda: show_wizard(app))  # noqa: F821 (closure over a name deleted after mainloop)
    try:
        root.mainloop()
    finally:
        try:
            ctl.stop(stop_tor=True)
        except Exception:
            pass
        if lock:
            lock.close()
    del app
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
