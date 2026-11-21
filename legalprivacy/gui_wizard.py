"""First-run welcome (the web dashboard's 3-question wizard) for the native app."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from .gui_theme import Card

LEVELS = [(2, "Light", "a little noise; barely any data"), (5, "Moderate (recommended)", "a good starting point"),
          (8, "Busy", "more cover; uses more data")]


def show_wizard(app) -> None:
    """Three questions, then Start. Skipping keeps the recommended settings."""
    win = tk.Toplevel(app.root)
    win.title("Welcome to legalPrivacy")
    win.transient(app.root)
    win.configure(bg=app.pal["bg"])
    win.resizable(False, False)
    body = ttk.Frame(win, padding=18)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text="Welcome to legalPrivacy", style="H1.TLabel").pack(anchor="w")
    ttk.Label(body, text="Three quick questions. Everything can be changed later, and everything already has a "
                         "recommended setting.", style="Muted.TLabel", wraplength=460, justify="left").pack(anchor="w", pady=(2, 12))
    level, mode, tor, auto = tk.IntVar(value=7), tk.StringVar(value="random"), tk.StringVar(value="off"), tk.BooleanVar(value=False)

    c = Card(body, app, "1. How much background noise?")
    c.pack(fill="x", pady=(0, 8))
    for val, lab, hint in LEVELS:
        c.radio(level, val, lab, hint)
    c.radio(mode, "random", "Randomised, like a person (recommended)")
    c.radio(mode, "steady", "Steady: about the same amount every hour")
    c = Card(body, app, "2. Add Tor darknet (.onion) noise?")
    c.pack(fill="x", pady=(0, 8))
    c.radio(tor, "off", "No (recommended)", "You can turn it on later in the Tor tab.")
    c.radio(tor, "onion", "Yes", "legalPrivacy runs its own private Tor and visits real .onion sites.")
    c = Card(body, app, "3. Start automatically?")
    c.pack(fill="x", pady=(0, 12))
    c.radio(auto, False, "No, I will press Start")
    c.radio(auto, True, "Yes, whenever I open legalPrivacy")

    def done(start: bool):
        answers = {"rate_mode": mode.get(), "level": level.get(), "tor": tor.get(), "autostart": bool(auto.get())}
        win.destroy()

        def go():
            app.ctl.wizard(answers)
            if start:
                app.ctl.start()
        app.work(go, done=lambda _r: (app.resync_now(), app.poll_now()), error=lambda e: app.error("Setup", e))

    row = ttk.Frame(body)
    row.pack(fill="x")
    app.btn(row, "Save and start", "play", "primary", lambda: done(True)).pack(side="right")
    app.btn(row, "Just save", None, "secondary", lambda: done(False)).pack(side="right", padx=6)
    app.btn(row, "Skip", None, "ghost", win.destroy).pack(side="left")
    win.update_idletasks()
    try:
        x = app.root.winfo_rootx() + (app.root.winfo_width() - win.winfo_width()) // 2
        y = app.root.winfo_rooty() + 60
        win.geometry(f"+{max(0, x)}+{max(0, y)}")
        win.grab_set()
    except tk.TclError:
        pass
