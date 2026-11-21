"""The Proof tab's three activity graphs, drawn on tk.Canvas from the data `Controller.activity_state()` returns."""
from __future__ import annotations

import time
import tkinter as tk

from .gui_logic import hours_label, nice_max, scale
from .gui_theme import swatch

PAD_L, PAD_R, PAD_T, PAD_B = 46, 14, 14, 26


class Chart(tk.Canvas):
    """A small base: axes, grid and a message when there is nothing to draw. Subclasses fill `_plot`."""

    def __init__(self, master, pal: dict, height: int = 170, **kw):
        super().__init__(master, height=height, highlightthickness=0, bd=0, **kw)
        self.pal, self.data = pal, None
        self._job, self._sig = None, None
        self.bind("<Configure>", lambda _e: self._soon())

    def set_palette(self, pal: dict) -> None:
        self.pal = pal
        self.redraw(force=True)

    def update_data(self, data) -> None:
        self.data = data
        self._soon()

    def _soon(self) -> None:
        """Coalesce redraw requests (resize bursts, repeated refreshes) into one repaint per idle moment."""
        if self._job is None:
            self._job = self.after_idle(self._run)

    def _run(self) -> None:
        self._job = None
        self.redraw()

    # -- drawing helpers
    def box(self) -> tuple[float, float, float, float]:
        return PAD_L, PAD_T, max(PAD_L + 10, self.winfo_width() - PAD_R), max(PAD_T + 10, self.winfo_height() - PAD_B)

    def message(self, text: str) -> None:
        self.create_text(self.winfo_width() / 2, self.winfo_height() / 2, text=text, fill=self.pal["muted"],
                         width=max(200, self.winfo_width() - 60), justify="center", font=("TkDefaultFont", 10))

    def y_axis(self, top: float, unit: str = "") -> None:
        x0, y0, x1, y1 = self.box()
        for frac in (0, 0.5, 1):
            y = round(scale(frac, 0, 1, y1, y0)) + .5            # half-pixel offsets keep 1px lines crisp
            self.create_line(x0, y, x1, y, fill=self.pal["grid"])
            val = top * frac
            self.create_text(x0 - 5, y, text=(f"{val:g}{unit}"), anchor="e", fill=self.pal["muted"],
                             font=("TkDefaultFont", 9))

    def hour_axis(self) -> None:
        x0, _y0, x1, y1 = self.box()
        for h in range(0, 24, 3):
            x = scale(h + 0.5, 0, 24, x0, x1)
            self.create_text(x, y1 + 12, text=hours_label(h), fill=self.pal["muted"], font=("TkDefaultFont", 9))

    def redraw(self, force: bool = False) -> None:
        sig = (repr(self.data), self.winfo_width(), self.winfo_height(), self.pal["panel"], self.pal["line"])
        if sig == self._sig and not force:               # same data, size and colours: leave the picture alone
            return
        self._sig = sig
        self.delete("all")
        self.configure(bg=self.pal["panel"])
        if self.winfo_width() < 60:
            return
        if not self.data:
            self.message("Nothing to show yet.")
            return
        self._plot(self.data)

    def _plot(self, data) -> None:               # pragma: no cover - overridden
        raise NotImplementedError


class IntendedChart(Chart):
    """The band the settings are meant to produce: 10th to 90th percentile per hour, median line."""

    def _plot(self, d: dict) -> None:
        p10, p50, p90 = d["p10"], d["p50"], d["p90"]
        top = nice_max(max(p90 + [0.1]))
        x0, y0, x1, y1 = self.box()
        self.y_axis(top)
        self.hour_axis()
        up = [(scale(h + 0.5, 0, 24, x0, x1), scale(p90[h], 0, top, y1, y0)) for h in range(24)]
        dn = [(scale(h + 0.5, 0, 24, x0, x1), scale(p10[h], 0, top, y1, y0)) for h in range(23, -1, -1)]
        self.create_polygon([c for pt in up + dn for c in pt], fill=self.pal["band"], outline="")
        line = [c for h in range(24) for c in (scale(h + 0.5, 0, 24, x0, x1), scale(p50[h], 0, top, y1, y0))]
        self.create_line(*line, fill=self.pal["line"], width=2)
        self.create_text(x1, y0 - 2, text="requests per hour (shaded: usual range, line: typical)", anchor="e",
                         fill=self.pal["muted"], font=("TkDefaultFont", 9))


class SessionChart(Chart):
    """What the noise actually did, in 10-minute steps, against the planned band; off-plan hours in red."""

    def _plot(self, d: dict) -> None:
        buckets = [b for b in d.get("buckets") or []]
        if not buckets or not any(b["on"] for b in buckets):
            self.message(d.get("verdict") or "The noise is off, so there is nothing to compare yet.")
            return
        top = nice_max(max([b["req"] for b in buckets] + [b["hi"] for b in buckets] + [0.5]))
        x0, y0, x1, y1 = self.box()
        t0, t1 = buckets[0]["t"], buckets[-1]["t"] + 600
        self.y_axis(top)
        for f in d.get("flags") or []:           # off-plan hours
            xa, xb = scale(f["t0"], t0, t1, x0, x1), scale(f["t1"], t0, t1, x0, x1)
            if xb >= x0 and xa <= x1:
                self.create_rectangle(max(x0, xa), y0, min(x1, xb), y1, fill=self.pal["bad"], stipple="gray25",
                                      outline="")
        step = max(1.0, (x1 - x0) / max(1, len(buckets)))
        up = [(scale(b["t"] + 300, t0, t1, x0, x1), scale(b["hi"], 0, top, y1, y0)) for b in buckets]
        dn = [(scale(b["t"] + 300, t0, t1, x0, x1), scale(b["lo"], 0, top, y1, y0)) for b in reversed(buckets)]
        if len(buckets) > 1:
            self.create_polygon([c for pt in up + dn for c in pt], fill=self.pal["band"], outline="")
        for b in buckets:
            if not b["on"]:
                continue
            x = scale(b["t"] + 300, t0, t1, x0, x1)
            self.create_rectangle(x - step * 0.4, scale(b["req"], 0, top, y1, y0), x + step * 0.4, y1,
                                  fill=self.pal["line"], outline="")
        # time labels
        for k in range(5):
            t = t0 + (t1 - t0) * k / 4
            self.create_text(scale(t, t0, t1, x0, x1), y1 + 12, text=time.strftime("%H:%M", time.localtime(t)),
                             fill=self.pal["muted"], font=("TkDefaultFont", 9))
        self.create_text(x1, y0 - 2, text="requests per 10 minutes (shaded: planned range, red: off plan)",
                         anchor="e", fill=self.pal["muted"], font=("TkDefaultFont", 9))


class BaselineChart(Chart):
    """Share of the day's activity by hour: yours (baseline) next to the noise's."""

    def _plot(self, d: dict) -> None:
        you, noise = d.get("you") or [0.0] * 24, d.get("noise") or [0.0] * 24
        if d.get("state") == "none" and not any(noise):
            self.message(d.get("verdict") or "Not enough data yet to say how you browse.")
            return
        top = nice_max(max(you + noise + [0.02]) * 100) / 100
        x0, y0, x1, y1 = self.box()
        self.y_axis(top * 100, "%")
        self.hour_axis()
        w = (x1 - x0) / 24
        for h in range(24):
            xa = x0 + h * w
            if you[h] > 0:
                self.create_rectangle(xa + w * 0.1, scale(you[h], 0, top, y1, y0), xa + w * 0.5, y1,
                                      fill=self.pal["you"], outline="")
            if noise[h] > 0:
                self.create_rectangle(xa + w * 0.5, scale(noise[h], 0, top, y1, y0), xa + w * 0.9, y1,
                                      fill=self.pal["noise"], outline="")
        swatch(self, x0 + 6, y0 - 6, 4, self.pal["you"], 1)               # square = you, circle = the noise
        self.create_text(x0 + 14, y0 - 6, text="you", anchor="w", fill=self.pal["you"], font=("TkDefaultFont", 9, "bold"))
        swatch(self, x0 + 50, y0 - 6, 4, self.pal["noise"], 0)
        self.create_text(x0 + 58, y0 - 6, text="the noise", anchor="w", fill=self.pal["noise"],
                         font=("TkDefaultFont", 9, "bold"))
        self.create_text(x1, y0 - 2, text="share of the day's activity, by hour", anchor="e",
                         fill=self.pal["muted"], font=("TkDefaultFont", 9))


class TimelineChart(Chart):
    """Last 6 hours per minute: different addresses connected, split by who opened them; stripes where the noise was on."""

    def _plot(self, rows: list) -> None:
        if not rows or not any(r["you"] + r["noise"] + (1 if r.get("tor") else 0) for r in rows):
            self.message("No connection counts yet. They fill in a minute at a time while this app is open.")
            return
        x0, y0, x1, y1 = self.box()
        mx = nice_max(max(3, max(r["you"] + r["noise"] + (1 if r.get("tor") else 0) for r in rows)))
        self.y_axis(mx)
        n = len(rows)
        w = (x1 - x0) / n
        for i, r in enumerate(rows):
            x = x0 + i * w
            if r.get("on"):
                self.create_rectangle(x, y0, x + max(w, 1), y1, fill=self.pal["bad"], stipple="gray12", outline="")
            base = 0
            for key, col in (("you", self.pal["line"]), ("noise", self.pal["noise"]), ("tor", self.pal["tor"])):
                v = (1 if r.get(key) else 0) if key == "tor" else r.get(key, 0)
                if v:
                    self.create_rectangle(x, scale(base + v, 0, mx, y1, y0), x + max(w - 0.3, 0.8), scale(base, 0, mx, y1, y0),
                                          fill=col, outline="")
                    base += v
        for k in range(5):
            t = rows[0]["t"] + (rows[-1]["t"] - rows[0]["t"]) * k / 4
            self.create_text(scale(k, 0, 4, x0, x1), y1 + 12, text=time.strftime("%H:%M", time.localtime(t)),
                             fill=self.pal["muted"], font=("TkDefaultFont", 9))
        lx = x0 + 4
        for n, (label, col) in enumerate((("your apps", self.pal["line"]), ("legalPrivacy", self.pal["noise"]),
                                          ("Tor", self.pal["tor"]))):
            swatch(self, lx + 4, y0 - 6, 4, col, (1, 0, 2)[n])             # square, circle, diamond
            self.create_text(lx + 12, y0 - 6, text=label, anchor="w", fill=self.pal["muted"], font=("TkDefaultFont", 9))
            lx += 20 + 7 * len(label)
