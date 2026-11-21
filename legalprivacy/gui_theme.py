"""Look and feel of the native app: pixel icons drawn in code (no image files), the ttk styles for both
themes, and the small widgets every tab shares (tooltips, cards, buttons, the stacked mix bar, sparklines).
Needs tkinter; the display-free logic is in gui_logic.py / gui_fields.py."""
from __future__ import annotations

import math
import sys
import tkinter as tk
from tkinter import ttk

from . import gui_fields as F
from .gui_logic import MIX_COLORS

# ── icons: 12x12 pixel art, drawn in whatever colour the theme wants ──────────
ICONS: dict[str, list[str]] = {
    "dash": ["............", ".####..####.", ".####..####.", ".####..####.", ".####..####.", "............",
             ".####..####.", ".####..####.", ".####..####.", ".####..####.", "............", "............"],
    "act": ["............", "............", "............", "......#.....", ".....#.#....", "....#...#...",
            "###.#.....#.", "...##......#", "............", "............", "............", "............"],
    "log": ["............", ".##########.", "............", ".#######....", "............", ".##########.",
            "............", ".######.....", "............", ".#########..", "............", "............"],
    "tor": ["....####....", "..########..", ".###....###.", ".##.####.##.", "##.##..##.##", "##.##..##.##",
            ".##.####.##.", ".###....###.", "..########..", "....####....", "............", "............"],
    "set": ["............", ".#########..", ".....##.....", "............", ".#########..", "...##.......",
            "............", ".#########..", "........##..", "............", "............", "............"],
    "proof": [".....##.....", "..########..", ".##########.", ".####..####.", ".###....###.", ".###.##.###.",
              ".####.####..", "..#######...", "...#####....", "....###.....", ".....#......", "............"],
    "list": ["............", ".#.########.", "............", ".#.########.", "............", ".#.########.",
             "............", ".#.########.", "............", "............", "............", "............"],
    "ml": ["............", "..........#.", "..........#.", "......#...#.", "......#.#.#.", "..#...#.#.#.",
           "..#.#.#.#.#.", "..#.#.#.#.#.", "............", "############", "............", "............"],
    "tools": ["........###.", ".......##.##", "......###.##", ".....####.##", "....####.##.", "...####.###.",
              "..####......", ".####.......", ".###........", ".##.........", "............", "............"],
    "health": ["............", "..###..###..", ".####.#####.", ".###########", ".###########", "..#########.",
               "...#######..", "....#####...", ".....###....", "......#.....", "............", "............"],
    "help": ["...######...", "..##....##..", "..##....##..", ".......##...", "......##....", ".....##.....",
             ".....##.....", "............", ".....##.....", ".....##.....", "............", "............"],
    "play": ["............", "..##........", "..####......", "..######....", "..########..", "..########..",
             "..######....", "..####......", "..##........", "............", "............", "............"],
    "pause": ["............", "..###..###..", "..###..###..", "..###..###..", "..###..###..", "..###..###..",
              "..###..###..", "..###..###..", "..###..###..", "............", "............", "............"],
    "stop": ["............", "............", "..########..", "..########..", "..########..", "..########..",
             "..########..", "..########..", "..########..", "............", "............", "............"],
    "refresh": ["............", "...######...", "..##....##..", ".##......##.", ".##....####.", ".##.....##..",
                ".##......#..", "..##....##..", "...######...", "............", "............", "............"],
    "bolt": ["......##....", ".....##.....", "....###.....", "...###......", "..########..", "......###...",
             ".....###....", "....##......", "...##.......", "..#.........", "............", "............"],
    "check": ["............", "............", "..........#.", ".........##.", "........##..", ".#.....##...",
              ".##...##....", "..##.##.....", "...###......", "....#.......", "............", "............"],
    "plus": ["............", "............", ".....##.....", ".....##.....", ".....##.....", "############",
             ".....##.....", ".....##.....", ".....##.....", "............", "............", "............"],
    "scan": ["....####....", "..##....##..", ".##......##.", ".##......##.", ".##......##.", "..##....##..",
             "...####..##.", "..........##", "...........#", "............", "............", "............"],
    "web": ["....####....", "..#.####.#..", ".#..#..#..#.", "############", "#...#..#...#", "#...#..#...#",
            "############", ".#..#..#..#.", "..#.####.#..", "....####....", "............", "............"],
}
for _k, _rows in ICONS.items():                 # keep every row exactly 12 wide
    ICONS[_k] = [(r + "." * 12)[:12] for r in _rows[:12]] + ["." * 12] * (12 - len(_rows))


def ui_scale(root: tk.Misc) -> int:
    """How many times to enlarge the icons: 1 at 96 dpi, 2 on high-density screens."""
    try:
        return max(1, int(round(root.winfo_fpixels("1i") / 96.0)))
    except tk.TclError:
        return 1


def make_icon(root: tk.Misc, name: str, color: str, scale: int = 1) -> tk.PhotoImage:
    rows = ICONS.get(name) or ICONS["dash"]
    px = scale
    img = tk.PhotoImage(master=root, width=12 * px, height=12 * px)
    for y, row in enumerate(rows):
        x = 0
        while x < 12:
            if row[x] == "#":
                x1 = x
                while x1 < 12 and row[x1] == "#":
                    x1 += 1
                img.put(color, to=(x * px, y * px, x1 * px, (y + 1) * px))
                x = x1
            else:
                x += 1
    return img


def dpi_factor(root: tk.Misc) -> float:
    """Screen density relative to 96 dpi (1.0 normal, 1.25 / 1.5 / 2.0 on scaled or high-density screens)."""
    try:
        return min(3.0, max(1.0, root.winfo_fpixels("1i") / 96.0))
    except tk.TclError:
        return 1.0


# ── anti-aliased shapes drawn in code (round slider handle, rounded track, legend swatches) ──────────────
def _rgb(h: str) -> tuple:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _mix(a: str, b: str, t: float) -> str:
    """Colour a moved t of the way towards colour b (both '#rrggbb')."""
    ca, cb = _rgb(a), _rgb(b)
    return "#%02x%02x%02x" % tuple(int(round(ca[i] + (cb[i] - ca[i]) * t)) for i in range(3))


def _paint(root: tk.Misc, w: int, h: int, bg: str, shade, ss: int = 4) -> tk.PhotoImage:
    """Render shade(x, y) -> '#rrggbb' | None into a w x h image, 4x4 supersampled, None meaning the background."""
    img = tk.PhotoImage(master=root, width=w, height=h)
    bgc = _rgb(bg)
    rows = []
    for y in range(h):
        row = []
        for x in range(w):
            r = g = b = 0.0
            for j in range(ss):
                for i in range(ss):
                    c = shade(x + (i + .5) / ss, y + (j + .5) / ss)
                    c = _rgb(c) if c else bgc
                    r += c[0]
                    g += c[1]
                    b += c[2]
            n = ss * ss
            row.append("#%02x%02x%02x" % (int(r / n + .5), int(g / n + .5), int(b / n + .5)))
        rows.append("{" + " ".join(row) + "}")
    img.put(" ".join(rows))
    return img


def _disc(cx: float, cy: float, layers: list):
    """shade function: concentric discs, outermost first; the last layer containing the point wins."""
    def shade(x, y):
        d2 = (x - cx) ** 2 + (y - cy) ** 2
        out = None
        for r, col in layers:
            if d2 <= r * r:
                out = col
        return out
    return shade


_check_ids = [0]


def _install_check_indicators(s, root, p: dict, px) -> None:
    """Check boxes that show a real check mark (the stock theme draws a cross), in both themes, with focus/disabled states."""
    size = max(14, px(16))
    _check_ids[0] += 1
    keep = getattr(root, "_lp_check_imgs", None)
    if keep is None:
        keep = root._lp_check_imgs = []

    def seg_d(x, y, a, b):
        ax, ay = a
        bx, by = b
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
        return ((x - ax - t * dx) ** 2 + (y - ay - t * dy) ** 2) ** 0.5

    pts = [(size * .24, size * .54), (size * .43, size * .72), (size * .78, size * .30)]
    half, rad, bw = size / 2.0, size * 0.22, max(1.3, size * 0.09)

    def inside(x, y, inset):
        dx = max(abs(x - half) - (half - inset - rad), 0)
        dy = max(abs(y - half) - (half - inset - rad), 0)
        return dx * dx + dy * dy <= rad * rad

    def make(bg, checked, disabled=False, focus=False):
        border = p["accent"] if focus else (p["border"] if disabled else p["muted"])
        fill = p["code"] if disabled else (p["accent"] if checked else p["field"])
        mark = p["muted"] if disabled else p["accent_fg"]

        def shade(x, y):
            if not inside(x, y, 0.4):
                return None
            if checked and (seg_d(x, y, pts[0], pts[1]) <= size * .065 or seg_d(x, y, pts[1], pts[2]) <= size * .065):
                return mark
            if not inside(x, y, 0.4 + bw):
                return border
            return fill
        img = _paint(root, size, size, bg, shade)
        keep.append(img)
        return img

    for pref, bg in (("T", p["bg"]), ("Card.T", p["panel"])):
        el = f"Chk{_check_ids[0]}{pref[0]}{'c' if pref != 'T' else ''}.indicator"
        s.element_create(el, "image", make(bg, False),
                         ("disabled", "selected", make(bg, True, disabled=True)), ("disabled", make(bg, False, disabled=True)),
                         ("selected", "focus", make(bg, True, focus=True)), ("selected", make(bg, True)),
                         ("focus", make(bg, False, focus=True)), sticky="w")
        s.layout(f"{pref}Checkbutton", [("Checkbutton.padding", {"sticky": "nswe", "children": [
            (el, {"side": "left", "sticky": ""}),
            ("Checkbutton.focus", {"side": "left", "sticky": "w", "children": [("Checkbutton.label", {"sticky": "nswe"})]})]})])


_scale_ids = [0]


def install_scale_styles(root: tk.Misc, s: ttk.Style, p: dict) -> None:
    """Replace Tk's striped slider handle: a round accent handle in a panel-coloured ring on a rounded track.
    Hover, pressed, keyboard focus and disabled each have their own image; sized for the screen density."""
    f = dpi_factor(root)
    D = int(round(30 * f)) // 2 * 2 or 30                       # image edge (even), handle diameter about 22*f
    c = D / 2.0
    k = D / 30.0
    keep = root.__dict__.setdefault("_lp_scale_imgs", [])
    for pref, bg in (("", p["bg"]), ("Card.", p["panel"])):
        _scale_ids[0] += 1
        uid = f"lp{_scale_ids[0]}"

        def handle(dot: float, ring: bool = False, dim: bool = False, bg: str = bg):
            acc = p["muted"] if dim else p["accent"]
            layers = []
            if ring:
                layers += [(14.2 * k, p["fg"]), (12.4 * k, bg)]
            layers += [(11 * k, acc), (9.8 * k, bg if not dim else p["panel"]), (dot * k, acc)]
            return _paint(root, D, D, bg, _disc(c, c, layers))
        normal, hover, press = handle(6.8), handle(8.2), handle(5.6)
        focus, dis = handle(6.8, ring=True), handle(6.0, dim=True)
        th = max(6, int(round(8 * f)) // 2 * 2)
        tw = th * 4
        edge = _mix(p["panel"], p["muted"], .55)
        r = th / 2.0

        def trough(x, y, tw=tw, th=th, r=r, edge=edge):
            def inside(rad):
                cx = min(max(x, r), tw - r)
                return (x - cx) ** 2 + (y - r) ** 2 <= rad * rad
            if inside(r):
                return p["code"] if inside(r - max(1.0, f * .9)) else edge
            return None
        tr = _paint(root, tw, th, bg, trough)
        keep.extend([normal, hover, press, focus, dis, tr])
        sl_name, tr_name = f"{uid}.Horizontal.Scale.slider", f"{uid}.Horizontal.Scale.trough"
        s.element_create(sl_name, "image", normal, ("disabled", dis), ("pressed", press), ("focus", focus),
                         ("active", hover), sticky="")
        s.element_create(tr_name, "image", tr, border=(int(r) + 1, 0, int(r) + 1, 0), sticky="ew")
        s.layout(f"{pref}Horizontal.TScale", [(tr_name, {"sticky": "nswe", "children": [
            (sl_name, {"side": "left", "sticky": ""})]})])


# ── tooltips ────────────────────────────────────────────────────────────────
class Tooltip:
    """A small hint that appears after the pointer rests on a widget (or the widget gets keyboard focus)."""
    app = None

    def __init__(self, widget: tk.Misc, text: str, delay: int = 550):
        self.widget, self.text, self.delay, self.tip, self._job = widget, text, delay, None, None
        widget.bind("<Enter>", self._arm, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")
        widget.bind("<FocusIn>", self._arm, add="+")
        widget.bind("<FocusOut>", self._hide, add="+")
        widget.bind("<Escape>", self._hide, add="+")
        widget.bind("<Destroy>", self._hide, add="+")

    def _arm(self, _e=None) -> None:
        self._hide()
        self._job = self.widget.after(self.delay, self._show)

    def _show(self) -> None:
        if not self.text or self.tip is not None:
            return
        pal = Tooltip.app.pal if Tooltip.app else {"panel": "#fff", "fg": "#000", "border": "#999"}
        try:
            x = self.widget.winfo_rootx() + 12
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
            self.tip = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(True)
            tw.configure(bg=pal["border"])                 # a 1px hairline frame around the hint
            lb = tk.Label(tw, text=self.text, justify="left", wraplength=340, bg=pal["panel"], fg=pal["fg"],
                          relief="flat", borderwidth=0, padx=10, pady=6, highlightthickness=0)
            lb.pack(padx=1, pady=1)
            tw.update_idletasks()
            x = max(0, min(x, self.widget.winfo_screenwidth() - tw.winfo_reqwidth() - 4))
            if y + tw.winfo_reqheight() > self.widget.winfo_screenheight() - 4:      # no room below: show above
                y = max(0, self.widget.winfo_rooty() - tw.winfo_reqheight() - 6)
            tw.wm_geometry(f"+{x}+{y}")
        except tk.TclError:
            self.tip = None

    def _hide(self, _e=None) -> None:
        if self._job:
            try:
                self.widget.after_cancel(self._job)
            except tk.TclError:
                pass
            self._job = None
        if self.tip is not None:
            try:
                self.tip.destroy()
            except tk.TclError:
                pass
            self.tip = None


def tip(widget, text: str):
    if text:
        Tooltip(widget, text)
    return widget


# ── theme ───────────────────────────────────────────────────────────────────
def init_fonts(root: tk.Misc) -> dict:
    from tkinter import font as tkfont
    base = tkfont.nametofont("TkDefaultFont")
    size = base.cget("size")
    if 0 < size < 10:                                  # readable by default; follows the OS above that
        base.configure(size=10)
        size = 10
    sign = 1 if size > 0 else -1
    mag = abs(size)

    def derive(factor, **kw):
        f = base.copy()
        f.configure(size=sign * max(8, int(round(mag * factor))), **kw)
        return f
    mono = tkfont.nametofont("TkFixedFont")
    mono.configure(size=sign * max(9, mag))
    return {"base": base, "bold": derive(1.0, weight="bold"), "small": derive(0.9), "h1": derive(1.55, weight="bold"),
            "h2": derive(1.15, weight="bold"), "kpi": derive(1.9, weight="bold"), "mono": mono,
            "title": derive(0.88, weight="bold")}


def apply_theme(root: tk.Misc, s: ttk.Style, p: dict, fonts: dict) -> None:
    root.configure(bg=p["bg"])
    s.configure(".", background=p["bg"], foreground=p["fg"], fieldbackground=p["field"], bordercolor=p["border"],
                lightcolor=p["panel"], darkcolor=p["panel"], troughcolor=p["code"], focuscolor=p["accent"],
                font=fonts["base"], selectbackground=p["select"], selectforeground=p["fg"])
    for name, bg in (("TFrame", p["bg"]), ("Card.TFrame", p["panel"]), ("CardBody.TFrame", p["panel"]),
                     ("Header.TFrame", p["panel"]), ("Tone.TFrame", p["code"])):
        s.configure(name, background=bg)
    s.configure("Card.TFrame", relief="solid", borderwidth=1, bordercolor=p["border"], lightcolor=p["border"],
                darkcolor=p["border"])
    s.configure("TLabel", background=p["bg"], foreground=p["fg"])
    for pref, bg in (("Card", p["panel"]), ("Header", p["panel"])):
        s.configure(f"{pref}.TLabel", background=bg, foreground=p["fg"])
        s.configure(f"{pref}Muted.TLabel", background=bg, foreground=p["muted"], font=fonts["small"])
    s.configure("Muted.TLabel", foreground=p["muted"], font=fonts["small"])
    s.configure("Strong.TLabel", font=fonts["bold"])
    s.configure("H1.TLabel", font=fonts["h1"])
    s.configure("H2.TLabel", font=fonts["h2"])
    s.configure("CardH2.TLabel", background=p["panel"], font=fonts["h2"])
    s.configure("HeaderH1.TLabel", background=p["panel"], font=fonts["h1"])
    s.configure("CardTitle.TLabel", background=p["panel"], foreground=p["muted"], font=fonts["title"])
    s.configure("KPI.TLabel", background=p["panel"], foreground=p["fg"], font=fonts["kpi"])
    s.configure("Code.TLabel", background=p["code"], foreground=p["fg"], font=fonts["mono"], padding=(6, 3))
    for tone in ("ok", "warn", "bad", "info", "tor", "off"):
        fg = {"ok": p["ok"], "warn": p["warn"], "bad": p["bad"], "info": p["info"], "tor": p["tor"], "off": p["muted"]}[tone]
        bg = {"ok": p["ok_bg"], "warn": p["warn_bg"], "bad": p["bad_bg"], "info": p["info_bg"], "tor": p["tor_bg"],
              "off": p["code"]}[tone]
        s.configure(f"Pill{tone}.TLabel", background=bg, foreground=fg, padding=(10, 3), font=fonts["bold"])
        s.configure(f"Note{tone}.TLabel", background=bg, foreground=p["fg"], padding=(10, 7))
        s.configure(f"Tone{tone}.TLabel", background=p["panel"], foreground=fg)
    # buttons: secondary (default), primary, danger, ghost
    fx = dpi_factor(root)

    def px(n):                                                   # paddings follow the screen density
        return int(round(n * fx))

    # secondary buttons: card-coloured fill with an accent outline and accent text (not flat grey)
    fill, fill_hi, fill_lo = p["panel"], _mix(p["panel"], p["accent"], .14), _mix(p["panel"], p["accent"], .26)
    s.configure("TButton", background=fill, foreground=p["accent"], padding=(px(12), px(6)), borderwidth=1, width=0,
                relief="flat", bordercolor=p["accent"], lightcolor=fill, darkcolor=fill, focuscolor=fill,
                focusthickness=0)
    s.map("TButton", background=[("disabled", p["bg"]), ("pressed", fill_lo), ("active", fill_hi)],
          foreground=[("disabled", p["muted"])], lightcolor=[("pressed", fill_lo), ("active", fill_hi)],
          darkcolor=[("pressed", fill_lo), ("active", fill_hi)],
          bordercolor=[("disabled", p["border"]), ("focus", p["fg"])])
    acc_hi, acc_lo = _mix(p["accent"], p["fg"], .12), _mix(p["accent"], p["fg"], .22)
    s.configure("Primary.TButton", background=p["accent"], foreground=p["accent_fg"], bordercolor=p["accent"],
                lightcolor=p["accent"], darkcolor=p["accent"], font=fonts["bold"], focuscolor=p["accent"])
    s.map("Primary.TButton", background=[("disabled", p["code"]), ("pressed", acc_lo), ("active", acc_hi)],
          lightcolor=[("pressed", acc_lo), ("active", acc_hi)], darkcolor=[("pressed", acc_lo), ("active", acc_hi)],
          foreground=[("disabled", p["muted"])], bordercolor=[("disabled", p["border"]), ("focus", p["fg"])])
    s.configure("Danger.TButton", foreground=p["bad"], bordercolor=p["bad"])
    s.map("Danger.TButton", background=[("disabled", p["bg"]), ("pressed", p["bad_bg"]), ("active", p["bad_bg"])],
          lightcolor=[("active", p["bad_bg"])], darkcolor=[("active", p["bad_bg"])],
          foreground=[("disabled", p["muted"])], bordercolor=[("disabled", p["border"]), ("focus", p["fg"])])
    s.configure("Tor.TButton", background=p["tor"], foreground=p["accent_fg"],
                bordercolor=p["tor"], lightcolor=p["tor"], darkcolor=p["tor"], font=fonts["bold"], focuscolor=p["tor"])
    s.map("Tor.TButton", background=[("disabled", p["code"]), ("active", _mix(p["tor"], p["fg"], .12))],
          foreground=[("disabled", p["muted"])], bordercolor=[("disabled", p["border"]), ("focus", p["fg"])])
    s.configure("Ghost.TButton", background=p["bg"], foreground=p["muted"], borderwidth=0, padding=(px(10), px(5)),
                lightcolor=p["bg"], darkcolor=p["bg"], bordercolor=p["bg"])
    s.map("Ghost.TButton", background=[("active", p["hover"])], foreground=[("active", p["fg"])],
          bordercolor=[("focus", p["accent"])], lightcolor=[("active", p["hover"])], darkcolor=[("active", p["hover"])])
    s.configure("Link.TButton", background=p["panel"], foreground=p["info"], borderwidth=0, padding=(2, 2),
                lightcolor=p["panel"], darkcolor=p["panel"], bordercolor=p["panel"])
    s.map("Link.TButton", foreground=[("active", p["accent"])], background=[("active", p["panel"])],
          bordercolor=[("focus", p["accent"])])
    s.configure("Seg.TButton", background=p["bg"], foreground=p["muted"], borderwidth=1, padding=(px(12), px(4)),
                lightcolor=p["bg"], darkcolor=p["bg"])
    s.map("Seg.TButton", background=[("active", p["hover"])], foreground=[("active", p["fg"])],
          bordercolor=[("focus", p["accent"])])
    for w in ("Check", "Radio"):
        for pref, bg in (("T", p["bg"]), ("Card.T", p["panel"])):
            name = f"{pref}{w}button"
            s.configure(name, background=bg, foreground=p["fg"], indicatorcolor=p["field"], indicatormargin=(0, 2, 6, 2),
                        focuscolor=p["accent"], bordercolor=p["muted"], padding=(2, 2), upperbordercolor=p["muted"],
                        lowerbordercolor=p["muted"], indicatorbackground=p["field"], indicatorforeground=p["accent_fg"])
            s.map(name, background=[("active", bg)], indicatorcolor=[("selected", p["accent"]), ("pressed", p["accent"])],
                  indicatorbackground=[("selected", p["accent"]), ("pressed", p["accent"]), ("disabled", p["code"])],
                  foreground=[("disabled", p["muted"])], bordercolor=[("focus", p["accent"])],
                  upperbordercolor=[("focus", p["accent"])], lowerbordercolor=[("focus", p["accent"])])
    s.configure("TNotebook", background=p["bg"], borderwidth=0, tabmargins=(px(8), px(6), px(8), 0), lightcolor=p["bg"],
                darkcolor=p["bg"], bordercolor=p["border"])
    s.configure("TNotebook.Tab", background=p["bg"], foreground=p["muted"], padding=(px(9), px(8)), borderwidth=1,
                bordercolor=p["bg"], lightcolor=p["bg"], darkcolor=p["bg"], focuscolor=p["accent"])
    s.map("TNotebook.Tab", background=[("selected", p["panel"]), ("active", p["hover"])],
          foreground=[("selected", p["fg"]), ("active", p["fg"])], expand=[("selected", (0, 0, 0, 0))],
          padding=[("selected", (px(9), px(8)))], bordercolor=[("selected", p["border"]), ("focus", p["accent"])],
          lightcolor=[("selected", p["accent"])], darkcolor=[("selected", p["panel"])])
    s.configure("TLabelframe", background=p["bg"], bordercolor=p["border"])
    s.configure("TLabelframe.Label", background=p["bg"], foreground=p["muted"], font=fonts["bold"])
    s.configure("TSeparator", background=p["border"])
    s.configure("Treeview", background=p["panel"], fieldbackground=p["panel"], foreground=p["fg"], borderwidth=0,
                rowheight=max(24, int(abs(fonts["base"].cget("size")) * 2.1)))
    s.configure("Treeview.Heading", background=p["code"], foreground=p["muted"], font=fonts["bold"], relief="flat",
                padding=(6, 5))
    s.map("Treeview", background=[("selected", p["select"])], foreground=[("selected", p["fg"])])
    s.map("Treeview.Heading", background=[("active", p["hover"])])
    s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    for w in ("TEntry", "TSpinbox", "TCombobox"):
        s.configure(w, fieldbackground=p["field"], foreground=p["fg"], bordercolor=p["border"], lightcolor=p["field"],
                    darkcolor=p["field"], padding=4, insertcolor=p["fg"])
        s.map(w, bordercolor=[("focus", p["accent"])], lightcolor=[("focus", p["accent"])])
    s.configure("TSpinbox", arrowcolor=p["fg"])
    s.configure("TCombobox", arrowcolor=p["fg"], background=p["panel"])
    s.map("TCombobox", fieldbackground=[("readonly", p["field"])], foreground=[("readonly", p["fg"])],
          selectbackground=[("readonly", p["field"])], selectforeground=[("readonly", p["fg"])])
    thumb, thumb_hi = _mix(p["bg"], p["fg"], .40), _mix(p["bg"], p["fg"], .58)       # clearly visible at rest
    trough = _mix(p["bg"], p["fg"], .09)
    s.configure("TScrollbar", background=thumb, troughcolor=trough, arrowcolor=p["fg"], bordercolor=trough,
                lightcolor=thumb, darkcolor=thumb, arrowsize=px(15))
    s.map("TScrollbar", background=[("pressed", p["accent"]), ("active", thumb_hi)],
          lightcolor=[("pressed", p["accent"]), ("active", thumb_hi)], darkcolor=[("pressed", p["accent"]), ("active", thumb_hi)])
    _install_check_indicators(s, root, p, px)
    s.configure("TProgressbar", background=p["accent"], troughcolor=p["code"], bordercolor=p["code"],
                lightcolor=p["accent"], darkcolor=p["accent"], thickness=9)
    s.configure("Tor.Horizontal.TProgressbar", background=p["tor"])
    for pref, bg in (("", p["bg"]), ("Card.", p["panel"])):
        s.configure(f"{pref}Horizontal.TScale", background=bg, troughcolor=p["code"], bordercolor=p["border"],
                    lightcolor=p["accent"], darkcolor=p["accent"])
        s.map(f"{pref}Horizontal.TScale", background=[("active", bg)])
    try:
        install_scale_styles(root, s, p)
    except tk.TclError:                                           # a Tk build without image elements: keep the default handle
        pass
    root.option_add("*TCombobox*Listbox.background", p["field"])
    root.option_add("*TCombobox*Listbox.foreground", p["fg"])
    root.option_add("*TCombobox*Listbox.selectBackground", p["select"])
    root.option_add("*TCombobox*Listbox.selectForeground", p["fg"])
    root.option_add("*TCombobox*Listbox.font", fonts["base"])


# ── shared widgets ─────────────────────────────────────────────────────────
def autowrap(label: tk.Misc, host: tk.Misc | None = None, margin: int = 8) -> tk.Misc:
    """Keep a label's wrap width equal to its container's width."""
    host = host or label.master

    def fit(_e=None):
        try:
            label.configure(wraplength=max(160, host.winfo_width() - margin))
        except tk.TclError:
            pass
    host.bind("<Configure>", fit, add="+")
    return label


class ScrollFrame(ttk.Frame):
    """A vertically scrolling page; put widgets in .inner. Follows the mouse wheel while the pointer is over it."""

    def __init__(self, master, app, padding=(18, 14)):
        super().__init__(master)
        self.app = app
        self.canvas = tk.Canvas(self, highlightthickness=0, bd=0)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.vsb.pack(side="right", fill="y")
        self.inner = ttk.Frame(self.canvas, padding=padding)
        self._win = self.canvas.create_window(0, 0, window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._win, width=e.width))
        for w in (self.canvas, self.inner):
            w.bind("<Enter>", self._bind_wheel)
            w.bind("<Leave>", self._unbind_wheel)

    def _bind_wheel(self, _e=None) -> None:
        r = self.winfo_toplevel()
        r.bind_all("<MouseWheel>", self._wheel)
        r.bind_all("<Button-4>", lambda _e: self.canvas.yview_scroll(-3, "units"))
        r.bind_all("<Button-5>", lambda _e: self.canvas.yview_scroll(3, "units"))

    def _unbind_wheel(self, _e=None) -> None:
        r = self.winfo_toplevel()
        for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            r.unbind_all(ev)

    def _wheel(self, e) -> None:
        step = -e.delta if sys.platform == "darwin" else -(e.delta // 120)
        self.canvas.yview_scroll(step * (1 if sys.platform == "darwin" else 3), "units")

    def scroll_to(self, widget: tk.Misc) -> None:
        self.update_idletasks()
        total = max(1, self.inner.winfo_height())
        self.canvas.yview_moveto(max(0.0, (widget.winfo_y() - 6) / total))

    def retheme(self) -> None:
        self.canvas.configure(bg=self.app.pal["bg"])


class Card(ttk.Frame):
    """A titled panel: header (icon, title, optional help tooltip), a thin separator, then .body for content."""

    def __init__(self, master, app, title: str, icon: str | None = None, help: str = "", pad: int = 16):
        super().__init__(master, style="Card.TFrame")
        self.app = app
        head = ttk.Frame(self, style="CardBody.TFrame", padding=(pad, 11, pad, 8))
        head.pack(fill="x")
        self.icon_lbl = None
        if icon:
            self.icon_lbl = ttk.Label(head, style="Card.TLabel", image=app.icon(icon, "muted"))
            self.icon_lbl.pack(side="left", padx=(0, 7))
            app.track_icon(self.icon_lbl, icon, "muted")
        ttk.Label(head, text=title.upper(), style="CardTitle.TLabel").pack(side="left")
        if help:
            h = ttk.Label(head, text=" ⓘ", style="CardMuted.TLabel", cursor="question_arrow")
            h.pack(side="left")
            tip(h, help)
        self.actions = ttk.Frame(head, style="CardBody.TFrame")
        self.actions.pack(side="right")
        ttk.Separator(self, orient="horizontal").pack(fill="x")
        self.body = ttk.Frame(self, style="CardBody.TFrame", padding=(pad, 10, pad, 14))
        self.body.pack(fill="both", expand=True)
        self.body.columnconfigure(0, weight=1)

    # -- content helpers (all use the card's panel colour)
    def note(self, text: str, muted: bool = True, pady=(0, 6)) -> ttk.Label:
        lb = ttk.Label(self.body, text=text, style="CardMuted.TLabel" if muted else "Card.TLabel", justify="left")
        lb.pack(fill="x", anchor="w", pady=pady)
        autowrap(lb, self.body, 4)
        return lb

    def heading(self, text: str, hint: str = "") -> None:
        f = ttk.Frame(self.body, style="CardBody.TFrame")
        f.pack(fill="x", pady=(8, 2))
        ttk.Label(f, text=text, style="Card.TLabel", font=self.app.fonts["bold"]).pack(side="left")
        if hint:
            ttk.Label(f, text="  " + hint, style="CardMuted.TLabel").pack(side="left")

    def row(self, pady=(2, 2)) -> ttk.Frame:
        f = ttk.Frame(self.body, style="CardBody.TFrame")
        f.pack(fill="x", pady=pady)
        return f

    def check(self, var, text: str, hint: str = "", command=None, tooltip: str = "") -> ttk.Checkbutton:
        cb = ttk.Checkbutton(self.body, text=text, variable=var, style="Card.TCheckbutton", command=command)
        cb.pack(anchor="w", pady=(3, 0))
        tip(cb, tooltip)
        if hint:
            h = ttk.Label(self.body, text=hint, style="CardMuted.TLabel", justify="left")
            h.pack(fill="x", anchor="w", padx=(24, 0))
            autowrap(h, self.body, 30)
        return cb

    def radio(self, var, value, text: str, hint: str = "", command=None) -> ttk.Radiobutton:
        rb = ttk.Radiobutton(self.body, text=text, value=value, variable=var, style="Card.TRadiobutton", command=command)
        rb.pack(anchor="w", pady=(3, 0))
        if hint:
            h = ttk.Label(self.body, text=hint, style="CardMuted.TLabel", justify="left")
            h.pack(fill="x", anchor="w", padx=(24, 0))
            autowrap(h, self.body, 30)
        return rb

    @staticmethod
    def lbl(parent, text: str, muted: bool = False) -> ttk.Label:
        return ttk.Label(parent, text=text, style="CardMuted.TLabel" if muted else "Card.TLabel")


def pill(parent, text: str, tone: str = "off") -> ttk.Label:
    return ttk.Label(parent, text=text, style=f"Pill{tone}.TLabel")


def set_pill(label: ttk.Label, text: str, tone: str) -> None:
    label.configure(text=text, style=f"Pill{tone}.TLabel")


class Banner(ttk.Label):
    """A tinted one-paragraph message (info / warn / bad / ok / tor)."""

    def __init__(self, master, text: str = "", tone: str = "info", host: tk.Misc | None = None):
        super().__init__(master, text=text, style=f"Note{tone}.TLabel", justify="left")
        autowrap(self, host or master, 8)


class Sparkline(tk.Canvas):
    """A small filled line chart of the last N values, drawn on a canvas. Redraws are coalesced and skipped when
    nothing changed, so a once-a-second refresh does not flicker."""

    def __init__(self, master, app, height=70):
        super().__init__(master, height=height, highlightthickness=0, bd=0)
        self.app, self.values, self.unit = app, [], " / min"
        self._job, self._sig = None, None
        self.bind("<Configure>", lambda _e: self._soon())

    def set_values(self, values: list[float]) -> None:
        values = list(values)
        if values != self.values:
            self.values = values
            self._soon()

    def _soon(self) -> None:
        if self._job is None:
            self._job = self.after_idle(self._run)

    def _run(self) -> None:
        self._job = None
        self.redraw()

    def redraw(self, force: bool = False) -> None:
        p = self.app.pal
        w, h = self.winfo_width(), self.winfo_height()
        sig = (tuple(self.values), w, h, p["panel"], p["ok"])
        if sig == self._sig and not force:
            return
        self._sig = sig
        self.delete("all")
        self.configure(bg=p["panel"])
        if w < 20:
            return
        for k in (0.25, 0.5, 0.75):
            y = int(h * k) + .5                                   # half-pixel offsets keep 1px lines crisp
            self.create_line(0, y, w, y, fill=p["grid"])
        vals = self.values
        if not vals or not any(vals):
            self.create_text(w / 2, h / 2, text="No hits yet in the last 30 minutes", fill=p["muted"],
                             font=self.app.fonts["small"])
            return
        top = max(max(vals), 1)
        n = len(vals)
        pts = [(4 + i * (w - 8) / max(1, n - 1), h - 6 - (v / top) * (h - 14)) for i, v in enumerate(vals)]
        self.create_polygon([4, h - 6] + [c for pt in pts for c in pt] + [w - 4, h - 6], fill=p["ok_bg"], outline="")
        self.create_line(*[c for pt in pts for c in pt], fill=p["ok"], width=2, smooth=True, capstyle="round",
                         joinstyle="round")
        self.create_line(4, h - 5.5, w - 4, h - 5.5, fill=p["border"])
        ex, ey = pts[-1]
        self.create_oval(ex - 3, ey - 3, ex + 3, ey + 3, fill=p["ok"], outline=p["panel"], width=1)
        self.create_text(w - 6, 8, text=f"peak {top:g}{self.unit}", anchor="e", fill=p["muted"], font=self.app.fonts["small"])


def swatch(canvas: tk.Canvas, x: float, y: float, r: float, color: str, shape: int = 0, outline: str = "") -> None:
    """A small legend marker whose SHAPE differs per series (circle, square, diamond, triangle, hexagon), so a
    series is never told apart by colour alone."""
    k = shape % 5
    if k == 0:
        canvas.create_oval(x - r, y - r, x + r, y + r, fill=color, outline=outline)
    elif k == 1:
        canvas.create_rectangle(x - r * .85, y - r * .85, x + r * .85, y + r * .85, fill=color, outline=outline)
    elif k == 2:
        canvas.create_polygon(x, y - r * 1.15, x + r * 1.15, y, x, y + r * 1.15, x - r * 1.15, y, fill=color, outline=outline)
    elif k == 3:
        canvas.create_polygon(x, y - r, x + r * 1.1, y + r * .85, x - r * 1.1, y + r * .85, fill=color, outline=outline)
    else:
        canvas.create_polygon(x - r * .55, y - r * .95, x + r * .55, y - r * .95, x + r, y, x + r * .55, y + r * .95,
                              x - r * .55, y + r * .95, x - r, y, fill=color, outline=outline)


def _ink_on(color: str) -> str:
    """Black or white text, whichever reads better on this fill (WCAG contrast)."""
    def lin(c):
        c /= 255.0
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = _rgb(color)
    lum = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
    return "#ffffff" if 1.05 / (lum + 0.05) >= 4.5 else "#10141c"


class MixBar(ttk.Frame):
    """A stacked bar of coloured parts with one slider per part. The parts always add up to 100%: dragging one
    makes the others give or take the difference in proportion; 0% turns a part off. The bar is drawn with
    rounded ends and names the wide parts directly; each legend swatch has its own shape."""

    BAR_H = 30

    def __init__(self, master, app, items: list[dict], on_change=None):
        super().__init__(master, style="CardBody.TFrame")
        self.app, self.on_change, self.items = app, on_change, []
        self.vals: list[float] = []
        self._busy = False
        self._job = None
        h = int(self.BAR_H * app.scale)
        self.bar = tk.Canvas(self, height=h, highlightthickness=0, bd=0)
        self.bar.pack(fill="x", pady=(2, 8))
        self.bar.bind("<Configure>", lambda _e: self._soon())
        self.grid_f = ttk.Frame(self, style="CardBody.TFrame")
        self.grid_f.pack(fill="x")
        self.grid_f.columnconfigure(1, minsize=int(170 * app.scale))
        self.grid_f.columnconfigure(2, weight=1)
        self.set_items(items)

    def set_items(self, items: list[dict]) -> None:
        for w in self.grid_f.winfo_children():
            w.destroy()
        self.items = items
        self.vals = F.mix_normalize([i.get("value", 0) for i in items])
        self.scales, self.vars, self.pcts, self.dots = [], [], [], []
        for k, it in enumerate(items):
            col = MIX_COLORS[k % len(MIX_COLORS)]
            dot = tk.Canvas(self.grid_f, width=16, height=16, highlightthickness=0, bd=0, bg=self.app.pal["panel"])
            swatch(dot, 8, 8, 6, col, k)
            dot.grid(row=k, column=0, padx=(0, 6), pady=3)
            self.dots.append(dot)
            lb = ttk.Label(self.grid_f, text=it["label"], style="Card.TLabel")
            lb.grid(row=k, column=1, sticky="w")
            var = tk.DoubleVar(value=self.vals[k])
            sc = ttk.Scale(self.grid_f, from_=0, to=100, orient="horizontal", variable=var, style="Card.Horizontal.TScale",
                           command=lambda v, k=k: self._moved(k, v))
            sc.grid(row=k, column=2, sticky="ew", padx=8)
            pc = ttk.Label(self.grid_f, text="", style="Card.TLabel", width=6, anchor="e", font=self.app.fonts["bold"])
            pc.grid(row=k, column=3)
            if it.get("hint"):
                hl = ttk.Label(self.grid_f, text=it["hint"], style="CardMuted.TLabel")
                hl.grid(row=k, column=4, sticky="w", padx=(8, 0))
            tip(sc, f"{it['label']}: drag (or use the arrow keys) to change; the others make room so the total stays 100%. 0% turns it off.")
            self.scales.append(sc)
            self.vars.append(var)
            self.pcts.append(pc)
        self._paint()

    def _moved(self, k: int, v) -> None:
        if self._busy:
            return
        self.vals = F.mix_adjust(self.vals, k, float(v))
        self._paint()
        if self.on_change:
            self.on_change()

    def _paint(self) -> None:
        self._busy = True
        try:
            for k, v in enumerate(self.vals):
                self.vars[k].set(v)
                self.pcts[k].configure(text=F.mix_percent_text(v))
        finally:
            self._busy = False
        self._soon()

    def _soon(self) -> None:
        """Coalesce redraws: many slider events per frame cost one repaint."""
        if self._job is None:
            self._job = self.after_idle(self._run)

    def _run(self) -> None:
        self._job = None
        self._draw()

    def _draw(self) -> None:
        c, p = self.bar, self.app.pal
        w, h = c.winfo_width(), int(self.BAR_H * self.app.scale)
        if w < 20:
            return
        c.delete("all")
        c.configure(bg=p["panel"])
        r = h / 2.0
        # a rounded track, then the parts clipped to it by painting panel-coloured corners over the ends
        parts, x = [], 0.0
        for k, v in enumerate(self.vals):
            wd = (w - 1) * v / 100.0
            if wd > 0.5:
                parts.append((k, x, x + wd))
                x += wd
        for k, xa, xb in parts:
            col = MIX_COLORS[k % len(MIX_COLORS)]
            c.create_rectangle(xa + (1 if xa else 0), 1, xb, h - 1, fill=col, outline="")
        for k, xa, xb in parts:
            wd = xb - xa
            label = self.items[k]["label"]
            txt = F.mix_percent_text(self.vals[k])
            if wd > 150:
                txt = f"{label}  {txt}"
            elif wd <= 40:
                continue
            c.create_text((xa + xb) / 2, h / 2, text=txt, fill=_ink_on(MIX_COLORS[k % len(MIX_COLORS)]), font=self.app.fonts["bold"])
        steps = 14
        for cx, sgn in ((r, 1), (w - 1 - r, -1)):                       # round both ends
            for side_y in (1, -1):
                poly = [cx - sgn * r, h / 2 + side_y * r]               # the square corner, then along the arc
                for i in range(steps + 1):
                    a = math.pi / 2 * i / steps
                    poly += [cx - sgn * r * math.cos(a), h / 2 + side_y * r * math.sin(a)]
                c.create_polygon(poly, fill=p["panel"], outline="")

    def values(self) -> dict:
        return {it["key"]: round(self.vals[k], 1) for k, it in enumerate(self.items)}

    def set_values(self, values: dict) -> None:
        self.vals = F.mix_normalize([values.get(it["key"], 0) for it in self.items])
        self._paint()

    def retheme(self) -> None:
        for d in self.dots:
            d.configure(bg=self.app.pal["panel"])
        self._draw()
