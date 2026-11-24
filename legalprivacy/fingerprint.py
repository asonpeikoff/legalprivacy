"""Browser fingerprint variation for the clearnet browser lane (not Tor Browser: see window_size()).

A fingerprint that never changes is itself an identifier, but one that changes on every page is a tell too. So the
values here come from one random seed that lasts 8-24 hours (saved in the app folder) and then rotates:

  - canvas: tiny per-seed noise on pixel reads (toDataURL, toBlob, getImageData)
  - WebGL: a plausible vendor/renderer pair per seed, and noise on readPixels
  - fonts: which uncommon fonts report as installed (document.fonts.check) differs per seed
  - audio: tiny noise on analyser/channel data
  - hardwareConcurrency and deviceMemory: plausible values per seed
  - window size: a non-maximised size per seed (never the screen's full size), nudged by a few pixels each time

Tor Browser is left alone on purpose: it already makes every user look the same, and a script (or an extension)
that changed its values would be the one thing that told your session apart. For it only the window size varies
(Tor Browser rounds it to standard steps, so the real size is not exposed)."""
from __future__ import annotations

import json
import random
import time

from .paths import app_dir

GPUS = [("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)")]
FONTS = ["Calibri", "Cambria", "Candara", "Consolas", "Constantia", "Corbel", "Segoe UI", "Tahoma", "Trebuchet MS",
         "Verdana", "Georgia", "Palatino Linotype", "Book Antiqua", "Century Gothic", "Franklin Gothic Medium",
         "Lucida Console", "Gill Sans MT", "Rockwell", "Garamond", "MS Gothic"]
SCREENS = [(1920, 1080), (2560, 1440), (1536, 864), (1440, 900), (1366, 768), (1680, 1050)]


def _state_path():
    return app_dir() / "fingerprint.json"


def seed_state(now: float | None = None, rng: random.Random | None = None) -> dict:
    """The current seed, rotated (with a new random lifetime of 8-24 hours) when it has run out."""
    now = now if now is not None else time.time()
    p = _state_path()
    try:
        st = json.loads(p.read_text(encoding="utf-8"))
        if st.get("until", 0) > now and "seed" in st:
            return st
    except Exception:
        pass
    r = rng or random.SystemRandom()
    st = {"seed": r.getrandbits(48), "until": now + r.uniform(8, 24) * 3600}
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(st), encoding="utf-8")
    except OSError:
        pass
    return st


def profile(seed: int) -> dict:
    r = random.Random(seed)
    return {"noise": r.randint(1, 2 ** 31 - 1), "gpu": r.choice(GPUS), "cores": r.choice([4, 6, 8, 8, 12, 16]),
            "memory": r.choice([4, 8, 8, 16]), "hidden_fonts": sorted(r.sample(FONTS, r.randint(5, 11)))}


def window_size(seed: int, screen: tuple[int, int] | None = None) -> tuple[int, int]:
    """A browser window that is never maximised (never the full screen) and stays the same for this seed."""
    r = random.Random(seed ^ 0x5EED)
    sw, sh = screen or r.choice(SCREENS)
    w = int(sw * r.uniform(0.62, 0.9)) // 8 * 8 + r.choice([0, 8, 16, 24])
    h = int(sh * r.uniform(0.62, 0.86)) // 8 * 8 + r.choice([0, 8, 16, 24])
    return min(w, sw - 40), min(h, sh - 80)


def init_script(seed: int) -> str:
    p = profile(seed)
    return ("(() => { const P = " + json.dumps(p) + ";\n" + """
let s = P.noise >>> 0; const rnd = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
const def = (o, k, v) => { try { Object.defineProperty(o, k, { get: () => v, configurable: true }); } catch (e) {} };
def(Navigator.prototype, 'hardwareConcurrency', P.cores); def(Navigator.prototype, 'deviceMemory', P.memory);
const flip = (d) => { for (let i = 0; i < d.length; i += 4 * 97) { d[i] = d[i] ^ (rnd() < 0.5 ? 1 : 0); } return d; };
const gid = CanvasRenderingContext2D.prototype.getImageData;
CanvasRenderingContext2D.prototype.getImageData = function (...a) { const r = gid.apply(this, a); flip(r.data); return r; };
for (const k of ['toDataURL', 'toBlob']) { const o = HTMLCanvasElement.prototype[k];
  HTMLCanvasElement.prototype[k] = function (...a) { try { const c = this.getContext('2d'); if (c && this.width && this.height) { const d = gid.call(c, 0, 0, Math.min(this.width, 16), Math.min(this.height, 16)); flip(d.data); c.putImageData(d, 0, 0); } } catch (e) {} return o.apply(this, a); }; }
for (const C of [window.WebGLRenderingContext, window.WebGL2RenderingContext]) { if (!C) continue;
  const gp = C.prototype.getParameter;
  C.prototype.getParameter = function (p) { if (p === 37445) return P.gpu[0]; if (p === 37446) return P.gpu[1]; return gp.call(this, p); };
  const rp = C.prototype.readPixels;
  C.prototype.readPixels = function (...a) { rp.apply(this, a); const b = a[6]; if (b && b.length) flip(b); }; }
if (window.AnalyserNode) { const f = AnalyserNode.prototype.getFloatFrequencyData;
  AnalyserNode.prototype.getFloatFrequencyData = function (arr) { f.call(this, arr); for (let i = 0; i < arr.length; i += 13) arr[i] += (rnd() - 0.5) * 1e-4; }; }
if (document.fonts && document.fonts.check) { const fc = document.fonts.check.bind(document.fonts);
  document.fonts.check = function (spec, text) { for (const f of P.hidden_fonts) { if (String(spec).includes(f)) return false; } return fc(spec, text); }; }
})();""")
