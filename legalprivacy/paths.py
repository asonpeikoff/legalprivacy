"""Filesystem locations: per-user app dir and bundled resources (PyInstaller-aware)."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def getenv(name: str, default: str | None = None) -> str | None:
    """LEGALPRIVACY_<name>, or the name it had before the rename (CRICKET_<name>)."""
    return os.environ.get(f"LEGALPRIVACY_{name}") or os.environ.get(f"CRICKET_{name}") or default


def app_dir() -> Path:
    """Per-user writable directory (config, managed Tor, browser cookies). Created on demand.
    An existing folder from before the rename (noisyCricket) keeps being used, so nothing is lost."""
    override = getenv("HOME")
    if override:
        base = Path(override)
    else:
        if sys.platform == "win32":
            parent = Path(os.environ.get("APPDATA", Path.home()))
            base, old = parent / "legalPrivacy", parent / "noisyCricket"
        else:
            base, old = Path.home() / ".legalprivacy", Path.home() / ".noisycricket"
        if not base.exists() and old.exists():
            base = old
    if not base.exists():
        base.mkdir(parents=True, exist_ok=True)
        try:
            base.chmod(0o700)                 # settings, tokens and saved sessions live here: owner only
        except OSError:
            pass
    return base


def write_private(path: Path, text: str) -> None:
    """Atomically write a text file that only its owner can read (0600 where the OS supports it)."""
    import threading
    path = Path(path)
    tmp = path.with_name(f"{path.name}.{threading.get_ident()}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        tmp.chmod(0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def ensure_utf8_console() -> None:
    """Windows consoles default to cp1252, which cannot print the symbols in our messages (a crash on the
    first print). Switch the standard streams to UTF-8 with replacement; harmless elsewhere and when a
    stream is missing (windowed launch) or already redirected."""
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None and (getattr(stream, "encoding", "") or "").lower().replace("-", "") != "utf8":
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def resource_root() -> Path:
    """Where bundled read-only files live (repo root, or PyInstaller's _MEIPASS)."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    return Path(__file__).resolve().parents[1]


def resolve_resource(rel: str) -> str:
    """Return an existing path for a possibly-relative resource (cwd first, then bundle)."""
    p = Path(rel)
    if p.is_absolute() or p.exists():
        return str(p)
    bundled = resource_root() / rel
    return str(bundled) if bundled.exists() else rel


def config_path() -> Path:
    return app_dir() / "config.yaml"


def tor_dir() -> Path:
    d = app_dir() / "tor"
    d.mkdir(parents=True, exist_ok=True)
    return d


def relay_dir() -> Path:
    """Where the optional relay keeps its own data (separate from the client Tor). Owner-only."""
    d = app_dir() / "relay"
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d
