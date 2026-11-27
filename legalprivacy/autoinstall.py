"""Install what the app needs by itself, instead of telling you to in the log.

  * "firefox" / "chromium": Playwright's own copy of the browser (the app drives that build; it cannot drive an ordinary
    Firefox). Your own Firefox is still the first choice, on a private copy of your profile (see realfirefox.py): this is only
    for when that cannot be used or a second browser is wanted for the mix.
  * "selenium": the package that drives your own Firefox (only when the app was installed with pip: the downloaded
    executable already contains it).

It runs once per kind in the background (the noise carries on meanwhile) and tries again after six hours if it failed.
Set LEGALPRIVACY_AUTOINSTALL=0 to switch it off.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

RETRY_AFTER = 6 * 3600
TIMEOUT = 20 * 60


def enabled() -> bool:
    return os.environ.get("LEGALPRIVACY_AUTOINSTALL", "1") != "0"


def command(name: str) -> tuple[list[str], dict | None]:
    """The command that installs `name`, and the environment to run it in."""
    if name == "selenium":
        return [sys.executable, "-m", "pip", "install", "--quiet", "selenium"], None
    try:                                                    # the driver Playwright ships with, so it also works frozen
        from playwright._impl._driver import compute_driver_executable, get_driver_env
        drv = compute_driver_executable()
        args = [str(x) for x in drv] if isinstance(drv, (tuple, list)) else [str(drv)]
        return args + ["install", name], get_driver_env()
    except Exception:
        return [sys.executable, "-m", "playwright", "install", name], None


class Installer:
    def __init__(self, log, run=subprocess.run, clock=time.time):
        self.log, self._run, self.clock = log, run, clock
        self._lock = threading.Lock()
        self._tried: dict[str, tuple[float, bool]] = {}
        self._busy: set[str] = set()

    def status(self, name: str) -> str:
        if name in self._busy:
            return "installing"
        t = self._tried.get(name)
        return "none" if t is None else ("ok" if t[1] else "failed")

    def ensure(self, name: str, on_done=None) -> bool:
        """Start installing `name` in the background unless it is off, running, done, or failed less than six hours ago.
        Returns True when an install was started."""
        if not enabled():
            return False
        with self._lock:
            t = self._tried.get(name)
            if name in self._busy or (t and (t[1] or self.clock() - t[0] < RETRY_AFTER)):
                return False
            self._busy.add(name)
        threading.Thread(target=self._do, args=(name, on_done), daemon=True, name=f"install-{name}").start()
        return True

    def _do(self, name: str, on_done) -> None:
        ok = False
        what = {"firefox": "the Firefox the noise browser uses", "chromium": "the Chromium the noise browser uses",
                "selenium": "the package that drives your own Firefox"}.get(name, name)
        self.log.info("browser", f"Installing {what} now (a minute or two; the noise carries on meanwhile).")
        try:
            cmd, env = command(name)
            r = self._run(cmd, capture_output=True, text=True, timeout=TIMEOUT, env=env)
            ok = getattr(r, "returncode", 1) == 0
            if ok:
                self.log.info("browser", f"Installed {what}. It is used from the next start (restarting the noise once now).")
            else:
                tail = ((getattr(r, "stderr", "") or getattr(r, "stdout", "") or "").strip().splitlines() or ["no details"])[-1]
                self.log.warn("browser", f"Could not install {what}: {tail[:200]}. It will try again in six hours.")
        except Exception as exc:
            self.log.warn("browser", f"Could not install {what}: {exc}. It will try again in six hours.")
        with self._lock:
            self._busy.discard(name)
            self._tried[name] = (self.clock(), ok)
        if on_done is not None:
            try:
                on_done(ok)
            except Exception:
                pass
