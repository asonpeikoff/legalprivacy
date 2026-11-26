"""Keep the noise running for weeks without you looking at it.

A watchdog checks every half minute whether the noise is still doing its job and wakes it when it is not:

  * it STOPPED ON ITS OWN (the runner crashed, or ended because of an error): it is started again (not more than six
    times an hour, so a crash that repeats immediately does not spin);
  * it PAUSED ITSELF for any reason except two: it is woken. The two it leaves alone are a pause YOU asked for, and your
    own daily data limit (that one ends by itself at midnight);
  * it is STUCK (the main loop has not moved for twenty minutes while it is meant to be running): it is stopped and started.

Turn it off in Settings ("Keep it running") and none of this happens: a pause stays a pause. After the computer wakes
from sleep the stuck check waits two minutes first, so a lid that was closed overnight is not mistaken for a hang.
"""
from __future__ import annotations

import time

STALL_SECONDS = 20 * 60
TICK_SECONDS = 30
RESTARTS_PER_HOUR = 6


class KeepAlive:
    def __init__(self, ctl, clock=time.time):
        self.ctl, self.clock = ctl, clock
        self._restarts: list[float] = []
        self._last_tick = clock()
        self._grace_until = 0.0

    def enabled(self) -> bool:
        try:
            return bool(self.ctl.profile.extras.keep_alive)
        except AttributeError:
            return True

    def tick(self) -> str | None:
        """One check. Returns what it did ("restarted", "woke", "unstuck") or None, for the log and the tests."""
        ctl, now = self.ctl, self.clock()
        gap, self._last_tick = now - self._last_tick, now
        if gap > 120:                                   # the computer was asleep: give the loop time to catch up
            self._grace_until = now + 120
        if not self.enabled() or not getattr(ctl, "wanted_running", False):
            return None
        if not ctl.running:
            recent = [t for t in self._restarts if now - t < 3600]
            self._restarts = recent
            if len(recent) >= RESTARTS_PER_HOUR:
                return None
            self._restarts.append(now)
            ctl.log.warn("app", "The noise had stopped on its own. Starting it again (Settings > Keep it running).")
            ctl.start(reason="it stopped on its own (keep-alive)")
            return "restarted"
        r = ctl.runner
        if r is None:
            return None
        if r.paused is True:                            # you paused it: that is yours to undo
            return None
        if r.paused:                                    # it paused itself ("failures" is the name an old version gave it)
            if r._data_capped():                        # your own daily data limit: it ends at midnight
                return None
            r.paused = False
            ctl.log.info("app", "The noise had paused itself. Woke it up (Settings > Keep it running).")
            return "woke"
        if now >= self._grace_until and time.time() - r.last_beat > STALL_SECONDS:
            ctl.log.warn("app", f"The noise looks stuck (nothing moved for {STALL_SECONDS // 60} minutes). Restarting it.")
            try:
                ctl.restart_for_keepalive()
            except Exception as exc:
                ctl.log.warn("app", f"Could not restart it: {exc}")
                return None
            return "unstuck"
        return None
