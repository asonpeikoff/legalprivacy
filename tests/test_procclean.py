import os
import shutil
import subprocess
import sys
import time

import pytest

from legalprivacy import procclean, selfupdate
from legalprivacy.events import EventLog

pytestmark = pytest.mark.skipif(sys.platform == "win32" or not shutil.which("sleep"), reason="needs a POSIX sleep")


def _fake_tor(folder):
    folder.mkdir(parents=True, exist_ok=True)
    exe = folder / "tor"
    shutil.copy(shutil.which("sleep"), exe)
    return subprocess.Popen([str(exe), "60"])


def test_leftover_tor_in_our_folder_is_stopped(tmp_path):
    mine, other = tmp_path / "ours", tmp_path / "someone-elses"
    a, b = _fake_tor(mine), _fake_tor(other)
    try:
        assert procclean.kill_stale_tors(EventLog(), folders=[str(mine)]) == 1
        a.wait(timeout=10)
        assert a.poll() is not None and b.poll() is None     # a Tor that is not ours is never touched
    finally:
        for p in (a, b):
            p.kill()
            p.wait()


def test_nothing_to_stop_is_fine(tmp_path):
    assert procclean.kill_stale_tors(folders=[str(tmp_path / "none")]) == 0


def test_update_restart_stops_leftovers_and_resets_the_bundle_environment(tmp_path, monkeypatch):
    calls = {}
    monkeypatch.setattr(procclean, "kill_stale_tors", lambda log=None, folders=None: calls.setdefault("killed", True))
    monkeypatch.setattr(os, "execve", lambda exe, argv, env: calls.update(exe=exe, env=env))

    class Ctl:
        log = EventLog()
        def stop(self, stop_tor=False):
            calls["stopped"] = stop_tor
    selfupdate._restart(Ctl())
    assert calls["stopped"] is True and calls["killed"] is True
    assert calls["env"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1" and calls["exe"] == sys.executable


def test_failed_restart_keeps_the_old_one_running(monkeypatch):
    def boom(*a):
        raise OSError("no such file")
    monkeypatch.setattr(os, "execve", boom)
    monkeypatch.delenv("INVOCATION_ID", raising=False)
    monkeypatch.setattr(procclean, "kill_stale_tors", lambda *a, **k: 0)

    class Ctl:
        log = EventLog()
        def stop(self, stop_tor=False): ...
    selfupdate._restart(Ctl())                                 # returns instead of dying
    time.sleep(0)
