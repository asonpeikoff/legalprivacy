"""The program and the Tor it runs stay on the newest release by themselves, and only ever install what checks out."""
import hashlib
import json
import threading
from pathlib import Path

import pytest

from legalprivacy import selfupdate as SU
from legalprivacy.tormanager import TorManager

URL = f"https://github.com/{SU.REPO}/releases/download/v9.9.9/{SU.ASSET}"


def _release(tag="v9.9.9", digest="sha256:" + "ab" * 32, url=URL, **kw):
    rel = {"tag_name": tag, "draft": False, "prerelease": False,
           "assets": [{"name": SU.ASSET, "browser_download_url": url, "size": 5, "digest": digest}]}
    rel.update(kw)
    return lambda _u, *a, **k: json.dumps(rel).encode()


def test_only_a_newer_published_release_with_a_digest_from_this_project_counts():
    got = SU.newest("2.21.0", _release())
    assert got and got["version"] == "9.9.9" and got["sha256"] == "ab" * 32 and got["url"] == URL
    assert SU.newest("9.9.9", _release()) is None and SU.newest("10.0.0", _release()) is None      # not newer
    assert SU.newest("2.21.0", _release(prerelease=True)) is None and SU.newest("2.21.0", _release(draft=True)) is None
    assert SU.newest("2.21.0", _release(digest="")) is None                                  # no digest: refuse
    assert SU.newest("2.21.0", _release(url="https://evil.example/x")) is None             # not this project's files
    assert SU.newest("2.21.0", _release(tag="vlatest")) is None


class _Resp:
    def __init__(self, data):
        self._d, self._pos = data, 0

    def read(self, n):
        out, self._pos = self._d[self._pos:self._pos + n], self._pos + n
        return out

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_a_download_is_swapped_in_only_if_its_checksum_matches(tmp_path):
    exe = tmp_path / "legalprivacy-launch-linux"
    exe.write_bytes(b"old")
    new = b"NEWPROGRAM"
    rel = {"url": URL, "size": len(new), "sha256": hashlib.sha256(new).hexdigest(), "version": "9.9.9"}
    prev = SU.download_and_swap(rel, exe, opener=lambda req, timeout=0: _Resp(new))
    assert exe.read_bytes() == new and prev.read_bytes() == b"old" and exe.stat().st_mode & 0o111
    exe.write_bytes(b"old")
    bad = dict(rel, sha256="00" * 32)
    with pytest.raises(RuntimeError, match="checksum"):
        SU.download_and_swap(bad, exe, opener=lambda req, timeout=0: _Resp(new))
    assert exe.read_bytes() == b"old" and not list(tmp_path.glob("*.new"))                 # untouched, nothing left behind
    with pytest.raises(RuntimeError, match="size"):
        SU.download_and_swap(dict(rel, size=0), exe, opener=lambda req, timeout=0: _Resp(new))


class _Log:
    def __init__(self):
        self.lines = []

    def info(self, _a, m):
        self.lines.append(m)

    warn = info


class _Ctl:
    def __init__(self, tmp, auto=True):
        self.app, self.log, self.profile_path = {"auto_update": auto}, _Log(), str(tmp / "config.yaml")


def test_a_round_updates_once_a_day_and_never_when_switched_off_or_not_the_downloaded_program(tmp_path, monkeypatch):
    restarts, applied = [], []
    monkeypatch.setattr(SU, "can_self_update", lambda: True)
    kw = dict(http=_release(), apply=lambda rel, exe, log=None: applied.append(rel["version"]),
              restart=lambda ctl: restarts.append(1))
    assert SU.run_once(_Ctl(tmp_path, auto=False), "2.21.0", **kw) is None and not applied
    ctl = _Ctl(tmp_path)
    assert SU.run_once(ctl, "2.21.0", **kw) == "9.9.9" and applied == ["9.9.9"] and restarts == [1]
    assert SU.run_once(ctl, "2.21.0", **kw) is None and applied == ["9.9.9"]               # not again within a day
    monkeypatch.setattr(SU, "can_self_update", lambda: False)
    assert SU.run_once(_Ctl(tmp_path / "x"), "2.21.0", **kw) is None


def test_a_failed_download_is_reported_and_nothing_restarts(tmp_path, monkeypatch):
    monkeypatch.setattr(SU, "can_self_update", lambda: True)

    def boom(rel, exe, log=None):
        raise RuntimeError("checksum mismatch")
    ctl, restarts = _Ctl(tmp_path), []
    assert SU.run_once(ctl, "2.21.0", http=_release(), apply=boom, restart=lambda c: restarts.append(1)) is None
    assert not restarts and any("Could not update" in m for m in ctl.log.lines)


def _tm(have, newest, binary_is_own=True):
    tm = TorManager.__new__(TorManager)
    tm.log, tm.mode, tm.auto_install, tm.state, tm._upgrading = _Log(), "managed", True, "ready", False
    tm._lock = threading.RLock()
    own = Path("/x/bundle/tor/tor")
    tm.binary = str(own if binary_is_own else "/usr/bin/tor")
    tm.calls = []
    tm._pick_bundle = lambda osn, arch: (newest, "f")
    tm.bundle_version = lambda: have
    tm._install = lambda: tm.calls.append("install")
    tm.restart = lambda: tm.calls.append("restart")
    return tm, own


def test_the_tor_the_app_runs_is_replaced_when_a_newer_official_one_exists(monkeypatch):
    from legalprivacy import tormanager as T
    monkeypatch.setattr(T, "platform_key", lambda: ("linux", "x86_64"))
    monkeypatch.setattr(T, "find_tor_binary", lambda: "/x/bundle/tor/tor")
    tm, own = _tm("14.5.4", "16.0.3")
    monkeypatch.setattr(T, "tor_dir", lambda: own.parent.parent.parent)
    monkeypatch.setattr(T, "_EXE", "tor")
    assert tm.refresh_if_newer() is True and tm.calls == ["install", "restart"]
    tm2, _ = _tm("16.0.3", "16.0.3")
    assert tm2.refresh_if_newer() is False and tm2.calls == []                             # already current
