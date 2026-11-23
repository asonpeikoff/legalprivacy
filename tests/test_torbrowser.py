"""Tor Browser: only installed after a good signature from the pinned key; never as root; safe versions."""
import time

import pytest

from legalprivacy import torbrowser as T


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    monkeypatch.setattr(T.sys, "platform", "linux")
    monkeypatch.setattr(T.platform, "machine", lambda: "x86_64")
    return tmp_path


def _http(listing_versions=("15.0.9", "16.0.1", "16.0.2")):
    def get(url, **kw):
        if url == T.DIST_BASE:
            return "".join(f'<a href="{v}/">{v}/</a>' for v in listing_versions).encode()
        if url.endswith("/") and url.startswith(T.DIST_BASE):
            v = url[len(T.DIST_BASE):-1]
            return f'<a href="tor-browser-linux-x86_64-{v}.tar.xz">x</a>'.encode() if v != "16.0.2" else b"nothing"
        raise AssertionError(url)
    return get


def test_newest_version_that_has_a_file_for_this_computer():
    assert T.latest_version(_http()) == "16.0.1"          # 16.0.2 has no Linux file yet


def test_unsafe_version_numbers_are_refused():
    with pytest.raises(T.TorBrowserError):
        T.archive_name("1.0/../../etc")
    assert T.archive_name("16.0.1") == "tor-browser-linux-x86_64-16.0.1.tar.xz"


def _fake_gpg(tmp_path, status, rc=0):
    script = tmp_path / "gpg"
    script.write_text("#!/bin/sh\n"
                      "case \"$*\" in *--import*) exit 0;; esac\n"
                      f"printf '%s\\n' \"{status}\"\n"
                      f"exit {rc}\n")
    script.chmod(0o755)
    return str(script)


def test_signature_must_be_valid_and_from_the_pinned_key(tmp_path):
    a, s = tmp_path / "a", tmp_path / "a.asc"
    a.write_bytes(b"x")
    s.write_bytes(b"y")
    good = f"[GNUPG:] VALIDSIG {'1' * 40} 2026-01-01 1 0 4 0 1 10 00 {T.KEY_FPR}"
    T.verify_signature(a, s, b"key", _fake_gpg(tmp_path, good))
    other = good.replace(T.KEY_FPR, "2" * 40)
    with pytest.raises(T.TorBrowserError, match="not signed"):
        T.verify_signature(a, s, b"key", _fake_gpg(tmp_path, other))
    with pytest.raises(T.TorBrowserError, match="NOT valid"):
        T.verify_signature(a, s, b"key", _fake_gpg(tmp_path, "[GNUPG:] BADSIG AAAA x", rc=1))
    with pytest.raises(T.TorBrowserError, match="NOT valid"):                 # an expired key is refused too
        T.verify_signature(a, s, b"key", _fake_gpg(tmp_path, "[GNUPG:] EXPKEYSIG AAAA x\n" + good))


def test_no_gpg_means_no_install(tmp_path, monkeypatch):
    monkeypatch.setattr(T.shutil, "which", lambda n: None)
    with pytest.raises(T.TorBrowserError, match="GnuPG"):
        T.verify_signature(tmp_path / "a", tmp_path / "b", b"k")


def test_never_launched_as_root(monkeypatch):
    monkeypatch.setattr(T.os, "geteuid", lambda: 0)
    with pytest.raises(T.TorBrowserError, match="administrator"):
        T.launch()


def _wait(calls, last):
    for _ in range(200):
        if calls[-1:] == [last]:
            return
        time.sleep(0.02)


def _installed(version="16.0.1", files=None):
    """Pretend a verified copy is installed (the files named are written and fingerprinted)."""
    import json
    tree = T.tb_dir() / "tor-browser"
    tree.mkdir(parents=True, exist_ok=True)
    fp = {}
    for rel, data in (files or {}).items():
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_bytes(data)
        fp[rel] = T._sha256(tree / rel)
    (T.tb_dir() / "VERSION").write_text(version)
    (T.tb_dir() / "SIGNED.json").write_text(json.dumps({"version": version, "fingerprint": T.KEY_FPR,
                                                         "verified_at": time.time(), "files": fp}))


def test_open_installs_first_when_missing_or_old_then_launches():
    calls = []
    m = T.TorBrowserManager(install_fn=lambda progress=None: (calls.append("install"), "16.0.1")[1],
                            latest_fn=lambda: "16.0.1", launch_fn=lambda: calls.append("launch"))
    m.open()
    _wait(calls, "launch")
    assert calls == ["install", "launch"]
    _installed("16.0.1")
    calls.clear()
    m.open()                                                  # up to date: just launch
    assert calls == ["launch"]
    _installed("15.0.9")
    calls.clear()
    m.open()                                                  # out of date: update first
    _wait(calls, "launch")
    assert calls == ["install", "launch"]


def test_noise_tor_bundle_is_updated_once_a_day_only_when_it_is_the_apps_own(tmp_path, monkeypatch):
    from legalprivacy.events import EventLog
    from legalprivacy.paths import tor_dir
    from legalprivacy.tormanager import _EXE, TorManager
    own = tor_dir() / "bundle" / "tor" / _EXE
    own.parent.mkdir(parents=True)
    own.write_text("")
    (tor_dir() / "bundle" / "VERSION").write_text("15.0.9")
    installs = []
    tm = TorManager(EventLog())
    tm.binary = str(own)
    monkeypatch.setattr(TorManager, "_pick_bundle", staticmethod(lambda osn, arch: ("16.0.1", "x")))
    monkeypatch.setattr(tm, "_install", lambda: installs.append(1))
    tm._maybe_update_bundle()
    assert installs == [1]                                    # older: updated
    installs.clear()
    tm._maybe_update_bundle()
    assert installs == []                                     # already checked in the last day
    (tor_dir() / "update_checked").unlink()
    tm.binary = "/usr/bin/tor"
    tm._maybe_update_bundle()
    assert installs == []                                     # a Tor you installed yourself is never touched


def test_a_changed_program_is_never_launched_but_reinstalled():
    calls = []
    _installed("16.0.1", {"Browser/start-tor-browser": b"#!/bin/sh\n"})
    m = T.TorBrowserManager(install_fn=lambda progress=None: (calls.append("install"), "16.0.1")[1],
                            latest_fn=lambda: "16.0.1", launch_fn=lambda: calls.append("launch"))
    m.open()
    assert calls == ["launch"]
    (T.tb_dir() / "tor-browser" / "Browser" / "start-tor-browser").write_bytes(b"evil")
    calls.clear()
    m.open()
    _wait(calls, "launch")
    assert calls == ["install", "launch"]
    with pytest.raises(T.TorBrowserError):
        T.verify_install()


def test_snapshot_reports_the_verified_signature():
    assert T.TorBrowserManager().snapshot()["signature"] is None
    _installed("16.0.1")
    sig = T.TorBrowserManager().snapshot()["signature"]
    assert sig["ok"] and sig["fingerprint"] == T.KEY_FPR


def test_auto_update_installs_a_newer_release_but_not_while_it_is_open(monkeypatch):
    calls = []
    _installed("15.0.9")
    m = T.TorBrowserManager(install_fn=lambda progress=None: (calls.append("install"), "16.0.1")[1],
                            latest_fn=lambda: "16.0.1", launch_fn=lambda: None)
    monkeypatch.setattr(T, "running", lambda: True)
    m.auto_update()
    assert calls == []
    monkeypatch.setattr(T, "running", lambda: False)
    m.auto_update()
    _wait(calls, "install")
    assert calls == ["install"]


def test_shared_mode_points_tor_browser_at_the_apps_tor(monkeypatch):
    env = T.shared_env("127.0.0.1:19150", "127.0.0.1:19051", "/c/cookie")
    assert env["TOR_SKIP_LAUNCH"] == "1" and env["TOR_SOCKS_PORT"] == "19150"
    assert env["TOR_CONTROL_PORT"] == "19051" and env["TOR_CONTROL_COOKIE_AUTH_FILE"] == "/c/cookie"
    got = []
    _installed("16.0.1")
    m = T.TorBrowserManager(latest_fn=lambda: "16.0.1", launch_fn=lambda *a: got.append(a))
    m.shared_fn = lambda: env
    m.open()
    assert got == [(env,)]
    m.shared_fn = lambda: None
    got.clear()
    m.open()
    assert got == [()]


def test_sharing_adds_a_separate_isolated_door_and_blocks_new_identity(tmp_path, monkeypatch):
    from legalprivacy.events import EventLog
    from legalprivacy.tormanager import TorManager
    tm = TorManager(EventLog(), share_browser=True)
    assert tm.new_identity() is False                       # would cut off the pages you have open
    tm.binary = str(tmp_path / "tor")
    tm.socks_host, tm.socks_port, tm.control_port, tm.user_socks_port = "127.0.0.1", 19050, 19051, 19150
    tm.cookie_path = str(tmp_path / "cookie")
    text = tm._write_torrc(tmp_path).read_text()
    assert "SocksPort 127.0.0.1:19150 IsolateSOCKSAuth IsolateClientAddr" in text
