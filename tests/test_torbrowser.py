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


def test_sharing_with_tor_browser_is_on_by_default_and_old_saved_settings_move_over_once(tmp_path, monkeypatch):
    import yaml
    from legalprivacy.config import Profile
    from legalprivacy.controller import Controller
    assert Profile(name="x").transports["tor"].share_browser is True
    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path / "p.yaml"
    path.write_text(yaml.safe_dump({"profile": {"transports": {"tor": {"enabled": True, "share_browser": False}}}}))
    c = Controller(str(path))
    assert c.profile.transports["tor"].share_browser is True and c.app["migrated_share"] is True   # moved over once
    c.apply_config({"transports": {"tor": {"share_browser": False}}})
    c2 = Controller(str(path))
    assert c2.profile.transports["tor"].share_browser is False            # and a later choice sticks


def test_the_noise_never_sends_newnym_under_a_shared_tor_browser():
    from legalprivacy.transports import TorTransport
    assert TorTransport(control="127.0.0.1:9051", share_browser=True).renew_circuits() is False


def test_opening_tor_browser_starts_the_shared_tor_first(tmp_path, monkeypatch):
    from legalprivacy.controller import Controller
    monkeypatch.setenv("HOME", str(tmp_path))
    c = Controller(str(tmp_path / "p.yaml"))

    class FakeTm:
        state, user_socks_port, control_addr, cookie_path, error = "stopped", 19150, "127.0.0.1:19151", "/tmp/c", None
        started = 0

        def start(self):
            self.started += 1
            self.state = "ready"
    tm = FakeTm()
    monkeypatch.setattr(c, "tor_manager", lambda: tm)
    import legalprivacy.torbrowser as tbm
    monkeypatch.setattr(tbm, "socks_answers", lambda *a, **k: "nothing is listening")
    import pytest
    with pytest.raises(tbm.TorBrowserError, match="isn't answering"):          # a dead door is reported, not opened
        c._shared_tor_env()
    tm.state = "stopped"
    tm.started = 0
    monkeypatch.setattr(tbm, "socks_answers", lambda *a, **k: None)
    env = c._shared_tor_env()
    assert tm.started == 1 and env                                         # the click just works: Tor was brought up
    c.profile.transports["tor"].share_browser = False
    assert c._shared_tor_env() is None


def test_relay_nickname_is_the_app_name_plus_random_characters_and_the_old_name_goes(tmp_path, monkeypatch):
    import yaml
    from legalprivacy.controller import Controller
    monkeypatch.setenv("HOME", str(tmp_path))
    c = Controller(str(tmp_path / "p.yaml"))
    n = c.profile.relay.nickname
    assert n.startswith("legalPrivacy") and len(n) == 16 and n.isalnum()
    path = tmp_path / "old.yaml"
    path.write_text(yaml.safe_dump({"profile": {"contribute": {"relay": {"nickname": "noisycricket"}}}}))
    assert Controller(str(path)).profile.relay.nickname.startswith("legalPrivacy")
    path.write_text(yaml.safe_dump({"profile": {"contribute": {"relay": {"nickname": "MyOwnRelay"}}}}))
    assert Controller(str(path)).profile.relay.nickname == "MyOwnRelay"    # a name you chose stays


def test_a_relay_never_publishes_a_contact_address(tmp_path, monkeypatch):
    from legalprivacy.config import RelayConfig
    from legalprivacy.relay import generate_torrc
    rc = RelayConfig(contact="me@example.org")
    assert rc.spec().contact is None and "ContactInfo" not in generate_torrc(rc.spec(), data_dir="/tmp/x")


def test_tor_browser_gets_the_original_library_path_back_in_the_packaged_app(monkeypatch):
    from legalprivacy import torbrowser as tb
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEI123/lib")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/usr/lib/x")
    monkeypatch.setattr("sys.frozen", True, raising=False)
    assert tb.clean_env()["LD_LIBRARY_PATH"] == "/usr/lib/x"               # what PyInstaller saved before it changed it
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG")
    assert "LD_LIBRARY_PATH" not in tb.clean_env()                          # there was none: drop the bundled one
    monkeypatch.setattr("sys.frozen", False, raising=False)
    monkeypatch.delattr("sys._MEIPASS", raising=False)
    monkeypatch.setenv("LD_LIBRARY_PATH", "mine")
    assert tb.clean_env()["LD_LIBRARY_PATH"] == "mine"                      # running from source: untouched


def test_a_dead_door_is_reported_before_tor_browser_is_opened():
    import socket
    import threading
    from legalprivacy import torbrowser as tb
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        c, _ = srv.accept()
        c.recv(3)
        c.sendall(b"\x05\x00")
        c.close()
    threading.Thread(target=serve, daemon=True).start()
    assert tb.socks_answers("127.0.0.1", port) is None                       # a SOCKS5 proxy answers
    srv.close()
    assert "nothing is listening" in tb.socks_answers("127.0.0.1", port, timeout=1.0)


def test_tor_browser_is_set_to_safest_and_every_known_onion_site_is_bookmarked(tmp_path):
    import json
    from legalprivacy import torbrowser as tb
    from legalprivacy.onion import BUILTIN_ONION_SEEDS
    tree = tmp_path / "tor-browser"
    dist = tree / "Browser" / "distribution"
    dist.mkdir(parents=True)
    (dist / "policies.json").write_text(json.dumps({"policies": {"DisableTelemetry": True}}))   # a policy already there stays
    prof = tree / "Browser" / "TorBrowser" / "Data" / "Browser" / "profile.default"
    prof.mkdir(parents=True)
    (prof / "user.js").write_text('user_pref("some.other", 1);\nuser_pref("browser.security_level.security_slider", 4);\n')
    tb.extra_bookmarks_fn = lambda: [("", "http://" + "a" * 56 + ".onion/")]
    try:
        tb.customize(tree)
        tb.customize(tree)                                                  # again: nothing doubles
    finally:
        tb.extra_bookmarks_fn = tb._no_extra_bookmarks
    uj = (prof / "user.js").read_text()
    assert uj.count("security_slider") == 1 and 'security_slider", 1)' in uj and "some.other" in uj     # 1 = Safest
    pol = json.loads((dist / "policies.json").read_text())["policies"]
    assert pol["DisableTelemetry"] is True and pol["DisplayBookmarksToolbar"] == "always"
    marks = pol["Bookmarks"]
    assert len(marks) == len(BUILTIN_ONION_SEEDS) + 1 and all(m["Placement"] == "toolbar" for m in marks)
    assert marks[0] == {"Title": BUILTIN_ONION_SEEDS[0][0], "URL": BUILTIN_ONION_SEEDS[0][1], "Placement": "toolbar"}
    assert marks[-1]["Title"].startswith("Onion site aaaaaa") and marks[-1]["URL"].endswith(".onion/")   # no name known yet


def test_site_names_are_learned_from_the_pages_the_noise_visits(tmp_path, monkeypatch):
    from legalprivacy import onion
    monkeypatch.setenv("HOME", str(tmp_path))
    url = "http://" + "b" * 56 + ".onion/"
    assert onion.site_label(url).startswith("Onion site bbbbbb")
    onion.learn_title(url, "<html><head><title> Example Wiki | Home &amp; more </title></head></html>")
    assert onion.site_label(url) == "Example Wiki"                           # the part before the separator
    onion.learn_title(url, "<title>Something else</title>")
    assert onion.site_label(url) == "Example Wiki"                           # the first name sticks
    onion.learn_title(onion.BUILTIN_ONION_SEEDS[0][1], "<title>Not this</title>")
    assert onion.site_label(onion.BUILTIN_ONION_SEEDS[0][1]) == onion.BUILTIN_ONION_SEEDS[0][0]


def test_shared_env_never_sets_tor_transproxy_which_switches_tor_browsers_proxy_off(monkeypatch):
    from legalprivacy import torbrowser as tb
    env = tb.shared_env("127.0.0.1:19150", "127.0.0.1:19151", "/tmp/cookie")
    assert "TOR_TRANSPROXY" not in env                                      # even "0" counts: Tor Browser checks existence
    assert env["TOR_SKIP_LAUNCH"] == "1" and env["TOR_SOCKS_PORT"] == "19150" and env["TOR_CONTROL_PORT"] == "19151"
    assert env["TOR_CONTROL_COOKIE_AUTH_FILE"] == "/tmp/cookie"
    monkeypatch.setenv("TOR_TRANSPROXY", "0")
    assert "TOR_TRANSPROXY" not in tb.clean_env()                           # and one inherited from outside is dropped
