"""An obsolete Tor is not acceptable: it is flagged loudly, replaced by the current official one, and its signature is checked."""
import threading

import pytest

from legalprivacy.tormanager import TorManager


class _Log:
    def __init__(self):
        self.lines = []

    def info(self, _a, m):
        self.lines.append(("info", m))

    def error(self, _a, m):
        self.lines.append(("error", m))

    warn = info


class _Ctl:
    def __init__(self, status):
        self.status = status

    def getinfo(self, key):
        assert key == "status/version/current"
        return self.status


def _tm(mode="managed", auto=True, binary="/usr/bin/tor"):
    tm = TorManager.__new__(TorManager)
    tm.log, tm.mode, tm.auto_install, tm.binary, tm.version = _Log(), mode, auto, binary, "0.4.7.16"
    tm.version_status, tm.alert, tm._version_checked, tm._upgrading = None, None, False, False
    tm._lock = threading.RLock()
    tm.upgrades = []
    tm._upgrade_tor = lambda: tm.upgrades.append(1)
    return tm


@pytest.mark.parametrize("status", ["recommended", "new", "new in series"])
def test_a_supported_tor_raises_no_alarm(status):
    tm = _tm()
    tm._check_version(_Ctl(status))
    assert tm.alert is None and tm.upgrades == [] and tm.version_status == status


@pytest.mark.parametrize("status", ["obsolete", "old", "unrecommended"])
def test_an_unsupported_tor_panics_and_is_replaced(status):
    tm = _tm()
    tm._check_version(_Ctl(status))
    assert tm.upgrades == [1] and "PANIC" in tm.log.lines[-1][1] and tm.log.lines[-1][0] == "error"
    assert status in tm.alert and "signature is checked" in tm.alert


def test_the_check_runs_once_per_start():
    tm = _tm()
    tm._check_version(_Ctl("obsolete"))
    tm._check_version(_Ctl("obsolete"))
    assert tm.upgrades == [1]


def test_a_tor_the_app_does_not_manage_is_flagged_but_never_replaced():
    tm = _tm(mode="external")
    tm._check_version(_Ctl("obsolete"))
    assert tm.upgrades == [] and "obsolete" in tm.alert and tm.log.lines[-1][0] == "error"


def test_the_checksum_signature_must_be_valid_and_a_missing_gpg_blocks_the_install(monkeypatch):
    from legalprivacy import torbrowser as TB
    tm = _tm()
    monkeypatch.setattr(TB, "_http_get", lambda *a, **k: b"key")

    def bad(*a, **k):
        raise TB.TorBrowserError("GnuPG (gpg) is needed to check Tor Browser's signature and isn't installed")
    monkeypatch.setattr(TB, "verify_signature", bad)
    with pytest.raises(RuntimeError, match="could not be verified"):
        tm._verify_sums_signature(b"sums", b"sig")
    monkeypatch.setattr(TB, "verify_signature", lambda *a, **k: None)
    tm._verify_sums_signature(b"sums", b"sig")                      # a valid signature passes
    assert "verified" in tm.log.lines[-1][1]


def test_the_firefox_path_you_set_is_used_or_explained(tmp_path):
    from legalprivacy.config import ConfigError, TransportConfig
    from legalprivacy.realfirefox import find_firefox
    fx = tmp_path / "firefox"
    fx.write_text("#!/bin/sh\n")
    path, why = find_firefox(str(fx))
    assert path == str(fx.resolve()) and why == ""
    path, why = find_firefox(str(tmp_path / "nope"))
    assert path is None and "does not exist" in why               # no silent guessing elsewhere
    TransportConfig(firefox_path=str(fx)).validate("clearnet")
    with pytest.raises(ConfigError, match="does not exist"):
        TransportConfig(firefox_path=str(tmp_path / "nope")).validate("clearnet")
