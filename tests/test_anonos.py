"""On Whonix / Qubes-Whonix the app uses the gateway's Tor (never Tor over Tor), unless switched off."""
import subprocess
from pathlib import Path

import pytest

from legalprivacy import anonos
from legalprivacy.config import ConfigError, TransportConfig


def _root(tmp_path, *markers):
    for m in markers:
        p = Path(str(tmp_path) + m)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")
    return str(tmp_path)


def _run(out):
    return lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=out, stderr="")


def test_an_ordinary_computer_is_nothing_special(tmp_path, monkeypatch):
    monkeypatch.setattr(anonos.shutil, "which", lambda n: None)
    assert anonos.detect(root=str(tmp_path)) is None


def test_non_qubes_whonix_workstation_uses_the_standard_gateway(tmp_path, monkeypatch):
    monkeypatch.setattr(anonos.shutil, "which", lambda n: None)
    d = anonos.detect(root=_root(tmp_path, anonos.WS_MARKER, anonos.WHONIX_MARKER))
    assert d["kind"] == "whonix-workstation" and not d["qubes"]
    assert d["socks"] == "10.152.152.10:9050" and d["control"] == "10.152.152.10:9051"


def test_qubes_whonix_workstation_asks_qubesdb_for_its_gateway(tmp_path, monkeypatch):
    monkeypatch.setattr(anonos.shutil, "which", lambda n: "/usr/bin/qubesdb-read" if n == "qubesdb-read" else None)
    d = anonos.detect(root=_root(tmp_path, anonos.WS_MARKER, anonos.QUBES_MARKER), run=_run("10.137.0.5\n"))
    assert d["name"] == "Qubes-Whonix Workstation" and d["socks"] == "10.137.0.5:9050"


def test_a_strange_qubesdb_answer_is_never_used_as_an_address(tmp_path, monkeypatch):
    monkeypatch.setattr(anonos.shutil, "which", lambda n: "/usr/bin/qubesdb-read" if n == "qubesdb-read" else None)
    d = anonos.detect(root=_root(tmp_path, anonos.WS_MARKER), run=_run("evil.example; rm -rf /"))
    assert d["socks"] == "10.152.152.10:9050"


def test_a_plain_qube_behind_sys_whonix_is_detected_by_its_gateway_answering_on_the_tor_port(tmp_path, monkeypatch):
    monkeypatch.setattr(anonos.shutil, "which", lambda n: "/usr/bin/qubesdb-read" if n == "qubesdb-read" else None)
    root = _root(tmp_path, anonos.QUBES_MARKER)
    d = anonos.detect(root=root, run=_run("10.137.0.9"), probe=lambda h, p: (h, p) == ("10.137.0.9", 9050))
    assert d["kind"] == "qubes-sys-whonix" and d["socks"] == "10.137.0.9:9050"
    assert anonos.detect(root=root, run=_run("10.137.0.9"), probe=lambda h, p: False) is None   # sys-firewall: ordinary


def test_on_the_gateway_itself_its_local_tor_is_used(tmp_path, monkeypatch):
    monkeypatch.setattr(anonos.shutil, "which", lambda n: None)
    d = anonos.detect(root=_root(tmp_path, anonos.GW_MARKER))
    assert d["kind"] == "whonix-gateway" and d["socks"] == "127.0.0.1:9050"


def test_setting_is_auto_by_default_and_validated():
    assert TransportConfig().anon_os == "auto"
    with pytest.raises(ConfigError):
        TransportConfig(anon_os="maybe").validate("tor")


WS = {"kind": "whonix-workstation", "qubes": False, "name": "Whonix-Workstation",
      "socks": "10.152.152.10:9050", "control": "10.152.152.10:9051"}


@pytest.fixture
def ctl(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    from legalprivacy.controller import Controller
    return Controller(str(tmp_path / "config.yaml"))


def test_on_whonix_the_app_attaches_to_the_gateway_instead_of_running_its_own_tor(ctl, monkeypatch):
    monkeypatch.setattr(anonos, "current", lambda: WS)
    tm = ctl.tor_manager()
    assert tm.mode == "external" and tm.ext_socks == "10.152.152.10:9050" and tm.ext_control == "10.152.152.10:9051"
    assert tm.anon_os == WS and tm.bridge_label() == "set on the Whonix-Gateway"
    msgs = " ".join(e["message"] for e in ctl.log.since(0))
    assert "Tor over Tor" in msgs and "50_user.conf" in msgs and "{us}" in msgs     # the avoid list: how to keep it


def test_switched_off_the_settings_win(ctl, monkeypatch):
    monkeypatch.setattr(anonos, "current", lambda: WS)
    ctl.apply_config({"transports": {"tor": {"anon_os": "off"}}})
    assert ctl.tor_manager().mode == "managed"


def test_no_relay_on_whonix(ctl, monkeypatch):
    monkeypatch.setattr(anonos, "current", lambda: WS)
    with pytest.raises(ConfigError, match="can't run on Whonix"):
        ctl.relay_start({})


def test_the_gateway_not_answering_says_so_plainly(monkeypatch):
    from legalprivacy.events import EventLog
    from legalprivacy.tormanager import TorManager
    tm = TorManager(EventLog(), mode="external", socks="10.152.152.10:9050", control="10.152.152.10:9051")
    tm.anon_os = WS
    monkeypatch.setattr("legalprivacy.tormanager.port_open", lambda h, p: False)
    monkeypatch.setattr(tm._stop_evt, "wait", lambda t: True)        # no 90 s wait in a test
    with pytest.raises(RuntimeError, match="Whonix-Gateway's Tor does not answer"):
        tm._attach_external()
