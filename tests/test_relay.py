"""Unit tests for the community relay torrc generator (offline, no network)."""

try:
    import pytest
except ImportError:
    class _RaisesContext:
        def __init__(self, exc): self.exc = exc
        def __enter__(self): return self
        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is None: raise AssertionError(f"DID NOT RAISE {self.exc}")
            return issubclass(exc_type, self.exc)
    import types
    pytest = types.ModuleType("pytest")
    pytest.raises = _RaisesContext

from legalprivacy.relay import (RelayConfigError, RelaySpec, generate_torrc,
                                warn_if_exit_requested)


def test_middle_torrc_rejects_all_exits():
    spec = RelaySpec(mode="middle", nickname="mylegalprivacy", or_port=9001)
    torrc = generate_torrc(spec)
    assert "ExitPolicy reject *:*" in torrc
    assert "BridgeRelay 0" in torrc
    assert "ORPort 9001" in torrc
    assert "DirPort 9030" in torrc
    assert "SocksPort 0" in torrc
    assert "RelayBandwidthRate 5Mbit" in torrc


def test_bridge_torrc():
    spec = RelaySpec(mode="bridge", nickname="bridgey")
    torrc = generate_torrc(spec)
    assert "BridgeRelay 1" in torrc
    assert "PublishServerDescriptor bridge" in torrc
    assert "DirPort 0" in torrc
    assert "SocksPort 0" in torrc
    assert torrc.endswith("ExitPolicy reject6 *:*\n")


def test_exit_mode_is_refused():
    with pytest.raises(RelayConfigError):
        generate_torrc(RelaySpec(mode="exit"))


def test_or_port_9050_is_refused():
    with pytest.raises(RelayConfigError):
        generate_torrc(RelaySpec(or_port=9050))


def test_nonalphanumeric_nickname_refused():
    with pytest.raises(RelayConfigError):
        generate_torrc(RelaySpec(nickname="bad-nick"))


def test_or_port_and_dir_port_collision_refused():
    with pytest.raises(RelayConfigError):
        generate_torrc(RelaySpec(or_port=9001, dir_port=9001))


def test_exit_scanner_defense():
    assert not warn_if_exit_requested(generate_torrc(RelaySpec()))
    torrc = generate_torrc(RelaySpec()) + "ExitPolicy accept *:*\n"
    assert warn_if_exit_requested(torrc)


def test_generate_client_torrc_snowflake():
    from legalprivacy.relay import generate_client_torrc
    torrc = generate_client_torrc(bridge_type="snowflake")
    assert "UseBridges 1" in torrc
    assert "ClientTransportPlugin snowflake" in torrc
    assert "Bridge snowflake" in torrc
    assert "SocksPort 127.0.0.1:9050" in torrc


def test_tor_transport_check_status_handles_offline_gracefully():
    from legalprivacy.transports import TorTransport
    # Non-existent port to test offline status handling
    tor = TorTransport(socks="127.0.0.1:1", control="127.0.0.1:2")
    status = tor.check_status()
    assert status["socks_ok"] is False
    assert status["control_ok"] is False
    assert status["error"] is not None


def test_a_relay_left_over_from_an_earlier_run_is_stopped_but_another_window_is_left_alone(tmp_path, monkeypatch):
    import subprocess
    import sys

    from legalprivacy import relayrun
    monkeypatch.setattr(relayrun, "relay_dir", lambda: tmp_path)
    data = tmp_path / "data"
    data.mkdir()
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)  # " + str(tmp_path)],
                             start_new_session=True)
    try:
        (data / "lock").write_text(f"{child.pid}\n")
        m = relayrun.RelayManager.__new__(relayrun.RelayManager)
        m.log = type("L", (), {"info": lambda *a: None})()
        m._reap_orphan(data)
        assert child.wait(timeout=10) is not None            # stopped
        (data / "lock").write_text("999999999\n")
        m._reap_orphan(data)                                  # a stale lock file: nothing to do, no error
    finally:
        child.kill()
