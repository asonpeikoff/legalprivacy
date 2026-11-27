"""The torrc preview shown in the relay card (nothing is saved or started)."""
import pytest


@pytest.fixture()
def ctl(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    from legalprivacy.controller import Controller
    return Controller(str(tmp_path / "config.yaml"))


def test_preview_follows_the_unsaved_settings(ctl):
    r = ctl.relay_preview({"mode": "bridge", "or_port": 9443, "bandwidth_mb": 2, "nickname": "abc"})
    assert r["error"] is None
    assert "ORPort 9443" in r["torrc"] and "BridgeRelay 1" in r["torrc"] and "RelayBandwidthRate 2 MBytes" in r["torrc"]
    assert "ExitPolicy accept" not in r["torrc"] and r["torrc"].endswith("ExitPolicy reject6 *:*\n")
    assert ctl.profile.relay.or_port == 9001                  # nothing was saved


@pytest.mark.parametrize("bad", [{"nickname": "a\nExitRelay 1"}, {"mode": "exit"},
                                 {"or_port": 80}, {"or_port": "abc"}, {"bandwidth_mb": 0}, {"bandwidth_mb": "1\n2"}])
def test_preview_explains_invalid_settings(ctl, bad):
    r = ctl.relay_preview(bad)
    assert r["torrc"] == "" and r["error"]
