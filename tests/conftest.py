"""Tests never install browsers or packages by themselves (the app does that for people; a test must not)."""
import os

os.environ.setdefault("LEGALPRIVACY_AUTOINSTALL", "0")
os.environ.setdefault("LEGALPRIVACY_GEOBAN_DOWNLOADS", "0")      # nor do they download the address lists

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _no_public_address_lookup(monkeypatch):
    """The privacy check's VPN row asks ifconfig.me and ipinfo.io who owns this computer's public address. Tests never
    do: they see an ordinary ISP address unless a test says otherwise."""
    import legalprivacy.nettools as n
    monkeypatch.setattr(n, "external_ip_owner", lambda timeout=6.0: {"ip": "192.0.2.10", "org": "AS64500 Example ISP",
                                                                     "hostname": "", "error": None})
