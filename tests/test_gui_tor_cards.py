"""Native Tor tab: the Tor DNS and relay cards (widget smoke tests; skip without Tk or a display)."""
import time

import pytest


@pytest.fixture
def tk_app(tmp_path, monkeypatch):
    tk = pytest.importorskip("tkinter")
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    from legalprivacy import gui
    from legalprivacy.controller import Controller
    ctl = Controller(str(tmp_path / "p.yaml"))
    app = gui.build_app_class()(root, ctl, 0)

    def pump(seconds=1.0):
        end = time.time() + seconds
        while time.time() < end:
            root.update()
            time.sleep(0.02)
    app.pump_for = pump
    yield app
    try:
        app.closing = True
        ctl.observer.stop()
        ctl.relay.stop()
        root.destroy()
    except tk.TclError:
        pass


def _tor_tab(app):
    tor = next(t for t in app.tabs if t.title == "Tor")
    app.nb.select(app.tabs.index(tor))
    return tor


def test_cards_default_off_and_save(tk_app):
    app = tk_app
    app.pump_for(1.2)
    tor = _tor_tab(app)
    app.pump_for(0.6)
    v = tor.values()
    assert v["tor_dns"] is False and v["tor_dns_lan"] is False          # off by default
    assert not tor.dns_body.winfo_manager()                             # details hidden until switched on
    assert tor.r_practice.get() is True
    assert app.ctl.relay_state()["status"]["state"] == "stopped"        # never started by itself
    assert "ORPort 127.0.0.1:" in tor.r_torrc.get("1.0", "end")         # practice mode by default
    assert "DNSPort" not in tor.r_torrc.get("1.0", "end")
    tor.load({"tor_dns": True})
    app.pump_for(2.0)
    assert app.ctl.profile.transports["tor"].dns_port == 19053
    assert tor.dns_body.winfo_manager()
    tor.load({"tor_dns_lan": True, "tor_dns_addr": ""})
    assert tor.values()["tor_dns_lan"] is False                         # sharing needs a chosen private address


def test_public_relay_start_needs_the_checklist(tk_app):
    app = tk_app
    app.pump_for(1.2)
    tor = _tor_tab(app)
    tor._r_tor_found = True
    tor.r_practice.set(False)
    tor._relay_changed()
    assert "disabled" in tor.r_start.state() and "checklist" in tor.r_msg.cget("text")
    for var in tor.r_checks.values():
        var.set(True)
    tor._relay_changed()
    assert "disabled" not in tor.r_start.state()
    assert "ExitPolicy accept" not in tor.r_torrc.get("1.0", "end")
    tor.r_nick.set("bad nick\nExitRelay 1")                             # a bad value is explained, not sent
    tor._relay_changed()
    assert "disabled" in tor.r_start.state()
