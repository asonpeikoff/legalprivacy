import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="process names are set on Linux")


def test_the_program_names_itself_legalprivacy():
    out = subprocess.run([sys.executable, "-c",
                          "from legalprivacy.procname import set_name; print(set_name(), open('/proc/self/comm').read().strip())"],
                         capture_output=True, text=True, timeout=30)
    assert out.stdout.split() == ["True", "legalprivacy"], out.stderr


def test_a_failure_to_rename_is_harmless(monkeypatch):
    from legalprivacy import procname
    monkeypatch.setattr(procname.sys, "platform", "darwin")
    assert procname.set_name() is False


def test_sigterm_stops_the_dashboard_the_tidy_way():
    import signal

    from legalprivacy import webui
    old = signal.getsignal(signal.SIGTERM)
    try:
        webui._stop_on_sigterm()
        handler = signal.getsignal(signal.SIGTERM)
        with pytest.raises(KeyboardInterrupt):
            handler(signal.SIGTERM, None)                # what killall sends ends the serve loop like Ctrl+C
    finally:
        signal.signal(signal.SIGTERM, old)
