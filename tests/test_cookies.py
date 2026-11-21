"""The noise browser's cookie jar: kept for a while, then wiped; never kept when set to 0."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from legalprivacy import browser as B  # noqa: E402
from legalprivacy.config import Profile, TransportConfig, apply_overrides  # noqa: E402


def _bt(hours, vary=True):
    os.environ["LEGALPRIVACY_HOME"] = tempfile.mkdtemp()
    t = B.BrowserTransport.__new__(B.BrowserTransport)
    t.cookie_hours, t.cookie_vary, t.engine, t.on_event = hours, vary, "chromium", lambda *a: None
    return t


def test_default_keeps_cookies_about_an_hour_and_varies_it():
    c = TransportConfig()
    assert c.cookie_hours == 1.0 and c.cookie_vary is True
    t = _bt(1.0)
    lives = [t._lifetime() for _ in range(500)]
    assert min(lives) >= 0.6 * 3600 and max(lives) <= 1.4 * 3600 and max(lives) - min(lives) > 1800
    assert _bt(1.0, vary=False)._lifetime() == 3600


def test_jar_is_kept_inside_its_lifetime_then_wiped():
    t = _bt(1.0)
    jar = t._jar(False)
    jar.parent.mkdir(parents=True, exist_ok=True)
    jar.write_text("{}")
    B._born_file(jar).write_text(f"{int(time.time()) - 1800} 3600")        # 30 min into a 1 h life
    assert t._load_jar(False) == str(jar)
    B._born_file(jar).write_text(f"{int(time.time()) - 4000} 3600")        # past its life
    assert t._load_jar(False) is None and not jar.exists()


def test_zero_never_keeps_and_old_day_settings_carry_over():
    assert _bt(0)._load_jar(False) is None
    p = Profile(name="t")
    apply_overrides(p, {"transports": {"clearnet": {"cookie_days": 7}}})
    assert p.transports["clearnet"].cookie_hours == 168
