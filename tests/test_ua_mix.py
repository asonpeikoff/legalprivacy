"""User agent "mix" mode: some share of identities use your real browser's UA, the rest random."""
import os
import random
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

from legalprivacy.config import ConfigError, IdentityConfig  # noqa: E402
from legalprivacy.controller import Controller  # noqa: E402
from legalprivacy.useragents import UaChooser  # noqa: E402

OWN = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"


def _share_own(share, n=2000):
    cfg = IdentityConfig(ua_mode="mix", own_ua=OWN, ua_own_share=share)
    ch = UaChooser(random.Random(7), cfg)
    return sum(1 for _ in range(n) if ch.choose()["ua"] == OWN) / n


def test_mix_uses_the_real_ua_about_the_chosen_share_of_the_time():
    assert abs(_share_own(0.7) - 0.7) < 0.05
    assert abs(_share_own(0.25) - 0.25) < 0.05
    assert _share_own(1.0) == 1.0
    assert _share_own(0.0) < 0.02        # the random library may rarely contain the same string


def test_mix_without_a_known_real_ua_is_all_random():
    ch = UaChooser(random.Random(1), IdentityConfig(ua_mode="mix", own_ua="", ua_own_share=1.0))
    assert ch.choose()["ua"]


def test_config_validates_mix_and_share():
    IdentityConfig(ua_mode="mix", ua_own_share=0.5).validate()
    for bad in (-0.1, 1.5):
        try:
            IdentityConfig(ua_mode="mix", ua_own_share=bad).validate()
        except ConfigError:
            continue
        raise AssertionError(bad)


def _ctl():
    return Controller(os.path.join(tempfile.mkdtemp(), "config.yaml"))


def test_ua_save_mix_roundtrips_and_needs_the_real_ua():
    c = _ctl()
    try:
        c.ua_save({"ua_mode": "mix", "own_share": 60})
    except ConfigError:
        pass
    else:
        raise AssertionError("mix needs your real user agent")
    st = c.ua_save({"ua_mode": "mix", "own_share": 60, "own_ua": OWN})
    assert st["mode"] == "mix" and st["own_share"] == 60
    c2 = Controller(c.profile_path)                       # survives a restart
    assert c2.profile.identity.ua_mode == "mix" and abs(c2.profile.identity.ua_own_share - 0.6) < 1e-9
    for bad in (-1, 101, "x"):
        try:
            c.ua_save({"ua_mode": "mix", "own_share": bad, "own_ua": OWN})
        except ConfigError:
            continue
        raise AssertionError(bad)
