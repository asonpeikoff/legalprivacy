import random

from legalprivacy.fingerprint_audit import audit_identity, audit_window
from legalprivacy.identity import Identity, make_identity


def test_every_identity_the_app_makes_is_internally_consistent():
    rng = random.Random(7)
    bad = [(i, p) for i in range(600) for p in audit_identity(make_identity(rng, i, []))]
    assert bad == []


def _id(**kw):
    base = dict(id=1, persona="desktop-chrome", user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36", accept_language="en-US,en;q=0.9", pace="normal",
                query_taste=[], chromium=True, mobile=False, platform="Windows")
    base.update(kw)
    return Identity(**base)


def test_the_auditor_catches_the_contradictions_it_is_for():
    assert audit_identity(_id()) == []
    assert any("platform" in p for p in audit_identity(_id(platform="Linux")))
    assert any("Chromium flag" in p for p in audit_identity(_id(chromium=False)))
    assert any("mobile flag" in p for p in audit_identity(_id(mobile=True, device="x")))
    assert any("descending" in p for p in audit_identity(_id(accept_language="en;q=0.5,en-US;q=0.9")))
    ff = _id(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0", chromium=False)
    assert audit_identity(ff) == []


def test_window_shapes():
    assert audit_window(_id(), 1500, 860) == [] and audit_window(_id(), 400, 700)
    assert audit_window(_id(mobile=True, device="iPhone 13"), 390, 780) == [] and audit_window(_id(mobile=True), 1400, 800)
