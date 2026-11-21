"""Objectivist personas and the sites every persona can visit."""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from legalprivacy.config import Profile  # noqa: E402
from legalprivacy.interests import CATEGORIES, PERSONAS, Persona  # noqa: E402


def test_objectivist_personas_exist_and_use_real_themes():
    assert "Objectivism" in CATEGORIES
    for name in ("Objectivist", "Objectivist data scientist"):
        assert name in PERSONAS and abs(sum(PERSONAS[name].values()) - 1) < 1e-9
        assert all(t in CATEGORIES for t in PERSONAS[name])
    half = PERSONAS["Objectivist data scientist"]
    assert half["Objectivism"] == half["Data science"]               # half and half


def test_every_persona_can_visit_postsocialist_com():
    for name in PERSONAS:
        p = Persona(random.Random(3), name)
        seen = {p.site() for _ in range(1500)}
        assert "postsocialist.com" in seen, name


def test_objectivist_sites_and_queries_come_from_the_theme():
    p = Persona(random.Random(1), "Objectivist")
    assert any("aynrand.org" in p.site() or "atlassociety" in p.site() for _ in range(200))
    assert any("Rand" in p.query() or "Objectiv" in p.query() or "Atlas" in p.query() or "Fountainhead" in p.query()
               for _ in range(200))


def test_default_traffic_level_is_fairly_high():
    assert Profile(name="t").rate.level == 7
