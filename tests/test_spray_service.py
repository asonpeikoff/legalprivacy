"""Spray and Pray (fast DNS lookups for many domains) and running as a service."""
import random
import xml.etree.ElementTree as ET

import pytest

from legalprivacy import feeds as feeds_mod
from legalprivacy.config import ConfigError, Profile, apply_overrides
from legalprivacy.service import first_run_answers, launchd_plist, systemd_unit
from legalprivacy.spray import LEVELS, Spray


class _Feeds:
    def __init__(self, items):
        self._i = items

    def items(self, name):
        return list(self._i) if name == "spray" else []


def _spray(on=True, active=True, level="medium", items=None, send=None, rng=None):
    items = items or [f"c|common{i}.com" for i in range(2000)] + [f"t|tail{i}.net" for i in range(2000)]
    sent = []
    sp = Spray(_Feeds(items), lambda: {"on": on, "level": level}, lambda: active, lambda: ["9.9.9.9"],
               rng=rng or random.Random(1), sleep=lambda s: None, send_fn=send or (lambda pk: sent.append(len(pk)) or len(pk)))
    sp._test_sent = sent
    return sp


def test_it_is_off_by_default_and_validates_its_level():
    p = Profile(name="d")
    assert p.extras.spray is False and p.extras.spray_level == "medium"
    apply_overrides(p, {"extras": {"spray": True, "spray_level": "high"}})
    assert p.extras.spray is True and p.extras.spray_level == "high"
    with pytest.raises(ConfigError):
        apply_overrides(Profile(name="x"), {"extras": {"spray_level": "insane"}})


def test_it_sends_nothing_unless_switched_on_and_the_noise_is_running():
    assert _spray(on=False).tick() == 0
    assert _spray(active=False).tick() == 0
    sp = _spray()
    assert sp.tick() > 0 and sp.sent > 0 and sp.answered == sp.sent


def test_most_queries_are_for_common_sites_with_a_long_tail_and_popular_names_come_first():
    sp = _spray()
    sp.load()
    picks = [sp.pick() for _ in range(4000)]
    common = sum(1 for d in picks if d.startswith("common")) / len(picks)
    assert 0.55 < common < 0.75
    assert len({d for d in picks}) > 600                         # hundreds of different names
    assert sum(1 for d in picks if d in ("common0.com", "common1.com", "common2.com")) > \
        sum(1 for d in picks if d in ("common1990.com", "common1991.com", "common1992.com"))


def test_a_level_means_about_that_many_queries_a_second_in_bursts():
    sp = _spray()
    for level, rate in LEVELS.items():
        n = [sp.burst_size(rate, 0.8) for _ in range(400)]
        assert 0.5 * rate * 0.8 < sum(n) / len(n) < 1.6 * rate * 0.8
        assert len(set(n)) > 5                                    # bursty, not a steady drip


def test_it_slows_when_the_resolver_stops_answering_and_recovers_when_it_answers_again():
    sp = _spray(send=lambda pk: 0)
    for _ in range(6):
        sp.tick()
    assert sp.factor < 0.3
    sp.send_fn = lambda pk: len(pk)
    for _ in range(12):
        sp.tick()
    assert sp.factor > 0.5 and sp.state()["answered"] > 0


class _Resp:
    def __init__(self, text):
        self.text = text


def test_the_domain_feed_is_built_from_big_lists_and_passes_the_safety_filter(monkeypatch, tmp_path):
    common = "\n".join(["google.com", "facebook.com", "bad-example-xxx.com", "wikipedia.org"])
    million = "\n".join([f"site{i}.org" for i in range(200)])
    rnd = "\n".join(["random-one.net", "random-two.net"])
    urls = feeds_mod.SPRAY_URLS

    def fake_get(url, timeout=0, **k):
        return _Resp({urls["opendns_top"]: common, urls["opendns_random"]: rnd, urls["top_million"]: million}[url])
    monkeypatch.setattr(feeds_mod, "_get", fake_get)
    monkeypatch.setattr(feeds_mod, "safe_domain", lambda d, deny=None: "xxx" not in d)
    f = feeds_mod.FeedStore(path=tmp_path / "f.json", bundled=False)
    items = f._fetch_spray(tail_keep=50, common_top=20)
    c = [i for i in items if i.startswith("c|")]
    t = [i for i in items if i.startswith("t|")]
    assert "c|google.com" in c and not any("xxx" in i for i in items)
    assert "t|random-one.net" in t and len(t) > 40 and len(set(items)) == len(items)


def test_the_service_unit_restarts_always_and_stops_everything_with_it():
    u = systemd_unit(["/usr/bin/python3", "-m", "legalprivacy.launcher", "--service"])
    assert "Restart=always" in u and "ExecStart=/usr/bin/python3 -m legalprivacy.launcher --service" in u
    assert "KillMode=control-group" in u and "WantedBy=default.target" in u
    root = ET.fromstring(launchd_plist(["/x/legalprivacy-launch", "--service"]))
    assert root.tag == "plist" and "KeepAlive" in ET.tostring(root, encoding="unicode")


def test_the_first_run_of_a_service_asks_nothing_and_uses_the_recommended_setup():
    assert first_run_answers(True) == {"rate_mode": "random", "level": 5, "tor": "onion", "autostart": True}
    assert first_run_answers(False)["tor"] == "off" and first_run_answers(False)["autostart"] is True


def test_a_chromium_without_a_google_key_does_not_keep_asking_safe_browsing_for_updates():
    from pathlib import Path
    src = (Path(__file__).parent.parent / "legalprivacy" / "browser.py").read_text(encoding="utf-8")
    assert '"--log-level=3"' in src and '"--safebrowsing-disable-auto-update"' in src and 'if "chromium" in exe' in src
