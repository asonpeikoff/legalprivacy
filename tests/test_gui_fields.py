"""Pure logic behind the desktop app's settings: the 100% mixes, the control <-> profile mapping and the
small formatters. No display needed."""
import os
import tempfile

from legalprivacy import gui_fields as F
from legalprivacy import gui_logic as L


# ── mixes ───────────────────────────────────────────────────────────────────
def test_mix_normalize():
    assert F.mix_normalize([100, 0, 15]) == [100 / 115 * 100, 0.0, 15 / 115 * 100]
    assert F.mix_normalize([0, 0, 0, 0]) == [25.0] * 4
    assert abs(sum(F.mix_normalize([3, 9, 1.5])) - 100) < 1e-9
    assert F.mix_normalize([]) == []


def test_mix_adjust_keeps_the_total_and_shares_the_difference_in_proportion():
    vals = F.mix_normalize([60, 30, 10])
    out = F.mix_adjust(vals, 0, 40)
    assert abs(sum(out) - 100) < 1e-9 and out[0] == 40
    assert abs(out[1] / out[2] - 3.0) < 1e-9                  # the others keep their ratio
    out = F.mix_adjust(vals, 0, 100)
    assert out == [100.0, 0.0, 0.0]                           # everything else gives way
    assert F.mix_adjust([100.0, 0.0, 0.0], 0, 70) == [70.0, 15.0, 15.0]    # nothing to scale: split evenly
    assert F.mix_adjust([100.0], 0, 20) == [20.0]            # a single part cannot leave a remainder anywhere
    assert F.mix_adjust(vals, 1, 250)[1] == 100.0 and F.mix_adjust(vals, 1, -5)[1] == 0.0


def test_mix_adjust_zero_means_off_and_can_come_back():
    vals = F.mix_adjust(F.mix_normalize([50, 50]), 0, 100)
    assert vals == [100.0, 0.0]
    back = F.mix_adjust(vals, 1, 30)
    assert back == [70.0, 30.0]


def test_mix_text_and_engine_settings():
    assert F.mix_percent_text(0) == "0%" and F.mix_percent_text(4.26) == "4.3%" and F.mix_percent_text(37.4) == "37%"
    eng = F.engines_from_mix({"search": 30, "dns": 0, "crawl": 12.5})
    assert eng["dns"] == {"enabled": False, "budget_per_day": 0}
    assert eng["search"] == {"enabled": True, "budget_per_day": 300} and eng["crawl"]["budget_per_day"] == 125


def test_traffic_items_follow_tor():
    t = {"mix_browser": 100, "mix_plain": 0, "mix_onion": 15}
    assert [i["key"] for i in F.traffic_items(t, False)] == ["mix_browser", "mix_plain"]
    assert [i["key"] for i in F.traffic_items(t, True)][-1] == "mix_onion"
    eng = {"search": 1, "crawl": 1, "dns": 1, "onion": 1, "packages": 1}
    assert F.visible_engines(eng, False, False) == ["search", "crawl", "dns"]
    assert F.visible_engines(eng, True, True) == list(eng)


# ── mapping ─────────────────────────────────────────────────────────────────
def test_every_field_path_exists_in_the_profile():
    from legalprivacy.config import Profile
    vals = F.read_fields(Profile(name="x"))
    assert set(vals) == set(F.FIELDS)


def test_payload_kinds():
    p = F.fields_payload({"dns_share": 30, "proxy": "  ", "tor_seeds": "http://a.onion/\nhttp://b.onion/",
                          "data_cap": "12", "active_from": "7", "persona_share": 90, "speed": 1.5})
    assert p["dns"]["system_share"] == 0.3 and p["transports"]["clearnet"]["proxy"] is None
    assert p["transports"]["tor"]["onion_seeds"].count("\n") == 1
    assert p["extras"] == {"daily_data_mb": 12.0, "active_from": 7, "persona_share": 0.9}
    assert abs(p["realtime_scale"] - 1 / 1.5) < 1e-9          # time compression 1.5x = waits 1/1.5 as long
    assert F.fields_payload({}) == {}


def test_randomness_slider_wins_and_steady_at_zero():
    assert F.build_config_payload({"randomness": 0})["rate"] == {"mode": "steady", "randomness": 0.0}
    assert F.build_config_payload({"randomness": 60, "level": 4})["rate"] == {"level": 4.0, "mode": "random", "randomness": 0.6}


def test_user_agent_choice_mapping():
    for choice in ("own", "rotate-hour", "rotate-day", "lib"):
        ident = F.ua_choice_to_identity(choice, "chrome-120-win")
        back = F.ua_choice_from_identity(ident["ua_mode"], ident.get("rotate_every", "hour"), ident.get("ua_pin", "own"))
        assert back == choice
    assert F.ua_choice_to_identity("lib", "x")["ua_pin"] == "x"
    assert F.build_config_payload({"ua_choice": "rotate-day"})["identity"] == {"ua_mode": "rotate", "rotate_every": "day"}


def test_every_control_value_survives_a_save_and_reload():
    from legalprivacy.controller import Controller
    ctl = Controller(os.path.join(tempfile.mkdtemp(), "p.yaml"))
    try:
        v = F.profile_values(ctl.profile, ctl.app)
        ctl.apply_config(F.build_config_payload(v, {"randomness": 1.0}))
        back = F.profile_values(ctl.profile, ctl.app)
        assert {k: (v[k], back[k]) for k in v if v[k] != back[k] and k != "engines_mix"} == {}
        # and a real edit of many cards at once is accepted
        v.update(dns_share=20, dns_opennic=True, typos=True, active_hours=True, active_from=9, persona="Developer",
                 mobile_share=40, mix_browser=60, mix_plain=40, mylist_enabled=True, mylist_sites=["example.com"],
                 mylist_weights={"example.com": 7}, q_words=False, interest_list=["Cooking"] if False else [],
                 accounts={"google": {"enabled": False, "per_hour": 2, "per_day": 9, "on_challenge": "pause"}})
        ctl.apply_config(F.build_config_payload(v, {"randomness": 1.0}))
        again = F.profile_values(ctl.profile, ctl.app)
        for k in ("dns_share", "dns_opennic", "typos", "active_from", "persona", "mobile_share", "mix_plain",
                  "mylist_sites", "q_words"):
            assert again[k] == v[k], k
        assert again["accounts"]["google"]["per_hour"] == 2 and again["mylist_weights"] == {"example.com": 7.0}
    finally:
        ctl.observer.stop()


# ── formatters ──────────────────────────────────────────────────────────────
def test_resolver_verdict_words():
    assert F.resolver_verdict(None)[0] == "not checked"
    assert F.resolver_verdict({"verdict": "ok", "rtt_ms": 12, "egress": "1.2.3.4"}) == ("✓ 12 ms verified", "ok", "")
    assert F.resolver_verdict({"verdict": "hijack"})[0].startswith("✗ hijacks") and F.resolver_verdict({"verdict": "hijack"})[1] == "bad"
    assert F.resolver_verdict({"verdict": "disagrees"})[0].startswith("✗ disagrees")
    assert F.resolver_verdict({"verdict": "disputed"})[:2] == ("? servers disagree", "warn")
    assert F.resolver_verdict({"verdict": "down", "error": "timeout"})[0] == "✗ timeout"


def test_account_text():
    assert F.account_status_text({"state": "signed_out"}) == ("Signed out", "off")
    assert F.account_status_text({"state": "signed_in"})[1] == "ok"
    assert F.account_status_text({"state": "needs_attention", "attention_until": 1700000000})[0].startswith("Paused until about")
    a = {"state": "signed_in", "visits_hour": 1, "per_hour": 3, "visits_day": 4, "per_day": 12}
    assert F.account_note(a) == "1 of 3 visits this hour, 4 of 12 today."
    assert F.account_note({"state": "signed_out", "signin": {"state": "waiting", "message": "Sign in in the window"}}) == "Sign in in the window"


def test_feed_row_and_misc_text():
    now = 1_000_000
    assert F.feed_row({"name": "trends", "count": 1200, "updated": now - 7200, "origin": "shipped"}, now) == \
        ("Google Trends", "1,200", "shipped", "2 h ago", "ok")
    assert F.feed_row({"name": "wiki", "count": 0}, now)[4] == "missing"
    assert F.feed_row({"name": "news", "count": 4, "stale": True}, now)[4].startswith("old")
    assert F.feed_row({"name": "news", "error": "boom" * 30}, now)[4].startswith("unavailable")
    assert F.mylist_weight_label(1) == "Rarely" and F.mylist_weight_label(10) == "Very often"
    assert F.weight_from_rank(0, 100) == 10 and F.weight_from_rank(99, 100) == 1 and F.weight_from_rank(5, 10, True) == 3
    assert F.rand_text(0).startswith("Steady") and F.rand_text(100).startswith("Fully") and "50% random" in F.rand_text(50)
    assert "Nothing" in F.level_scope(False, False) and ".onion" in F.level_scope(True, True)
    assert "250 MB a day" in F.estimate_text({"mb_per_day": 250, "gb_per_month": 7.5, "actions_per_hour": 20,
                                              "hours_per_day": 15, "real_browser": True, "low_data": False, "cap_mb": 0})


def test_urls_from_text():
    html = '<A HREF="https://example.com/a">x</A> <a href="http://news.org/b?q=1">y</a> https://example.com/a'
    assert F.urls_from_text(html) == ["https://example.com/a", "http://news.org/b?q=1"]
    assert F.urls_from_text("example.org\nfoo.net,12\nnot a site") == ["https://example.org", "https://foo.net"]
    assert F.urls_from_text("") == []


def test_gui_logic_still_exposes_the_old_names():
    assert L.build_config_payload is F.build_config_payload and L.profile_values is F.profile_values
    assert len(L.PALETTES["light"]) == len(L.PALETTES["dark"]) and len(L.MIX_COLORS) >= 5
