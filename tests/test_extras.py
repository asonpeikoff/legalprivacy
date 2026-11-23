"""Optional extras: active hours, data cap, typos, search-engine weights, browser-like DNS,
hover and text selection, polite mode, settings validation."""
import os
import random
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from legalprivacy import engines  # noqa: E402
from legalprivacy.config import ConfigError, Profile, apply_overrides  # noqa: E402
from legalprivacy.engines import ENGINE_NAMES, add_typo, build_dns_query, pick_search_endpoint  # noqa: E402
from legalprivacy.humanize import HumanDriver  # noqa: E402
from legalprivacy.rate import RatePlanner  # noqa: E402
from legalprivacy.scheduler import Runner, build_lanes  # noqa: E402
from legalprivacy.transports import HitResult  # noqa: E402


def _runner(extras, probe=None):
    p = Profile(name="t")
    apply_overrides(p, {"extras": extras, "rate": {"mode": "steady", "level": 5}})
    return Runner(profile=p, lanes=build_lanes(p, ["w"]), wordlist=["w"], sleep_fn=lambda s: None,
                  probe_fn=probe or (lambda *a: HitResult(200, "x" * 1000)),
                  rate=RatePlanner(random.Random(1), p.rate), mix=True)


def test_active_hours_rest_outside_the_window_and_wrap_past_midnight():
    r = _runner({"active_hours": True, "active_from": 8, "active_to": 22})
    assert r.plan_hour(3) == 0 and all(b.per_day == 0 for l in r.lanes for b in l.budgets.values())
    assert r.plan_hour(12) > 0
    night = _runner({"active_hours": True, "active_from": 20, "active_to": 2})
    assert night.plan_hour(23) > 0 and night.plan_hour(1) > 0 and night.plan_hour(10) == 0


def test_daily_data_cap_pauses_until_tomorrow():
    from legalprivacy.scheduler import MaxFailuresExceeded
    r = _runner({"daily_data_mb": 0.002})               # 2 kB
    r.plan_hour(12)
    hit_cap = False
    for _ in range(10):
        try:
            r.run_once(wait=False)
        except MaxFailuresExceeded as exc:
            hit_cap = "data cap" in str(exc)
            break
    assert hit_cap and r.bytes_today >= 2000
    r.reset_budgets()
    assert r.bytes_today == 0


def test_typos_are_small_human_slips():
    rng = random.Random(3)
    q = "best hiking boots for beginners"
    for _ in range(50):
        t = add_typo(rng, q)
        assert t != q and abs(len(t) - len(q)) <= 1 and t.split()[0] == "best"


def test_search_engine_weights_and_caps_apply():
    engines._ENGINE_HITS.clear()
    engines.configure_search({n: (10 if n == "Bing" else 0) for n in ENGINE_NAMES})
    picks = {pick_search_endpoint(random.Random(i), now=1e6 + i) for i in range(8)}
    assert picks == {"https://www.bing.com/search?q="}
    engines._ENGINE_HITS.clear()
    engines.configure_search({})
    try:
        apply_overrides(Profile(name="t"), {"extras": {"search_engines": {n: 0 for n in ENGINE_NAMES}}})
        raise AssertionError("all engines off was accepted")
    except ConfigError:
        pass


def test_dns_questions_for_aaaa_and_https_records():
    for qt, code in (("A", 1), ("AAAA", 28), ("HTTPS", 65)):
        pkt = build_dns_query("example.com", 7, qt)
        assert struct.unpack(">HH", pkt[-4:]) == (code, 1)


class _Page:
    mobile = False
    def __init__(self): self.y, self.sel = 0.0, 0
    def viewport(self): return (1280, 720)
    def page_height(self): return 8000
    def scroll_y(self): return self.y
    def move(self, x, y): pass
    def wheel(self, dy): self.y = max(0.0, min(8000 - 720, self.y + dy))
    def sleep(self, s): pass
    def stopped(self): return False
    def select_text(self, x, y, dx):
        self.sel += 1
        return True


def test_reading_includes_hovers_and_occasional_text_selection():
    tot = {"hovers": 0, "selections": 0}
    for seed in range(80):
        s = HumanDriver(random.Random(seed), _Page()).browse()
        tot["hovers"] += s["hovers"]
        tot["selections"] += s["selections"]
    assert tot["hovers"] > 20 and 0 < tot["selections"] < tot["hovers"]


def test_polite_mode_avoids_the_same_site_within_a_minute():
    from legalprivacy.transports import Target
    got = []
    r = _runner({"polite": True}, lambda lane, ident, target: (got.append(target.url), HitResult(200, ""))[1])
    r.plan_hour(12)
    r.clock = lambda: 1000.0
    r._host_last["same.example"] = 990.0                     # visited 10 s ago
    queue = [Target(url="https://same.example/a"), Target(url="https://other.example/b")]
    r._make_target = lambda lane, eng, ident: queue.pop(0) if queue else Target(url="https://x.example/")
    for lane in r.lanes:                                      # only page-type engines this time
        lane.engines = [e for e in lane.engines if e == "crawl"] or lane.engines
        for e in lane.engines:
            lane.budgets[e].per_day, lane.budgets[e].spent = 10, 0
    r.run_once(wait=False)
    assert got == ["https://other.example/b"]
    r2 = _runner({"polite": False}, lambda lane, ident, target: (got.append(target.url), HitResult(200, ""))[1])
    r2.plan_hour(12)
    r2._host_last["same.example"] = r2.clock() - 10
    r2._make_target = lambda lane, eng, ident: Target(url="https://same.example/a")
    got.clear()
    r2.run_once(wait=False)
    assert got == ["https://same.example/a"]                  # off: no change


def test_interest_personas_are_stable_within_a_period_and_change_after():
    from legalprivacy.interests import CATEGORIES, Interests
    t = [0.0]
    it = Interests(random.Random(1), None, 3, 10, "salt", clock=lambda: t[0])
    first = it.active()
    assert len(first) == 3 and all(c in CATEGORIES for c in first)
    t[0] = 9 * 86400
    assert it.active() == first
    changed = False
    for k in range(1, 6):
        t[0] = k * 10 * 86400 + 1
        changed |= it.active() != first
    assert changed
    other = Interests(random.Random(1), None, 3, 10, "another-salt", clock=lambda: 0.0)
    assert sorted(CATEGORIES)  # and different installs usually differ:
    assert other.active() != first or len(CATEGORIES) <= 3
    only = Interests(random.Random(2), ["Cooking", "Books"], 3, 10, "s")
    assert set(only.active()) == {"Cooking", "Books"}


def test_interest_share_steers_sites_and_searches():
    from legalprivacy.domains import DomainPool
    from legalprivacy.interests import CATEGORIES, Interests
    from legalprivacy.queries import QuerySource
    it = Interests(random.Random(3), ["Gardening"], 1, 10, "s")
    pool = DomainPool(random.Random(4), None)
    pool.interests, pool.interest_share = it, 0.5
    picks = [pool.pick(browsable=True) for _ in range(1000)]
    share = sum(p in CATEGORIES["Gardening"]["sites"] for p in picks) / len(picks)
    assert 0.38 < share < 0.62
    qs = QuerySource(random.Random(5), None)
    qs.interests, qs.interest_share = it, 1.0
    q, origin = qs.next()
    assert origin == "interest"


def test_netwatch_rate_excludes_our_own_bytes_and_tracks_idle():
    from legalprivacy.netwatch import NetWatch, total_bytes
    vals, t = [1_000_000, 1_000_000 + 250_000], [0.0]
    nw = NetWatch(reader=lambda: vals.pop(0), clock=lambda: t[0])
    nw.sample()
    t[0] = 10.0
    rate = nw.sample(own_bytes_since_last=50_000)
    assert abs(rate - 160.0) < 0.5                         # 200 kB in 10 s = 160 kbit/s
    assert total_bytes() is None or total_bytes() >= 0     # real counters readable here (or unknown)


def test_backoff_pauses_while_busy():
    r = _runner({"activity": "backoff", "busy_kbps": 100})
    from legalprivacy.netwatch import NetWatch
    nw = NetWatch(reader=lambda: 0)
    nw.rate_kbps = 900.0
    r._netwatch, r._nw_next, r._nw_bytes, r._nw_said = nw, 1e18, 0, ""
    slept = []
    r.sleep_fn = slept.append
    assert r._activity_says_wait() and slept == [30.0]
    nw.rate_kbps = 5.0
    assert not r._activity_says_wait()


def test_estimate_and_privacy_check_have_the_expected_shape():
    import tempfile
    os.environ["LEGALPRIVACY_HOME"] = tempfile.mkdtemp()
    from legalprivacy.controller import Controller
    c = Controller()
    e = c.estimate()
    assert e["mb_per_day"] >= 0 and e["gb_per_month"] >= 0 and e["hours_per_day"] == 15.0
    c.apply_config({"extras": {"daily_data_mb": 1}})
    assert c.estimate()["mb_per_day"] <= 1
    names = {x["name"] for x in c.privacy_check()}
    assert {"Content blocker", "VPN", "Encrypted DNS", "Real browser for noise"} <= names


def test_betting_and_adult_names_are_filtered_without_blocking_lookalikes():
    from legalprivacy.safety import safe_domain
    for bad in ("www.betano.pe", "crocobet.com", "1xbet.com", "dpbossnet.me", "hi.faphouse2.com",
                "javwow.com", "olxtoto818.com", "slots77.com", "livecamrips.to"):
        assert not safe_domain(bad), bad
    for ok in ("www.betterhelp.com", "alphabet.com", "www.tibet.net", "beta.nptel.ac.in", "hindi.news18.com",
               "slotted.example.com", "www.youtube.com", "dictionary.cambridge.org"):
        assert safe_domain(ok), ok


def test_crux_only_reranks_sites_already_on_the_safe_list():
    from legalprivacy.domains import DomainPool
    from legalprivacy.feeds import parse_crux

    class Store:
        def items(self, name):
            return {"tranco": ["alpha-example.com", "beta-example.org", "gamma-example.net"],
                    "crux": ["gamma-example.net|1000", "only-in-crux.example|1000"]}.get(name, [])
        def denylist(self):
            return set()
    pool = DomainPool(random.Random(1), Store())
    picks = [pool.pick() for _ in range(3000)]
    assert "only-in-crux.example" not in picks                   # never a source on its own
    assert picks.count("gamma-example.net") > picks.count("beta-example.org")   # boosted by real browsing
    pool.site_list = "tranco"
    pool._boost_cache = None
    assert pool._crux_boost() == {}
    assert parse_crux("origin,rank\nhttps://www.example.com,1000\nhttps://www.betano.pe,1000\nhttps://x.example,100000\n") \
        == ["www.example.com|1000"]


def test_household_members_keep_their_devices_and_follow_their_hours():
    from legalprivacy.household import Household
    from legalprivacy.useragents import sample_entry
    t = [1_800_000_000.0]
    hh = Household(4, "salt", clock=lambda: t[0], sample_entry=sample_entry)
    ms = hh.members()
    assert len(ms) == 4 and ms[0]["entry"] is None and all(m["entry"] for m in ms[1:])
    assert hh.members() is ms                                         # same period: same people
    rng = random.Random(1)
    for h in (3, 10, 20):
        picks = [hh.pick(rng, h)["id"] for _ in range(2000)]
        awake = {m["id"] for m in ms if hh._awake(m["hours"], h)}
        if awake and len(awake) < len(ms):
            assert sum(p in awake for p in picks) / len(picks) > 0.7      # mostly whoever's awake
    redrawn = False
    for k in range(1, 8):                                             # a later period: new people
        t[0] = 1_800_000_000.0 + k * 100 * 86400
        redrawn |= [(m["rhythm"], (m["entry"] or {}).get("ua")) for m in hh.members()] != \
                   [(m["rhythm"], (m["entry"] or {}).get("ua")) for m in ms]
    assert redrawn


def test_household_identities_come_from_several_browsers():
    r = _runner({"household": True, "household_size": 4, "interest_salt": "abc"})
    uas = {r._entry_for_next_identity()["ua"] for _ in range(200)}
    assert len(uas) >= 2


def test_top_result_is_clicked_about_half_the_time():
    import legalprivacy.engines as E
    from legalprivacy.engines import SearchTargetFactory
    real = E.extract_result_links
    E.extract_result_links = lambda html, u: [f"https://r{i}.example.com/" for i in range(10)]
    try:
        f = SearchTargetFactory(rng=random.Random(2), words=["w"])
        picks = [f.result_target("", "https://www.google.com/search?q=x").url for _ in range(4000)]
    finally:
        E.extract_result_links = real
    assert 0.45 < picks.count("https://r0.example.com/") / len(picks) < 0.55


def test_offline_onion_sites_are_quiet_and_rested():
    from legalprivacy.scheduler import _onion_offline
    r = _runner({})
    assert _onion_offline(HitResult(None, error="SOCKS error: Host unreachable"))
    assert not _onion_offline(HitResult(None, error="HTTP 500"))
    url = "http://" + "a" * 56 + ".onion/"
    r._onion_seen_dead(url)
    assert not r._onion_is_dead(url)                           # one miss: try again later
    r._onion_seen_dead(url)
    assert r._onion_is_dead(url)                               # two misses: rest it for hours


def test_login_walls_are_recognised_but_public_pages_are_not():
    from legalprivacy.loginwall import looks_like_login_wall as w
    assert w("https://www.facebook.com/login/?next=https%3A%2F%2Fwww.facebook.com%2Fgroups%2F1")
    assert w("https://www.instagram.com/accounts/login/?next=/someone/")
    assert w("https://www.linkedin.com/authwall?trk=bf")
    assert w("https://x.com/i/flow/login")
    assert w("https://www.facebook.com/somepage", "Facebook", "See more on Facebook. Log in to continue")
    assert w("https://example.com/members", html='<form><input name=u><input type="password" name=p></form>')
    article = "<a href='/login'>Log in</a><p>" + "words " * 2000 + "</p>"
    assert not w("https://news.example.com/story", html=article)           # a login link isn't a wall
    assert not w("https://www.facebook.com/somepublicpage", "Public Page | Facebook",
                 "About · Photos · Posts · 12,000 people like this")


def test_a_login_wall_is_not_a_failure_and_the_site_rests():
    from legalprivacy.transports import Target
    seen = []
    wall = '<html><title>Log in</title><form><input type="password"></form></html>'
    r = _runner({}, lambda lane, ident, target: (seen.append(target.url),
                HitResult(200, wall if "walled" in target.url else "<p>" + "ok " * 900 + "</p>"))[1])
    r.plan_hour(12)
    queue = [Target(url="https://walled.example.com/a"), Target(url="https://walled.example.com/b"),
             Target(url="https://open.example.org/c")]
    r._make_target = lambda lane, eng, ident: queue.pop(0) if queue else Target(url="https://x.example.net/")
    for lane in r.lanes:
        lane.engines = [e for e in lane.engines if e == "crawl"] or lane.engines
        for e in lane.engines:                                   # make sure this hour has visits to make
            lane.budgets[e].per_day, lane.budgets[e].spent = 10, 0
    r.run_once(wait=False)
    assert seen == ["https://walled.example.com/a"] and r.day_failures == 0
    assert r._host_rested("https://walled.example.com/anything")
    r.run_once(wait=False)
    assert seen[-1] == "https://open.example.org/c"                       # skipped the rested site
    assert r.hit_log[0]["ok"] and "login required" in (r.hit_log[0]["detail"] or "")


def test_logs_clear_on_each_start_by_default_and_can_be_kept():
    import tempfile
    os.environ["LEGALPRIVACY_HOME"] = tempfile.mkdtemp()
    from legalprivacy.controller import Controller
    c = Controller()
    assert c.app["clear_logs_on_restart"] is True
    c.apply_config({"transports": {"clearnet": {"browser": "off"}}})
    c.log.info("app", "from before")
    c.start(); c.stop()
    assert not any(e["message"] == "from before" for e in c.log.since(0)) and c.state()["log_epoch"] == 1
    c.runner._hit_seq = 41                                     # pretend the last run made 41 requests
    c.update_app({"clear_logs_on_restart": False})
    c.log.info("app", "keep me")
    c.start(); c.stop()
    assert any(e["message"] == "keep me" for e in c.log.since(0)) and c.state()["log_epoch"] == 1
    assert c.runner._hit_seq >= 41                             # numbering continues, so Activity keeps updating


def test_data_scientist_persona_is_followed_mostly_not_perfectly():
    import tempfile
    from legalprivacy.interests import CATEGORIES, PERSONAS
    os.environ["LEGALPRIVACY_HOME"] = tempfile.mkdtemp()
    from legalprivacy.controller import Controller
    c = Controller()
    c.apply_config({"extras": {"persona": "Data scientist"}})
    assert c.profile.extras.persona_share == 0.9
    pool = c._domain_pool(random)
    themed = {s.split("/")[0] for t in PERSONAS["Data scientist"] for s in CATEGORIES[t]["sites"]}
    picks = [pool.pick(browsable=True) for _ in range(3000)]
    share = sum(p in themed for p in picks) / len(picks)
    assert 0.8 < share < 0.97                                   # mostly on theme, not all of it
    qs = c._query_source([])
    origins = [qs.next()[1] for _ in range(400)]
    assert 0.75 < origins.count("interest") / len(origins) < 0.97
    try:
        c.apply_config({"extras": {"persona": "Astronaut"}})
        raise AssertionError("unknown persona accepted")
    except Exception as exc:
        assert "unknown persona" in str(exc)


def test_popular_data_science_sites_come_up_more_and_real_searches_are_used():
    from legalprivacy.interests import Persona, real_queries
    rng = random.Random(5)
    p = Persona(rng, "Data scientist")
    picks = [p.site() for _ in range(6000)]
    assert picks.count("arxiv.org") > 4 * picks.count("distill.pub")              # very high vs low
    assert "www.reddit.com/r/datascience/" in picks                               # a section of a site, as listed
    real = set(real_queries("Data science"))
    assert len(real) > 5000
    qs = [p.query() for _ in range(500)]
    assert 0.55 < sum(q in real for q in qs) / len(qs) < 0.95                      # mostly real people's wording (some are everyday searches)


def test_foreign_language_sites_and_pages_are_skipped():
    from legalprivacy.engines import CrawlTargetFactory
    from legalprivacy.safety import english_host, english_url, page_language
    assert not english_host("www.spiegel.de") and not english_host("de.wikipedia.org") and not english_host("x.co.jp")
    assert english_host("en.wikipedia.org") and english_host("pola.rs") and english_host("huggingface.co")
    assert english_host("bbc.co.uk") and english_host("fast.ai")
    assert not english_url("https://example.com/de/") and not english_url("https://example.com/pt-br/x")
    assert english_url("https://example.com/en-gb/") and english_url("https://example.com/docs/")
    assert page_language('<html lang="de-DE"><body>') == "de" and page_language("<html><body>") is None
    html = '<a href="/de/seite">a</a><a href="/fr/page">b</a><a href="/guide">c</a>'
    f = CrawlTargetFactory(rng=random.Random(1), seeds=["https://example.com/"])
    assert {f.next_from(html, "https://example.com/").url for _ in range(30)} == {"https://example.com/guide"}


def test_a_page_in_another_language_is_left_quickly_and_the_site_rested():
    r = _runner({}, probe=lambda *a: HitResult(200, '<html lang="fr"><a href="/x">x</a></html>'))
    for l in r.lanes:
        for e in l.engines:
            l.budgets[e].per_day, l.budgets[e].spent = 10, 0
    for _ in range(40):
        r.run_once(wait=False)
    pages = [h for h in r.hit_log if h["engine"] == "crawl"]
    assert pages and all(h["detail"] == "not in English: moved on" for h in pages)
    assert r._host_rested(pages[0]["url"])


def test_data_scientist_persona_also_has_everyday_life():
    from legalprivacy.interests import CATEGORIES, PERSONAS, Persona
    assert PERSONAS["Data scientist"]["Data science"] > 0.7 and PERSONAS["Data scientist"]["Everyday"] >= 0.1
    p = Persona(random.Random(9), "Data scientist")
    picks = [p.site() for _ in range(6000)]
    everyday = set(CATEGORIES["Everyday"]["sites"])
    share = sum(x in everyday for x in picks) / len(picks)
    assert 0.1 < share < 0.2
    assert picks.count("mail.google.com") > 20 and picks.count("outlook.live.com") > 10
    qs = [p.query() for _ in range(1000)]
    assert any(q.endswith("near me") or q.startswith("best ") or q.endswith(" reviews") for q in qs)


def test_builtin_onion_list_is_valid_unique_and_has_no_directories():
    from legalprivacy.onion import BUILTIN_ONION_SEEDS, builtin_site_name, is_valid_v3_onion
    urls = [u for _, u in BUILTIN_ONION_SEEDS]
    assert len(urls) >= 30 and len(set(urls)) == len(urls)
    assert all(is_valid_v3_onion(u.split('/')[2]) for u in urls)                     # every address passes the v3 checksum
    assert not any("dark.fail" in n.lower() for n, _ in BUILTIN_ONION_SEEDS)     # link directories lead to anything
    assert builtin_site_name("http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/docs") == "Tor Project"


def test_onion_walk_never_leaves_the_vetted_list():
    import random as _r
    from legalprivacy.onion import BUILTIN_ONION_SEEDS, OnionTargetFactory
    a, b = BUILTIN_ONION_SEEDS[0][1], BUILTIN_ONION_SEEDS[1][1]
    stranger = "http://" + "a" * 56 + ".onion/"                           # not on the list (and not even valid)
    stranger2 = "http://" + "b" * 55 + "d.onion/market"
    html = f'<a href="{stranger}">x</a><a href="{stranger2}">y</a><a href="{a}docs">same</a><a href="{b}">listed</a>'
    f = OnionTargetFactory(rng=_r.Random(1))
    picks = {f.next_from(html, a).url for _ in range(100)}
    assert picks <= {a + "docs", b}
    assert not OnionTargetFactory(rng=_r.Random(1), follow_offsite=False).next_from(f'<a href="{b}">listed</a>', a)


def test_onion_list_has_no_facebook_and_has_the_cross_checked_additions():
    from legalprivacy.onion import BUILTIN_ONION_SEEDS, is_valid_v3_onion
    names = {n for n, _ in BUILTIN_ONION_SEEDS}
    assert "Facebook" not in names
    assert {"Whonix", "OnionShare", "Cryptostorm VPN", "XMPP.is"} <= names
    assert not names & {"The Tor Times", "Keybase", "Archive.today", "The Intercept"}      # could not be verified
    assert all(is_valid_v3_onion(u.split("/")[2]) for _, u in BUILTIN_ONION_SEEDS)
    assert len({u for _, u in BUILTIN_ONION_SEEDS}) == len(BUILTIN_ONION_SEEDS)


def test_a_broken_certificate_counts_as_a_site_that_is_down_and_is_remembered(tmp_path, monkeypatch):
    from legalprivacy.scheduler import _onion_offline
    assert _onion_offline(HitResult(None, error="SOCKSHTTPSConnectionPool(host='x.onion'): SSLError(SSLCertVerificationError)"))
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    r = _runner({}, probe=lambda *a: HitResult(200, "x"))
    r.rate = object()                                   # app mode: kept between runs
    url = "http://" + "a" * 56 + ".onion/"
    r._onion_seen_dead(url)
    r._onion_seen_dead(url)
    assert r._onion_is_dead(url)
    r2 = _runner({}, probe=lambda *a: HitResult(200, "x"))
    r2.rate = object()
    assert r2._onion_is_dead(url)                       # a new run still knows it was down
    r2._onion_seen_alive(url)
    assert not r2._onion_is_dead(url)
