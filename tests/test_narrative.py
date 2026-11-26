import random

from legalprivacy.narrative import chat_script, coherence, follow_ups, tokens
from legalprivacy.queries import QuerySource


class _Who:
    id = 1


def test_follow_ups_stay_on_the_topic_and_a_comparison_uses_a_related_query():
    rng = random.Random(2)
    ups = follow_ups(rng, "sourdough bread recipe", ["bread machine reviews", "linux kernel"])
    assert 1 <= len(ups) <= 4 and all(tokens("sourdough bread recipe") & tokens(u) for u in ups[:1])
    seen = set()
    for i in range(60):
        seen.update(follow_ups(random.Random(i), "sourdough bread recipe", ["bread machine reviews"]))
    assert any(" vs bread machine reviews" in u for u in seen)
    assert follow_ups(rng, "a very long query with far too many words in it", None) == []


def test_searches_come_in_related_runs_more_than_random_ones():
    def run(share):
        qs = QuerySource(random.Random(11), None)
        qs.narrative_share = share
        return coherence([qs.next(_Who())[0] for _ in range(200)])
    assert run(0.55) > run(0.0) + 0.05


def test_chat_scripts_vary_in_turns_and_length_and_stay_on_one_topic():
    lens, turns = set(), set()
    for i in range(80):
        s = chat_script(random.Random(i), "indoor plants low light")
        turns.add(len(s))
        lens.add(len(s[0].split()))
        assert "indoor plants low light" in s[0]
    assert turns == {1, 2, 3, 4} and len(lens) > 5


def test_a_long_session_on_duck_ai_becomes_a_chat_only_when_chat_noise_is_on():
    from legalprivacy.config import Profile
    from legalprivacy.scheduler import Runner
    from legalprivacy.transports import HitResult

    def lane_with(duck_chat):
        from legalprivacy.scheduler import Budget, Lane
        from legalprivacy.transports import Transport

        class T(Transport):
            def hit(self, identity, target):
                return HitResult(200, "")
        ln = Lane(name="clearnet", transport=T(), engines=["crawl"], budgets={"crawl": Budget(per_day=5)})
        p = Profile(name="default")
        p.extras.duck_chat = duck_chat
        r = Runner(profile=p, lanes=[ln], wordlist=["alpha"], clock=lambda: 1000.0, sleep_fn=lambda s: None,
                   probe_fn=lambda l, i, t: HitResult(200, ""))
        r.rng = random.Random(4)                                  # seeded: the chat is chosen at random
        ln.linger = {"mode": "work", "url": "https://duck.ai/", "engine": "crawl", "exclusive": False, "chat": True,
                     "until": 1e9, "next_at": 0.0, "other_at": 1e9}
        return r, ln
    r, ln = lane_with(True)
    ln.budgets["crawl"].spent = 0
    got = [r._linger_due([]) for _ in range(30)]
    chats = [g[2] for g in got if g and g[2].role == "chat"]
    assert chats and all(c.script and c.accept_terms for c in chats) and len(chats) <= 2
    r, ln = lane_with(False)
    assert all(g is None or g[2].role != "chat" for g in [r._linger_due([]) for _ in range(30)])


def test_chat_noise_and_the_other_extras_switches_survive_a_settings_change():
    from legalprivacy.config import Profile, apply_overrides
    p = apply_overrides(Profile(name="default"), {"extras": {"duck_chat": True, "long_sessions": False, "multi_tab": False}})
    assert p.extras.duck_chat is True and p.extras.long_sessions is False and p.extras.multi_tab is False


def test_the_chat_runs_in_a_real_browser_against_a_stand_in_chat_page(tmp_path):
    import http.server
    import random
    import threading

    import pytest
    pw = pytest.importorskip("playwright.sync_api")
    from legalprivacy import browser as B
    from legalprivacy.humanize import HumanDriver
    from legalprivacy.transports import Target
    (tmp_path / "index.html").write_text(
        "<div id=m><button onclick=\"document.getElementById('m').remove()\">Continue</button></div><div id=log></div>"
        "<textarea></textarea><script>const ta=document.querySelector('textarea');ta.addEventListener('keydown',e=>{"
        "if(e.key==='Enter'){e.preventDefault();const d=document.createElement('p');d.textContent='YOU: '+ta.value;ta.value='';"
        "document.getElementById('log').append(d);const r=document.createElement('p');document.getElementById('log').append(r);"
        "let i=0;const t=setInterval(()=>{r.textContent+='w ';if(++i>5)clearInterval(t)},80)}})</script>")
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=str(tmp_path), **k)  # noqa: E731
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pw.sync_playwright() as p:
            try:
                b = p.chromium.launch(args=["--no-sandbox"])
            except Exception:
                try:
                    b = p.chromium.launch(executable_path="/opt/pw-browsers/chromium", args=["--no-sandbox"])
                except Exception:
                    pytest.skip("no browser installed")
            page = b.new_context().new_page()
            t = B.BrowserTransport.__new__(B.BrowserTransport)
            t.rng, t.stop_event, t.scale, t._doing = random.Random(1), threading.Event(), (lambda: 0.02), (lambda *a, **k: None)
            drv = HumanDriver(t.rng, B.PlaywrightActuator(page, False, t.stop_event, None), scale=0.02)
            url = f"http://127.0.0.1:{srv.server_port}/"
            no = t._chat_hit(page, drv, Target(url=url, role="chat", script=["hello"], accept_terms=False, timeout=15), {})
            assert "terms screen" in no.detail
            page.goto("about:blank")
            ok = t._chat_hit(page, drv, Target(url=url, role="chat", script=["hello", "more"], accept_terms=True, timeout=15), {})
            assert ok.detail == "chat: 2 messages" and page.locator("#log p").count() == 4
            b.close()
    finally:
        srv.shutdown()
