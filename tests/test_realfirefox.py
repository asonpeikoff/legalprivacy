"""Your own Firefox on a private copy of your profile: what is copied, what never is, and the visit itself."""
import random
import sqlite3
import threading
from pathlib import Path

from legalprivacy import realfirefox as RF
from legalprivacy.transports import Target


def _profile(root: Path) -> Path:
    p = root / "abc.default-release"
    (p / "extensions").mkdir(parents=True)
    (p / "extensions" / "ublock@raymondhill.net.xpi").write_bytes(b"xpi")
    (p / "browser-extension-data" / "ublock").mkdir(parents=True)
    (p / "browser-extension-data" / "ublock" / "storage.js").write_text("{}")
    (p / "storage" / "default").mkdir(parents=True)
    (p / "storage" / "default" / "secret").write_text("x")
    for name, body in (("prefs.js", 'user_pref("intl.accept_languages", "en-US, en");'), ("extensions.json", "{}"),
                       ("cookies.sqlite", "COOKIES"), ("logins.json", "PASSWORDS"), ("key4.db", "KEYS"),
                       ("formhistory.sqlite", "FORMS")):
        (p / name).write_text(body)
    db = sqlite3.connect(p / "places.sqlite")
    db.executescript("""
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER, last_visit_date INTEGER, frecency INTEGER);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER);
        CREATE TABLE moz_inputhistory (place_id INTEGER, input TEXT);
        CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, fk INTEGER, title TEXT, type INTEGER);
        INSERT INTO moz_places VALUES (1, 'https://aynrand.org/', 40, 1700000000, 900), (2, 'https://example.com/private', 3, 1700000001, 10);
        INSERT INTO moz_historyvisits VALUES (1, 1), (2, 2);
        INSERT INTO moz_inputhistory VALUES (2, 'priv');
        INSERT INTO moz_bookmarks VALUES (1, 1, 'Ayn Rand Institute', 1);
    """)
    db.commit()
    db.close()
    return p


def test_profile_copy_keeps_settings_addons_and_bookmarks_but_never_logins_cookies_or_history(tmp_path):
    src, dst = _profile(tmp_path / "real"), tmp_path / "copy"
    done = RF.copy_profile(src, dst)
    assert {"prefs.js", "extensions.json", "extensions/", "browser-extension-data/", "bookmarks"} <= set(done)
    assert (dst / "extensions" / "ublock@raymondhill.net.xpi").exists()
    assert (dst / "prefs.js").read_text().startswith("user_pref")
    for never in ("cookies.sqlite", "logins.json", "key4.db", "formhistory.sqlite", "storage"):
        assert not (dst / never).exists(), never
    db = sqlite3.connect(dst / "places.sqlite")
    assert db.execute("SELECT title FROM moz_bookmarks").fetchall() == [("Ayn Rand Institute",)]      # bookmarks kept
    assert db.execute("SELECT COUNT(*) FROM moz_historyvisits").fetchone() == (0,)                    # visits wiped
    assert db.execute("SELECT COUNT(*) FROM moz_inputhistory").fetchone() == (0,)
    assert db.execute("SELECT MAX(visit_count) FROM moz_places").fetchone() == (0,)
    db.close()
    assert sqlite3.connect(src / "places.sqlite").execute("SELECT COUNT(*) FROM moz_historyvisits").fetchone() == (2,)   # yours untouched


def test_default_profile_follows_profiles_ini(tmp_path, monkeypatch):
    base = tmp_path / ".mozilla" / "firefox"
    p = _profile(base)
    other = base / "zzz.other"
    other.mkdir()
    (base / "profiles.ini").write_text(f"[Profile0]\nName=default-release\nIsRelative=1\nPath={p.name}\nDefault=1\n"
                                       "[Profile1]\nName=other\nIsRelative=1\nPath=zzz.other\n")
    monkeypatch.setattr("legalprivacy.history._firefox_bases", lambda: [str(base)])
    assert RF.default_profile() == p


def test_snap_and_flatpak_firefox_are_refused_with_a_reason(tmp_path, monkeypatch):
    fake = tmp_path / "snap" / "firefox" / "current" / "firefox"
    fake.parent.mkdir(parents=True)
    fake.write_text("")
    monkeypatch.setattr(RF.shutil, "which", lambda n: str(fake))
    monkeypatch.setattr(RF.Path, "exists", lambda self: str(self) == str(fake))
    exe, why = RF.find_firefox()
    assert exe is None and "Snap" in why


class FakeDriver:
    def __init__(self):
        self.current_url, self.page_source, self.calls, self.cookies_deleted = "about:blank", "<html>ok</html>", [], 0

    def execute_script(self, script, *a):
        if "navigator.userAgent" in script:
            return "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
        if "innerWidth" in script:
            return [1280, 720]
        if "scrollHeight" in script:
            return 3000
        if "responseStatus" in script:
            return 200
        return 0

    def set_page_load_timeout(self, t):
        self.calls.append(("timeout", t))

    def get(self, url):
        self.calls.append(("get", url))
        self.current_url = url

    def find_elements(self, *a):
        return []

    def delete_all_cookies(self):
        self.cookies_deleted += 1

    def quit(self):
        self.calls.append(("quit",))


def test_a_visit_loads_the_page_in_the_users_firefox_and_reads_it_like_a_person(tmp_path):
    prof = _profile(tmp_path / "real")
    fd = FakeDriver()
    t = RF.RealFirefoxTransport("/usr/bin/firefox", prof, stop_event=threading.Event(), scale=lambda: 0.001,
                                rng=random.Random(1), driver_factory=lambda copy: fd)
    res = t.hit(None, Target(url="https://www.aynrand.org/", dwell=2.0))
    assert res.ok and res.status == 200 and "ok" in res.html and res.final_url == "https://www.aynrand.org/"
    assert ("get", "https://www.aynrand.org/") in fd.calls and res.detail == "your Firefox"
    assert t.user_agent and "Firefox/140" in t.user_agent
    copy = t._copy
    assert copy is not None and (copy / "prefs.js").exists()
    t.close()
    assert not copy.exists() and ("quit",) in fd.calls                       # the copy never outlives the browser


def test_a_result_click_falls_back_to_opening_the_address(tmp_path):
    prof = _profile(tmp_path / "real")
    fd = FakeDriver()
    t = RF.RealFirefoxTransport("/usr/bin/firefox", prof, scale=lambda: 0.001, rng=random.Random(2),
                                driver_factory=lambda copy: fd)
    fd.current_url = "https://duckduckgo.com/?q=x"                            # we are on the results page
    res = t.hit(None, Target(url="https://pandas.pydata.org/", referer="https://duckduckgo.com/?q=x", role="result"))
    assert res.ok and ("get", "https://pandas.pydata.org/") in fd.calls       # no link found: opened directly
    t.close()


def test_a_broken_driver_is_reported_not_raised(tmp_path):
    def boom(copy):
        raise RuntimeError("geckodriver not found")
    t = RF.RealFirefoxTransport("/usr/bin/firefox", _profile(tmp_path / "real"), driver_factory=boom)
    res = t.hit(None, Target(url="https://example.org/"))
    assert not res.ok and "Firefox unavailable" in res.error
    t.close()


def test_if_your_firefox_cannot_start_the_apps_own_browser_takes_over(tmp_path):
    class Alt:
        def __init__(self):
            self.hits = []

        def hit(self, identity, target):
            self.hits.append(target.url)
            from legalprivacy.transports import HitResult
            return HitResult(200, "from the app's own browser")

        def close(self):
            self.hits.append("closed")

    def boom(copy):
        raise RuntimeError("geckodriver could not be downloaded")
    alt, events = Alt(), []
    t = RF.RealFirefoxTransport("/usr/bin/firefox", _profile(tmp_path / "real"), driver_factory=boom,
                                alt_factory=lambda: alt, on_event=lambda lvl, msg: events.append((lvl, msg)))
    assert t.hit(None, Target(url="https://example.org/")).ok
    assert t.hit(None, Target(url="https://example.net/")).ok
    assert alt.hits == ["https://example.org/", "https://example.net/"]
    assert len([e for e in events if e[0] == "warn"]) == 1                  # said once, not on every visit
    t.close()
    assert alt.hits[-1] == "closed"
