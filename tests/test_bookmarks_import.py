"""Import bookmarks from Firefox and Chrome (including Flatpak paths) into My List."""
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from legalprivacy import history  # noqa: E402


def _home(monkeypatch=None):
    h = tempfile.mkdtemp()
    os.environ["HOME"] = h
    return Path(h)


def test_reads_chrome_and_firefox_bookmarks_including_flatpak_profiles():
    home = _home()
    chrome = home / ".var/app/com.google.Chrome/config/google-chrome/Default"
    chrome.mkdir(parents=True)
    (chrome / "Bookmarks").write_text(json.dumps({"roots": {"bookmark_bar": {"children": [
        {"type": "url", "url": "https://www.wikipedia.org/wiki/Tor"},
        {"type": "folder", "children": [{"type": "url", "url": "https://news.ycombinator.com/"}]}]}}}))
    ff = home / ".var/app/org.mozilla.firefox/.mozilla/firefox/abc.default"
    ff.mkdir(parents=True)
    db = sqlite3.connect(ff / "places.sqlite")
    db.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT)")
    db.execute("CREATE TABLE moz_bookmarks (id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER)")
    db.execute("INSERT INTO moz_places VALUES (1, 'https://www.bbc.com/news')")
    db.execute("INSERT INTO moz_bookmarks VALUES (1, 1, 1)")
    db.commit()
    db.close()
    res = history.bookmark_sites()
    domains = {d for d, _ in res["sites"]}
    assert {"wikipedia.org", "news.ycombinator.com", "bbc.com"} <= {d.removeprefix("www.") for d in domains}
    assert any("Firefox" in b for b in res["browsers"]) and any("Chrome" in b for b in res["browsers"])


def test_no_browser_gives_a_helpful_hint_about_exporting_a_file():
    _home()
    res = history.bookmark_sites()
    assert res["sites"] == [] and any("From a file" in e for e in res["errors"])
