"""Update check: compares with GitHub, only ever reads, copes with being offline."""
import json

from legalprivacy import updatecheck as U

NEW, OLD = "a" * 40, "b" * 40


def _http(compare_status="ahead", ahead_by=3, fail_compare=False):
    def get(url):
        if url.endswith("/commits/master"):
            return json.dumps({"sha": NEW, "commit": {"message": "Add a thing\n\nmore"}}).encode()
        if "/compare/" in url:
            if fail_compare:
                raise OSError("404")
            return json.dumps({"status": compare_status, "ahead_by": ahead_by}).encode()
        if url.endswith("/releases/latest"):
            return json.dumps({"tag_name": "v9.0.0", "name": "legalPrivacy v9.0.0"}).encode()
        if url == U.RAW_INIT:
            return b'__version__ = "8.0.0"\n'
        raise AssertionError(url)
    return get


def test_same_commit_is_current():
    assert U.check("2.14.0", _http(), commit=NEW)["status"] == "current"


def test_behind_says_by_how_many_and_how_to_update():
    r = U.check("2.14.0", _http(), commit=OLD)
    assert r["status"] == "behind" and r["behind_by"] == 3 and r["how"] == "git pull"
    assert r["latest_message"] == "Add a thing"


def test_your_own_newer_work_is_not_called_out_of_date():
    assert U.check("2.14.0", _http("behind"), commit=OLD)["status"] == "current"
    assert U.check("2.14.0", _http(fail_compare=True), commit=OLD)["status"] == "unknown"


def test_without_git_it_compares_version_numbers(monkeypatch):
    monkeypatch.setattr(U, "local_commit", lambda root=None: None)
    r = U.check("2.14.0", _http())
    assert r["status"] == "behind" and r["latest_version"] == "9.0.0"
    assert U.check("9.0.0", _http())["status"] == "current"


def test_only_https_is_used():
    import pytest
    with pytest.raises(ValueError):
        U._get("http://api.github.com/")


def test_controller_reports_and_survives_being_offline(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path))
    from legalprivacy.controller import Controller
    c = Controller(str(tmp_path / "c.yaml"))
    assert c.update_state()["status"] == "unchecked"

    def boom(v):
        raise OSError("offline")
    assert c.update_check(boom)["status"] == "unchecked"
    s = c.update_check(lambda v: {"status": "behind", "behind_by": 2, "how": "git pull"})
    assert s["status"] == "behind" and s["enabled"] is True


def test_a_downloaded_copy_follows_releases_not_the_newest_commit(monkeypatch):
    monkeypatch.setattr(U, "local_commit", lambda root=None: None)
    r = U.check("2.14.0", _http())
    assert r["latest_version"] == "9.0.0" and r["latest_message"] == "legalPrivacy v9.0.0"      # 9.0.0 release, not 8.0.0 on master


def test_it_falls_back_to_the_version_on_master_when_releases_cannot_be_read(monkeypatch):
    monkeypatch.setattr(U, "local_commit", lambda root=None: None)
    inner = _http()

    def get(url):
        if url.endswith("/releases/latest"):
            raise OSError("404")
        return inner(url)
    r = U.check("2.14.0", get)
    assert r["latest_version"] == "8.0.0" and r["status"] == "behind"
