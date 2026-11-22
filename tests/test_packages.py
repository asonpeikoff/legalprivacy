"""Package-manager noise: real pip/npm commands in a throwaway environment."""
import os
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from legalprivacy.config import ConfigError, Profile, apply_overrides  # noqa: E402
from legalprivacy.packages import DATA_SCIENCE, GENERAL, NPM, PackageNoise, downloaded_bytes  # noqa: E402
from legalprivacy.scheduler import build_lanes  # noqa: E402


def _fake(calls, rc=0, out="Downloading numpy-2.1.0-cp312.whl (16.3 MB)\n"):
    def run(cmd, timeout):
        calls.append(cmd)
        if cmd[1:3] == ["-m", "venv"]:
            vpy = Path(cmd[3]) / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            vpy.parent.mkdir(parents=True, exist_ok=True)
            vpy.write_text("")
            return 0, ""
        return rc, out
    return run


def test_automatic_means_on_for_techy_personas_only():
    p = Profile(name="t")
    assert p.extras.persona == "Data scientist" and "packages" in p.active_engines("clearnet")
    apply_overrides(p, {"extras": {"persona": ""}})
    assert "packages" not in p.active_engines("clearnet")
    apply_overrides(p, {"extras": {"persona": "Data scientist"}})
    assert "packages" in p.active_engines("clearnet")
    apply_overrides(p, {"extras": {"persona": "Data scientist", "packages": "off"}})
    assert "packages" not in p.active_engines("clearnet")
    apply_overrides(p, {"extras": {"persona": "", "packages": "on"}})
    assert "packages" in p.active_engines("clearnet")


def test_never_over_tor_and_not_on_the_plain_lane():
    p = Profile(name="t")
    apply_overrides(p, {"extras": {"packages": "on"}, "transports": {"tor": {"enabled": True}}})
    assert "packages" not in p.active_engines("tor")
    lanes = build_lanes(p, ["w"], plain_transport=object())
    by = {l.name: l.engines for l in lanes}
    assert "packages" in by["clearnet"] and "packages" not in by.get("clearnet-plain", [])


def test_bad_setting_is_refused():
    try:
        apply_overrides(Profile(name="t"), {"extras": {"packages": "maybe"}})
        assert False
    except ConfigError:
        pass


def test_install_only_ready_built_and_ignores_your_pip_config():
    with tempfile.TemporaryDirectory() as d:
        calls = []
        pk = PackageNoise(Path(d) / "p", random.Random(1), run_fn=_fake(calls))
        cmd = pk.command("install", "numpy")
        assert "--only-binary=:all:" in cmd and str(pk.venv) in cmd[0]
        env = pk._env()
        assert env["PIP_CONFIG_FILE"] == os.devnull and "PIP_INDEX_URL" not in env
        r = pk.do("install", "numpy")
        assert r["ok"] and r["label"] == "pip install numpy" and r["bytes"] == 16_300_000
        assert pk.installed == ["numpy"]


def test_installs_are_removed_again_and_downloads_never_kept():
    with tempfile.TemporaryDirectory() as d:
        calls = []
        pk = PackageNoise(Path(d) / "p", random.Random(1), run_fn=_fake(calls))
        for name in ["a", "b", "c", "d", "e", "f"]:
            pk.do("install", name)
        assert len(pk.installed) == 4
        assert [c[-1] for c in calls if "uninstall" in c] == ["a", "b"]
        pk.do("uninstall", "c")
        assert "c" not in pk.installed
        pk.do("download", "numpy")
        assert not [x for x in (Path(d) / "p").iterdir() if x.name.startswith("dl-")]


def test_environment_is_rebuilt_when_old():
    with tempfile.TemporaryDirectory() as d:
        calls = []
        pk = PackageNoise(Path(d) / "p", random.Random(1), run_fn=_fake(calls), max_age=-1)
        pk.do("index", "numpy")
        pk.do("index", "numpy")
        assert sum(1 for c in calls if c[1:3] == ["-m", "venv"]) == 2


def test_data_scientist_mostly_picks_data_science_packages():
    pk = PackageNoise(Path("/nonexistent"), random.Random(3), persona="Data scientist")
    pk.npm = None
    picks = [c[1] for c in (pk.choose() for _ in range(400)) if c[0] != "bundle"]
    ds = sum(p in DATA_SCIENCE for p in picks)
    assert ds > 0.6 * len(picks) and any(p in GENERAL for p in picks)
    assert all(p in DATA_SCIENCE + GENERAL + NPM for p in picks)


def test_downloaded_bytes_reads_pip_output():
    out = "Downloading a.whl (1.5 kB)\nDownloading b.whl (2.0 MB)\n"
    assert downloaded_bytes(out) == 1500 + 2_000_000


def test_bundle_is_a_requirements_file_install_that_is_thrown_away():
    with tempfile.TemporaryDirectory() as d:
        seen = {}

        def run(cmd, timeout):
            if cmd[1:3] == ["-m", "venv"]:
                vpy = Path(cmd[3]) / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
                vpy.parent.mkdir(parents=True, exist_ok=True)
                vpy.write_text("")
                return 0, ""
            if "-r" in cmd:
                seen["req"] = Path(cmd[cmd.index("-r") + 1]).read_text().split()
                seen["cmd"] = cmd
            return 0, "Downloading flask-3.0.whl (1.0 MB)\n"
        pk = PackageNoise(Path(d) / "p", random.Random(1), run_fn=run)
        r = pk.do("bundle", "web:7")
        assert r["ok"] and r["label"] == "pip install -r requirements.txt (7 packages, web)"
        assert len(seen["req"]) == 7 and len(set(seen["req"])) == 7
        assert "--only-binary=:all:" in seen["cmd"] and "--no-cache-dir" in seen["cmd"] and "--target" in seen["cmd"]
        assert not [x for x in (Path(d) / "p").iterdir() if x.name.startswith("dl-")]      # nothing kept


def test_choose_sometimes_picks_a_whole_project_and_sometimes_one_package():
    pk = PackageNoise(Path("/nonexistent"), random.Random(5), persona="Developer")
    pk.npm = None
    acts = [pk.choose()[0] for _ in range(400)]
    assert acts.count("bundle") > 20 and acts.count("install") > 100
