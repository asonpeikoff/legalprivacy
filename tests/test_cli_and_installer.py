"""Command line and Tor installer safety (offline: nothing is downloaded, no Tor is started)."""
import contextlib
import hashlib
import io
import os
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("LEGALPRIVACY_HOME", tempfile.mkdtemp(prefix="legalprivacy-test-"))

import pytest  # noqa: E402

from legalprivacy import cli, tormanager  # noqa: E402
from legalprivacy.events import EventLog  # noqa: E402


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exc:               # argparse exits on --help / bad usage
            code = exc.code
    return code, out.getvalue(), err.getvalue()


def _profile(tmp):
    p = Path(tmp) / "p.yaml"
    p.write_text("name: t\n", encoding="utf-8")
    return str(p)


# ── command line ────────────────────────────────────────────────────────────
def test_help_lists_the_real_commands_only():
    code, out, _ = _run(["--help"])
    assert code == 0
    for name in ("run", "ui", "tor", "doctor", "relay"):
        assert name in out
    assert "country" not in out.lower()                              # the exit-country option is gone
    code, out, _ = _run(["tor", "--help"])
    assert "status" in out and "install" in out and "stop" not in out.split("{")[1].split("}")[0]


def test_relay_gen_writes_a_non_exit_torrc_and_refuses_line_injection():
    d = tempfile.mkdtemp()
    out_file = os.path.join(d, "torrc")
    code, out, _ = _run(["relay", "gen", "--nickname", "mine", "--out", out_file, "--bridge"])
    text = Path(out_file).read_text(encoding="utf-8")
    assert code == 0 and "ExitPolicy reject *:*" in text and "BridgeRelay 1" in text and "mine" in out
    code, _, err = _run(["relay", "gen", "--contact", "me@example.com\nExitPolicy accept *:*",
                         "--out", os.path.join(d, "evil")])
    assert code == 2 and "single line" in err and not os.path.exists(os.path.join(d, "evil"))
    code, _, err = _run(["relay", "gen", "--bandwidth", "5Mbit\nSocksPort 0.0.0.0:9050", "--out", os.path.join(d, "e2")])
    assert code == 2 and not os.path.exists(os.path.join(d, "e2"))


def test_run_dry_run_and_doctor_on_the_default_profile():
    prof = _profile(tempfile.mkdtemp())
    code, out, _ = _run(["run", "--dry-run", "--profile", prof])
    assert code == 0 and "lane" in out
    code, out, _ = _run(["doctor", "--profile", prof])
    assert "Doctor diagnostics" in out


def test_a_missing_profile_is_a_clean_error_not_a_traceback():
    code, _, err = _run(["doctor", "--profile", os.path.join(tempfile.mkdtemp(), "nope.yaml")])
    assert code != 0 and "Traceback" not in err


# ── Tor installer ───────────────────────────────────────────────────────────
def _tar(members):
    path = os.path.join(tempfile.mkdtemp(), "b.tar.gz")
    with tarfile.open(path, "w:gz") as tf:
        for name, data, kind in members:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            elif kind == "link":
                ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
                tf.addfile(ti)
    return Path(path)


def test_archive_extraction_rejects_path_traversal_and_skips_links():
    target = Path(tempfile.mkdtemp()) / "bundle"
    target.mkdir()
    with pytest.raises(RuntimeError):
        tormanager._safe_extract(_tar([("../escape.txt", b"x", "file")]), target)
    with pytest.raises(RuntimeError):
        tormanager._safe_extract(_tar([("/tmp/abs.txt", b"x", "file")]), target)
    tormanager._safe_extract(_tar([("tor/tor", b"bin", "file"), ("tor/link", b"", "link")]), target)
    assert (target / "tor" / "tor").read_bytes() == b"bin" and not (target / "tor" / "link").exists()


def test_install_discards_a_download_whose_checksum_does_not_match():
    tm = tormanager.TorManager(EventLog())
    key = tormanager.platform_key()
    if not key:
        pytest.skip("no official bundle for this platform")
    osn, arch = key
    fname = f"tor-expert-bundle-{osn}-{arch}-14.0.1.tar.gz"
    payload = b"definitely not the real bundle"

    tm._verify_sums_signature = lambda sums, sig: None          # the signature check has its own tests (test_tor_version.py)

    def fake_get(url, timeout=30.0):
        if url.endswith(".asc"):
            return b"signature"
        if url.endswith("sha256sums-signed-build.txt"):
            return f"{'0' * 64}  {fname}\n".encode()
        if url.endswith("/14.0.1/"):
            return f'<a href="{fname}">x</a>'.encode()
        return b'<a href="14.0.1/">14.0.1/</a>'

    class Resp(io.BytesIO):
        headers = {"Content-Length": str(len(payload))}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.close()

    old_get, old_open = tormanager._http_get, urllib.request.urlopen
    tormanager._http_get = fake_get
    urllib.request.urlopen = lambda req, timeout=60: Resp(payload)
    try:
        with pytest.raises(RuntimeError, match="Checksum mismatch"):
            tm._install()
    finally:
        tormanager._http_get, urllib.request.urlopen = old_get, old_open
    assert not (tormanager.tor_dir() / fname).exists()                      # the bad download is deleted
    assert hashlib.sha256(payload).hexdigest() != "0" * 64


def test_country_bridges_are_parsed_from_the_bridge_service_reply():
    body = (b'{"settings": [{"bridges": {"type": "obfs4", "bridge_strings": ["obfs4 1.2.3.4:443 AA cert=x iat-mode=0"]}},'
            b' {"bridges": {"type": "snowflake", "bridge_strings": []}}]}')

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.close()

    old = urllib.request.urlopen
    urllib.request.urlopen = lambda req, timeout=30: Resp(body)
    try:
        sets = tormanager.fetch_bridges_for_country("IR")
    finally:
        urllib.request.urlopen = old
    assert sets == [{"type": "obfs4", "lines": ["obfs4 1.2.3.4:443 AA cert=x iat-mode=0"]}]


def test_small_installer_helpers():
    assert tormanager._version_key("14.0.10") > tormanager._version_key("14.0.9")
    assert tormanager._torrc_quote(Path("C:\\Users\\a b\\data")) == '"C:/Users/a b/data"'
