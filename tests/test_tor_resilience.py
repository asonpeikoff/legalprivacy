"""Tor must connect with a country on the avoid list (the US by default) and recover by itself, never by loosening the list."""
import io
import json
import time

import pytest

from legalprivacy import geoban, tormanager
from legalprivacy.events import EventLog
from legalprivacy.tormanager import TorManager, bridge_refusal, fetch_bridges_for_country

US_IP, DE_IP = "146.57.248.225", "212.83.43.95"
SNOW = ("snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
        "url=https://example.cdn/ fronts=a.example,b.example utls-imitate=hellorandomizedalpn")
WEBT = "webtunnel [2001:db8:e673:640c::1]:443 985302D69D7D0284CE24A22DCFD451EE239B082F url=https://example.com/x ver=0.0.7"
OBFS_US = f"obfs4 {US_IP}:22 10A6CD36A537FCE513A322361547444B393989F0 cert=abc iat-mode=0"
OBFS_DE = f"obfs4 {DE_IP}:443 {'C' * 40} cert=abc iat-mode=0"
MEEK = "meek_lite 192.0.2.20:80 url=https://meek.example/ front=www.example.com utls=HelloRandomizedNoALPN"


def _ip(s):
    a, b, c, d = map(int, s.split("."))
    return ((a * 256 + b) * 256 + c) * 256 + d


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("LEGALPRIVACY_HOME", str(tmp_path / "home"))
    tormanager._geoip_cache.clear()
    tor = tmp_path / "bundle" / "tor"
    (tor / "pluggable_transports").mkdir(parents=True)
    (tor / "tor").write_text("")
    (tmp_path / "bundle" / "data").mkdir()
    (tmp_path / "bundle" / "data" / "geoip").write_text(
        f"# test\n{_ip(US_IP)},{_ip(US_IP) + 255},US\n{_ip(DE_IP)},{_ip(DE_IP) + 255},DE\n")
    (tor / "pluggable_transports" / "pt_config.json").write_text(json.dumps({
        "pluggableTransports": {"lyrebird": "ClientTransportPlugin meek_lite,obfs4,webtunnel exec ${pt_path}lyrebird",
                                "snowflake": "ClientTransportPlugin snowflake exec ${pt_path}lyrebird"},
        "bridges": {"obfs4": [OBFS_US, OBFS_DE], "snowflake": [SNOW], "meek": [MEEK]}}))
    return tmp_path


def _tm(bundle, **kw):
    tm = TorManager(EventLog(), auto_install=False, **{"exclude_nodes": ["{us}"], **kw})
    tm.geoban = False
    tm.binary = str(bundle / "bundle" / "tor" / "tor")
    tm.socks_port, tm.control_port, tm.cookie_path = 19050, 19051, str(bundle / "cookie")
    return tm


def _geo(bundle):
    return bundle / "bundle" / "data" / "geoip"


def test_snowflake_meek_and_webtunnel_placeholders_are_never_refused_by_a_country_exclusion(bundle):
    for line in (SNOW, MEEK, WEBT):
        assert bridge_refusal(line, {"us"}, [], set(), _geo(bundle)) is None


def test_bridges_in_an_avoided_country_range_or_identity_are_left_out(bundle):
    import ipaddress
    assert "{us}" in bridge_refusal(OBFS_US, {"us"}, [], set(), _geo(bundle))
    assert bridge_refusal(OBFS_DE, {"us"}, [], set(), _geo(bundle)) is None
    assert "in 212.0.0.0/8" in bridge_refusal(OBFS_DE, set(), [ipaddress.ip_network("212.0.0.0/8")], set(), _geo(bundle))
    assert "avoid list" in bridge_refusal(OBFS_DE, set(), [], {"C" * 40}, _geo(bundle))


def test_torrc_keeps_the_us_strictly_excluded_and_lets_placeholder_bridges_through(bundle):
    tm = _tm(bundle, bridge_mode="snowflake")
    text = tm._write_torrc(bundle / "data").read_text()
    excl = text.split("ExcludeNodes ", 1)[1].splitlines()[0].split(",")
    assert "{us}" in excl and "StrictNodes 1" in text
    assert "GeoIPExcludeUnknown 0" in text                       # Tor's 'auto' would refuse the Snowflake bridge
    assert "Bridge " + SNOW in text


def test_without_a_country_tors_own_unknown_handling_is_left_alone(bundle):
    text = _tm(bundle, exclude_nodes=["A" * 40]).\
        _write_torrc(bundle / "data").read_text()
    assert "GeoIPExcludeUnknown" not in text


def test_relays_with_no_known_country_are_excluded_one_by_one(bundle, monkeypatch):
    class G:
        unknown_country = ["D" * 40]
        def tor_excludes(self): return []
    monkeypatch.setattr(geoban, "shared", lambda: G())
    tm = _tm(bundle)
    tm.geoban = True
    assert "$" + "D" * 40 in tm._write_torrc(bundle / "data").read_text().split("ExcludeNodes ", 1)[1].splitlines()[0]


def test_only_usable_obfs4_bridges_go_into_the_torrc(bundle):
    tm = _tm(bundle, bridge_mode="obfs4")
    text = tm._write_torrc(bundle / "data").read_text()
    assert "Bridge " + OBFS_DE in text and US_IP not in text


def test_ladder_skips_a_way_whose_bridges_are_all_ruled_out(bundle):
    tm = _tm(bundle, bridge_mode="off", bridges=[OBFS_US])
    assert tm.ladder() == ["off", "obfs4", "snowflake", "meek"]          # 'custom' (only a US bridge) is skipped
    assert _tm(bundle, bridge_mode="obfs4", bridge_auto=False).ladder() == ["obfs4"]


def test_recovery_walks_the_ladder_then_resets_everything_and_never_touches_the_avoid_list(bundle, monkeypatch):
    tm = _tm(bundle, bridge_mode="obfs4")
    starts, wipes = [], []
    monkeypatch.setattr(tm, "stop", lambda: None)
    monkeypatch.setattr(tm, "_wipe_state", lambda: wipes.append(1))

    def fake_start():
        tm.started_at = time.time() + len(starts)
        starts.append(tm.bridge_mode)
    monkeypatch.setattr(tm, "start", fake_start)
    tm.MAX_BACKOFF = tm.RETRY_DELAY = 0
    tm.started_at = 1.0
    for _ in range(5):
        before = len(starts)
        tm._recover("stuck")
        deadline = time.time() + 5
        while len(starts) == before and time.time() < deadline:
            time.sleep(0.02)
    assert starts == ["off", "snowflake", "meek", "obfs4", "off"]       # after the last way: a full reset, then again
    assert wipes == [1] and tm.exclude_nodes == ["{us}"]


def test_a_stop_you_asked_for_ends_recovery(bundle):
    tm = _tm(bundle)
    tm._stop_evt.set()
    tm._recover("stuck")
    assert tm._recovering is None


def test_the_bridge_in_use_is_named_from_tors_guard_list(bundle):
    tm = _tm(bundle, bridge_mode="obfs4")
    tm.state = "ready"
    tm.bridge_in_use = tm._bridge_now(f"${'C' * 40}~bridge up\n$10A6CD36A537FCE513A322361547444B393989F0~x down")
    assert tm.bridge_in_use["transport"] == "obfs4" and tm.bridge_in_use["country"] == "de"
    assert tm.bridge_label().startswith(f"obfs4 {DE_IP}:443, DE, CCCCCCCC")
    tm.bridge_mode = "snowflake"
    tm.bridge_in_use = tm._bridge_now("$2B280B23E1107BB62ABFC40DDCC816EB173884A7~x up\n"
                                      "$2B280B23E1107BB62ABFC40DDCC8824814F80A72~flakey up")
    assert tm.bridge_label().startswith("snowflake via the snowflake network, 2B280B23") and "automatically" in tm.bridge_label()
    assert _tm(bundle, bridge_mode="off").bridge_label() == "none (direct)"


class _Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def test_bridge_service_names_the_country_and_falls_back_to_its_defaults():
    calls = []

    def opener(req, timeout=0):
        calls.append(req.full_url)
        if req.full_url.endswith("/settings"):
            return _Resp(json.dumps({"settings": [], "country": "us"}).encode())
        return _Resp(json.dumps({"settings": [{"bridges": {"type": "obfs4", "source": "builtin",
                                                           "bridge_strings": [OBFS_DE]}}]}).encode())
    got = fetch_bridges_for_country("", opener=opener)
    assert got["country"] == "us" and got["source"] == "defaults" and got["sets"][0]["lines"] == [OBFS_DE]
    assert calls[1].endswith("/defaults")


def test_bridge_service_errors_are_reported_not_mistaken_for_no_bridges():
    def opener(req, timeout=0):
        return _Resp(json.dumps({"errors": [{"code": 406, "detail": "Country not found"}]}).encode())
    with pytest.raises(RuntimeError, match="Country not found"):
        fetch_bridges_for_country("zz", opener=opener)


def test_relay_list_records_relays_with_no_country(tmp_path):
    g = geoban.GeoBan(path=tmp_path / "g.json")
    data = {"relays": [{"fingerprint": "A" * 40, "or_addresses": ["20.0.0.5:9001"], "country": "de"},
                       {"fingerprint": "E" * 40, "or_addresses": ["20.0.0.6:9001"]}]}
    g.update_relays(opener=lambda *a, **k: _Resp(json.dumps(data).encode()))
    assert g.unknown_country == ["E" * 40]
    assert geoban.GeoBan(path=tmp_path / "g.json").unknown_country == ["E" * 40]
