import random
import struct
from legalprivacy import dnsplan as D


def packet(ips, rcode=0):
    hdr = struct.pack(">HHHHHH", 1, 0x8180 | rcode, 1, len(ips), 0, 0)
    q = b"\x03www\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    ans = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes(map(int, ip.split("."))) for ip in ips)
    return hdr + q + ans


def test_answers_parser_reads_every_address():
    assert D.answers_a(packet(["1.2.3.4", "5.6.7.8"])) == ["1.2.3.4", "5.6.7.8"]
    assert D.answers_a(packet([], rcode=3)) == []
    assert D.answers_a(b"junk") == []


def S(*p):
    return set(p)


def test_one_liar_among_four_is_flagged_after_two_names():
    honest = {"a.com": S("1.1"), "b.com": S("2.2"), "c.com": S("3.3")}
    liar = {"a.com": S("6.6"), "b.com": S("6.6"), "c.com": S("6.6")}
    out = D.consensus({"r1": honest, "r2": honest, "r3": honest, "bad": liar})
    assert out["bad"] == "outlier" and out["r1"] == "ok"


def test_even_split_is_disputed_not_guessed():
    a = {"a.com": S("1.1"), "b.com": S("2.2"), "c.com": S("3.3")}
    b = {"a.com": S("9.1"), "b.com": S("9.2"), "c.com": S("9.3")}
    out = D.consensus({"r1": a, "r2": a, "r3": b, "r4": b})
    assert set(out.values()) == {"disputed"}          # half and half: can't tell who is right


def test_normal_cdn_variety_is_not_flagged():
    a = {"a.com": S("1.1", "1.2"), "b.com": S("2.2"), "c.com": S("3.3")}
    b = {"a.com": S("1.2"), "b.com": S("2.2", "2.9"), "c.com": S("3.3")}      # overlapping networks
    assert set(D.consensus({"r1": a, "r2": b, "r3": a}).values()) == {"ok"}


class Cfg:
    mode = "secure"; slow_ms = 250; resolvers = []; opennic = False; quad9 = False; custom = []
    system_share = 0.5; block_minutes = [10, 60]


def plan():
    c = Cfg()
    c.resolvers = [{"ip": f"10.0.0.{i}", "name": f"s{i}", "role": "primary", "enabled": True} for i in range(1, 5)]
    p = D.DnsPlan(random.Random(1), c)
    for r in c.resolvers:
        p.health[r["ip"]] = {"ok": True, "rtt_ms": 20, "egress": r["ip"]}
    return p


def test_hijacker_and_repeat_liar_leave_the_rotation():
    p = plan()
    p.health["10.0.0.1"]["canary"] = "hijack"
    p.strikes["10.0.0.2"] = 2
    assert p.verdict("10.0.0.1") == "hijack" and p.verdict("10.0.0.2") == "disagrees"
    seen = {p.secure_choice()["ip"] for _ in range(60)}
    assert seen <= {"10.0.0.3", "10.0.0.4"}


def test_no_server_answers_more_than_about_half():
    p = plan()
    for _ in range(400):
        p.secure_choice()
    top = max(p._recent.count(ip) for ip in set(p._recent)) / len(p._recent)
    assert top <= 0.6
