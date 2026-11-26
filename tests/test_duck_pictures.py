"""The duck.ai chat noise is a heavy user: often, several chats a session, and some messages carry a made-up picture."""
import random
import struct
import zlib
from pathlib import Path

from legalprivacy.chatpics import make_png


def _decode(png: bytes):
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    pos, chunks = 8, {}
    while pos < len(png):
        n = struct.unpack(">I", png[pos:pos + 4])[0]
        kind, data, crc = png[pos + 4:pos + 8], png[pos + 8:pos + 8 + n], struct.unpack(">I", png[pos + 8 + n:pos + 12 + n])[0]
        assert crc == zlib.crc32(kind + data) & 0xFFFFFFFF
        chunks[kind] = data
        pos += 12 + n
    return chunks


def test_the_picture_is_a_valid_png_of_varying_size():
    sizes = set()
    for seed in range(12):
        png = make_png(random.Random(seed))
        ch = _decode(png)
        w, h = struct.unpack(">II", ch[b"IHDR"][:8])
        assert len(zlib.decompress(ch[b"IDAT"])) == h * (1 + 3 * w) and b"IEND" in ch
        sizes.add(len(png))
    assert len(sizes) > 6 and min(sizes) < max(sizes) / 1.5          # the size is not a fixed fingerprint


class _Loc:
    def __init__(self, n, sink):
        self._n, self.sink = n, sink
        self.first = self

    def count(self):
        return self._n

    def set_input_files(self, f):
        self.sink.append(f)


class _Page:
    def __init__(self, n_inputs):
        self.sink = []
        self._n = n_inputs

    def locator(self, sel):
        assert "file" in sel
        return _Loc(self._n, self.sink)

    def wait_for_timeout(self, ms):
        pass


def _browser():
    from legalprivacy.browser import BrowserTransport
    b = BrowserTransport.__new__(BrowserTransport)
    b.rng = random.Random(1)
    b.scale = lambda: 0.0
    return b


def test_a_picture_is_attached_only_through_a_file_button_that_the_page_has():
    b = _browser()
    page = _Page(1)
    assert b._attach_picture(page) is True
    f = page.sink[0]
    assert f["mimeType"] == "image/png" and f["buffer"][:4] == b"\x89PNG" and f["name"].endswith(".png")
    assert b._attach_picture(_Page(0)) is False                    # no file button: nothing is invented


def test_the_chat_noise_is_on_by_default_and_a_heavy_user():
    from legalprivacy.config import Profile
    from legalprivacy.scheduler import Runner
    ex = Profile(name="d").extras
    assert ex.duck_chat is True and ex.duck_images is True
    assert Runner.DUCK_AI_CHANCE >= 0.5


def test_the_easter_egg_logos_have_no_white_box_in_dark_mode():
    html = (Path(__file__).parent.parent / "legalprivacy" / "web" / "index.html").read_text(encoding="utf-8")
    assert "if(grp==='egg')e.classList.add('egg')" in html
    assert html.count(".logos img:not(.egg)") >= 2 and ".logos img,.logos video{background:#fff}" not in html
