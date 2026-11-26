"""A picture to attach in a chat: made here, from nothing of yours.

When the chat noise has a message to send on a chat site, now and then it attaches a picture the way a person would (through
the page's own file button) and asks about it. The picture is a plain PNG built in memory from a random smooth gradient with
shapes and some grain: no camera, no file of yours, nothing read from disk. Its size varies a lot (tens of kilobytes to a few
hundred), because the size of what is sent is part of what an observer sees.
"""
from __future__ import annotations

import random
import struct
import zlib


def _chunk(kind: bytes, data: bytes) -> bytes:
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def make_png(rng: random.Random, width: int | None = None, height: int | None = None) -> bytes:
    """A valid 8-bit RGB PNG: a two-colour gradient, a few filled shapes, light noise. Random size unless given."""
    w = width or rng.choice([320, 400, 480, 560, 640, 720, 800])
    h = height or max(120, int(w * rng.choice([0.5625, 0.66, 0.75, 1.0, 1.33])))
    c1 = [rng.randrange(40, 230) for _ in range(3)]
    c2 = [rng.randrange(40, 230) for _ in range(3)]
    grain = rng.choice([4, 10, 24])                       # more grain: a bigger file
    shapes = [(rng.randrange(w), rng.randrange(h), rng.randrange(20, max(21, w // 4)),
               [rng.randrange(0, 256) for _ in range(3)]) for _ in range(rng.randrange(2, 7))]
    rows = []
    for y in range(h):
        t_y = y / max(1, h - 1)
        row = bytearray([0])                               # filter type 0 (none)
        for x in range(w):
            t = (t_y + x / max(1, w - 1)) / 2
            px = [int(c1[k] + (c2[k] - c1[k]) * t) for k in range(3)]
            for cx, cy, r, col in shapes:
                if (x - cx) ** 2 + (y - cy) ** 2 < r * r:
                    px = col
                    break
            n = rng.randrange(-grain, grain + 1)
            row += bytes(min(255, max(0, v + n)) for v in px)
        rows.append(bytes(row))
    raw = b"".join(rows)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(raw, 6)) + _chunk(b"IEND", b"")


PICTURE_QUESTIONS = [
    "what do you think of this picture?", "can you describe this image", "is this a good colour scheme?",
    "what mood does this give you", "could this work as a wallpaper?", "what would you change about this image",
    "does this look balanced to you?", "describe what you see here",
]
