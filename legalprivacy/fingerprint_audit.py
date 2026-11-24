"""Consistency auditor: does an identity add up the way a real browser's does?

Bot detection looks less for a "bad" value than for values that contradict each other: a Windows user agent with a Linux
platform hint, a phone that reports a 1920-pixel window, Firefox sending client hints, a Chrome 150 string with Chrome 148
brands. Each check here names one such contradiction; an identity (or a browser window) passes when none is found."""
from __future__ import annotations

import re

from .identity import Identity, navigation_headers

_UA_PLATFORM = {"Windows": "Windows NT", "Linux": "X11; Linux", "macOS": "Macintosh", "Android": "Android", "iOS": "iPhone"}


def audit_identity(identity: Identity) -> list[str]:
    ua, out = identity.user_agent, []
    want = _UA_PLATFORM.get(identity.platform)
    if want and want not in ua:
        out.append(f"platform {identity.platform} but the user agent has no '{want}'")
    is_chrome = bool(re.search(r"Chrome/\d+", ua)) and "Firefox/" not in ua
    if identity.chromium != is_chrome:
        out.append("the Chromium flag and the user agent disagree")
    if identity.mobile != bool(re.search(r"Mobile|iPhone|Android", ua)):
        out.append("the mobile flag and the user agent disagree")
    if identity.mobile and not identity.device:
        out.append("a phone identity without a device model")
    langs = re.findall(r";q=([0-9.]+)", identity.accept_language)
    if "q=" in identity.accept_language.split(",")[0] or langs != sorted(langs, reverse=True):
        out.append("Accept-Language is not in descending preference order")
    h = {k.lower(): v for k, v in navigation_headers(identity, "https://example.com/").items()}
    if not identity.chromium:
        if any(k.startswith("sec-ch-") for k in h):
            out.append("client hints sent by a non-Chromium browser")
    else:
        major = re.search(r"Chrome/(\d+)", ua)
        if major and f'v="{major.group(1)}"' not in h.get("sec-ch-ua", ""):
            out.append("the client hint brands do not match the Chrome version")
        if h.get("sec-ch-ua-platform") != f'"{identity.platform}"':
            out.append("the client hint platform does not match")
        if h.get("sec-ch-ua-mobile") != ("?1" if identity.mobile else "?0"):
            out.append("the client hint mobile flag does not match")
    return out


def audit_window(identity: Identity, width: int, height: int) -> list[str]:
    """A phone is narrow and tall; a desktop window is wide and never the odd shape of a phone."""
    if identity.mobile and not (width <= 520 and height > width):
        return [f"a phone window of {width}x{height}"]
    if not identity.mobile and (width < 800 or height < 500):
        return [f"a desktop window of {width}x{height}"]
    return []
