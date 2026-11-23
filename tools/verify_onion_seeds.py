"""Maintainer tool: check that each built-in onion address really belongs to the site it is named for.

A site's own HTTPS page can announce its onion address in an `Onion-Location` header. That header is
delivered over a certificate-checked connection to the site's real domain, so a match proves the onion
address is the site's own and not a look-alike. The addresses published by the Tor Project at
onion.torproject.org are accepted as authoritative for the Tor Project's own sites.

Many sites do not send the header; those were checked against a page of the owner's own that names the address
(see the comment above the list in legalprivacy/onion.py), and anything that could not be checked was removed.

Usage:  python tools/verify_onion_seeds.py            (needs the `requests` package and the internet)
Prints OK / MISMATCH / NO HEADER for each site; exits 1 if any MISMATCH.
"""
from __future__ import annotations

import sys
import urllib.parse
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from legalprivacy.onion import BUILTIN_ONION_SEEDS  # noqa: E402

# Built-in name -> the real site's normal address (where it announces its onion address).
CLEARNET = {
    "DuckDuckGo": "https://duckduckgo.com/", "Tor Project": "https://www.torproject.org/",
    "The New York Times": "https://www.nytimes.com/", "BBC": "https://www.bbc.com/",
    "ProPublica": "https://www.propublica.org/", "Debian": "https://www.debian.org/", "Proton": "https://proton.me/", "Qubes OS": "https://www.qubes-os.org/",
    "Riseup": "https://riseup.net/", "Tech Learning Collective": "https://techlearningcollective.com/",
    "Blockchair": "https://blockchair.com/", "Mullvad VPN": "https://mullvad.net/", "Njalla": "https://njal.la/",
    "keys.openpgp.org": "https://keys.openpgp.org/", "Whonix": "https://www.whonix.org/", "OnionShare": "https://onionshare.org/",
    "Cryptostorm VPN": "https://cryptostorm.is/", "XMPP.is": "https://xmpp.is/", "Tails": "https://tails.net/",
}


def host(u: str) -> str:
    return (urllib.parse.urlparse(u).hostname or "").lower().removeprefix("www.")


def main() -> int:
    bad = 0
    for name, onion in BUILTIN_ONION_SEEDS:
        site = CLEARNET.get(name)
        if site is None:
            print(f"-- {name}: not checked (the Tor Project's own pages are listed at onion.torproject.org)")
            continue
        try:
            r = requests.head(site, timeout=20, allow_redirects=True, headers={"User-Agent": "legalPrivacy-verify"})
            hdr = r.headers.get("Onion-Location", "")
        except requests.RequestException as exc:
            print(f"?? {name}: could not reach {site} ({exc.__class__.__name__})")
            continue
        if not hdr:
            print(f"NO HEADER  {name}: {site} does not announce an onion address")
        elif host(hdr) == host(onion):
            print(f"OK         {name}")
        else:
            bad += 1
            print(f"MISMATCH   {name}: the site announces {host(hdr)} but the list has {host(onion)}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
