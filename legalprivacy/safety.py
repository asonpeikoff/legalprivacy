"""Content safety for generated noise: never search for, or visit, anything that
could embarrass or endanger the user if their traffic were ever read."""
from __future__ import annotations

import re

# Words that disqualify a query outright (adult, gambling, violence/self-harm, weapons,
# illegal drugs, hacking/crime, extremism). Matched on word boundaries.
_BAD_WORDS = [r"porn\w*", r"xxx", r"nude\w*", r"naked", r"sex", r"sexy", r"sexual\w*", r"erotic\w*", r"escort\w*", r"fetish\w*", r"hentai", r"nsfw", r"onlyfans", r"camgirl\w*", r"milf\w*", r"nsfw", r"casino\w*", r"gambl\w*", r"betting", r"bookmaker\w*", r"poker", r"slots", r"suicid\w*", r"self-harm", r"kill\w*", r"murder\w*", r"assassin\w*", r"bomb\w*", r"explosive\w*", r"weapon\w*", r"firearm\w*", r"gun\w*", r"rifle\w*", r"terror\w*", r"jihad\w*", r"extremis\w*", r"nazi\w*", r"genocide", r"rape\w*", r"molest\w*", r"abuse\w*", r"trafficking", r"cocaine", r"heroin", r"meth\w*", r"fentanyl", r"lsd", r"mdma", r"ecstasy", r"opioid\w*", r"narcotic\w*", r"overdos\w*", r"hack\w*", r"crack\w*", r"exploit\w*", r"malware", r"ransomware", r"phishing", r"ddos", r"carding", r"counterfeit\w*", r"forgery", r"fake\s+id", r"launder\w*", r"darknet", r"dark\s+web"]
_BAD_RE = re.compile(r"\b(?:" + "|".join(_BAD_WORDS) + r")\b", re.I)

_BAD_DOMAIN_PARTS = ("porn", "xxx", "sex", "adult", "nude", "cam4", "xvideos", "xnxx", "xhamster",
                     "casino", "bet365", "gambl", "poker", "slots", "escort", "hentai", "onlyfans",
                     "torrent", "pirate", "warez", "crack")
_INFRA_PARTS = ("akamai", "cloudfront", "amazonaws", "googleapis", "gstatic", "doubleclick",
                "googlesyndication", "googleadservices", "googletagmanager", "google-analytics",
                "fbcdn", "facebook.net", "cdn", "edgekey", "edgesuite", "azure", "windows.net",
                "trafficmanager", "ytimg", "googleusercontent", "googlevideo", "tiktokcdn",
                "byteoversea", "root-servers", "gtld-servers", "ezviz", "hicloudcam", "icloud-content",
                "apple-dns", "aaplimg", "skype.com", "msedge.net", "office.net", "live.com",
                "microsoftonline", "mozilla.net", "sentry", "cloudflare", "fastly", "akadns", "nflxvideo")
_BAD_TLDS = (".gov", ".mil", ".xxx", ".adult", ".porn", ".sex", ".bet", ".casino", ".poker")
# Name patterns for betting, lottery and adult sites that a word list misses (e.g. betano, crocobet,
# 1xbet, dpboss, faphouse). Checked per label, with a few common words that merely contain "bet".
_BAD_LABEL_RE = re.compile(
    r"(^\d*x?bet(?!ter|h|a$|a\d|ween)|bet\d*$|bet\d+|^bet[a-z]{2,}$|satta|matka|dpboss|lott(o|ery)|jackpot|"
    r"slots?\d*$|^slots?(\d|online|gacor|game|club)|slotter|togel|toto\d|bets?$|bet-|apuesta|casino|poker|bingo|wager|sportsbook|^stake|1win|1xbet|mostbet|melbet|parimatch|"
    r"fap|nsfw|hentai|xvideo|xnxx|xhamster|spankbang|eporner|rule34|chaturbate|stripchat|bongacam|livejasmin|"
    r"camsoda|onlyfans|^jav|jav$|livecam|camrips|pussy|desi18|18plus|^18av|fansly|brazzers|redtube|youporn|tube8|javhd|jav[a-z]*\d|escort|hookup|nude|milf)")
_LABEL_OK = {"alphabet", "tibet", "betterhelp", "better", "betterment", "beta", "bethesda", "bethel",
             "betty", "elizabeth", "between", "cabinet", "sorbet", "barbet", "abet", "quibet"}


def safe_query(q: str) -> bool:
    q = q.strip()
    if not (3 <= len(q) <= 90) or "http" in q.lower() or "www." in q.lower():
        return False
    if not re.fullmatch(r"[A-Za-z0-9 '\-.,?&:/+()$%#!]+", q):
        return False
    return not _BAD_RE.search(q)


def safe_domain(domain: str, denylist: set[str] | None = None) -> bool:
    d = domain.lower().strip(".")
    if not d or d.endswith(_BAD_TLDS) or any(p in d for p in _BAD_DOMAIN_PARTS):
        return False
    if any(p in d for p in _INFRA_PARTS):
        return False
    if any(_BAD_LABEL_RE.search(lbl) for lbl in d.split(".") if lbl not in _LABEL_OK):
        return False
    if denylist:
        parts = d.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in denylist:
                return False
    return True


# (The app no longer skips non-English sites: every language is treated the same.)
