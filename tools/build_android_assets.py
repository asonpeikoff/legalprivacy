"""Builds the small word lists the Android app ships (from the same bundled snapshot the desktop app uses).

    python3 tools/build_android_assets.py

Writes android/app/src/main/assets/domains.txt (popular sites) and queries.txt (real search-style queries).
Same sources and caveats as data/feeds/README.md (e.g. MS MARCO is published for non-commercial research use).
"""
import gzip
import json
import random
from pathlib import Path

root = Path(__file__).resolve().parent.parent
snap = json.load(gzip.open(root / "data/feeds/snapshot.json.gz"))
out = root / "android/app/src/main/assets"
out.mkdir(parents=True, exist_ok=True)
rng = random.Random(7)
def items(k):
    v = snap[k]
    return v["items"] if isinstance(v, dict) else v


domains = [d for d in items("tranco") if "." in d][:2500]
(out / "domains.txt").write_text("\n".join(domains) + "\n", encoding="utf-8")
q = [s for s in items("dataset") if 8 <= len(s) <= 70]
rng.shuffle(q)
queries = q[:2500] + [s for s in items("trends") + items("wiki") if 3 <= len(s) <= 70]
(out / "queries.txt").write_text("\n".join(queries) + "\n", encoding="utf-8")
print(len(domains), "domains,", len(queries), "queries")
