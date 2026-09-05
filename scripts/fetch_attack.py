#!/usr/bin/env python3
"""Fetch the MITRE ATT&CK Enterprise STIX bundle into `data/`.

Bishop ships a compact catalogue derived from this bundle
(`src/bishop/attck/catalogue.json`), so you do not need to run this to use
Bishop. Run it when you want to rebuild the catalogue against a newer ATT&CK
release:

    uv run python scripts/fetch_attack.py
    uv run python scripts/build_attck_catalogue.py

or just `just attack`, which does both.

`data/` is gitignored. The bundle is around 45 MB and MITRE's terms are
permissive but there is no reason to vendor it.
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET = REPO_ROOT / "data" / "attack-stix" / "enterprise-attack.json"

#: Pinned rather than "latest" on purpose: a validator whose vocabulary changes
#: silently under you is a validator that makes yesterday's reports unverifiable.
#: Bump this deliberately, rebuild the catalogue, and re-run `just eval`.
ATTACK_VERSION = "17.1"
URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)


def main() -> int:
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    print(f"fetching ATT&CK v{ATTACK_VERSION}")
    print(f"  from {URL}")
    print(f"  to   {TARGET.relative_to(REPO_ROOT)}")
    try:
        with urllib.request.urlopen(URL, timeout=300) as response:
            TARGET.write_bytes(response.read())
    except OSError as exc:
        print(f"failed: {exc}", file=sys.stderr)
        print(
            "Bishop still works without this — it ships a derived catalogue at "
            "src/bishop/attck/catalogue.json.",
            file=sys.stderr,
        )
        return 1
    size_mb = TARGET.stat().st_size / 1_000_000
    print(f"done ({size_mb:.1f} MB)")
    print("now run: uv run python scripts/build_attck_catalogue.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
