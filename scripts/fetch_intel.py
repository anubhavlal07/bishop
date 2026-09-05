#!/usr/bin/env python3
"""Populate the indicator cache from abuse.ch.

Bishop never calls a threat-intelligence feed during triage — see
`src/bishop/detectors/intel.py` for the three reasons. This script does the
fetching ahead of time, into a cache the detector reads.

    uv run python scripts/fetch_intel.py        # or: just intel

**The fetched cache is gitignored.** abuse.ch's terms permit use but not
redistribution, so what ships in the repo is the small synthetic cache at
`fixtures/intel/ioc_cache.json`, which says so in its own metadata and in every
rationale the detector produces from it.

Needs `ABUSECH_AUTH_KEY` in `.env` — abuse.ch requires a free account for the
API. Without it this script explains that and exits; Bishop still runs.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET = REPO_ROOT / "data" / "intel" / "ioc_cache.json"

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
DAYS = 1


def fetch_threatfox(auth_key: str) -> list[dict[str, Any]]:
    request = urllib.request.Request(
        THREATFOX_URL,
        data=json.dumps({"query": "get_iocs", "days": DAYS}).encode(),
        headers={"Content-Type": "application/json", "Auth-Key": auth_key},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = json.loads(response.read())

    if payload.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox returned {payload.get('query_status')}")

    records: list[dict[str, Any]] = []
    for entry in payload.get("data", []):
        indicator = str(entry.get("ioc", "")).strip()
        if not indicator:
            continue
        kind = {
            "ip:port": "ip",
            "domain": "domain",
            "url": "url",
            "md5_hash": "md5",
            "sha256_hash": "sha256",
        }.get(str(entry.get("ioc_type")), "unknown")
        if kind == "ip":
            indicator = indicator.split(":")[0]
        if kind in {"unknown", "md5"}:
            continue

        records.append(
            {
                "indicator": indicator,
                "kind": kind,
                "verdict": "malicious",
                "source": "abuse.ch ThreatFox",
                "first_seen": str(entry.get("first_seen", ""))[:10],
                "last_seen": str(entry.get("last_seen") or entry.get("first_seen", ""))[:10],
                "malware_family": str(entry.get("malware_printable", "")),
                "confidence": round(float(entry.get("confidence_level", 50)) / 100, 2),
                "note": f"ThreatFox id {entry.get('id', '')}",
            }
        )
    return records


def main() -> int:
    auth_key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if not auth_key:
        print(
            "ABUSECH_AUTH_KEY is not set.\n"
            "\n"
            "abuse.ch requires a free account for the ThreatFox API. Sign up at\n"
            "https://auth.abuse.ch/ and put the key in .env as ABUSECH_AUTH_KEY.\n"
            "\n"
            "Bishop runs without it — the committed cache at\n"
            "fixtures/intel/ioc_cache.json is synthetic and labelled as such.",
            file=sys.stderr,
        )
        return 1

    try:
        records = fetch_threatfox(auth_key)
    except (urllib.error.URLError, RuntimeError, TimeoutError) as exc:
        print(f"fetch failed: {exc}", file=sys.stderr)
        return 1

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(
        json.dumps(
            {
                "snapshot_taken": datetime.now(UTC).isoformat(),
                "synthetic": False,
                "source": "abuse.ch ThreatFox",
                "licence": "https://threatfox.abuse.ch/faq/ — use permitted, redistribution not",
                "indicators": records,
            },
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {len(records)} indicators to {TARGET.relative_to(REPO_ROOT)}")
    print("This file is gitignored. Do not commit it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
