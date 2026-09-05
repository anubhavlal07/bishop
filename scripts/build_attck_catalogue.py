#!/usr/bin/env python3
"""Compress the ATT&CK STIX bundle into the catalogue Bishop ships.

The official Enterprise bundle is ~45 MB of STIX 2.1. Bishop needs four things
out of it — the technique ID, its name, its tactics, and whether it is
deprecated — so the catalogue committed to the repo is the projection of those
fields and nothing else.

Why commit a derived file at all, rather than fetching at start-up:

- `CLAUDE.md` says offline is the default, and technique validation is on the
  path of every run. A validator that needs the network is a validator that
  fails closed on a plane and fails open in a hurry.
- The full bundle is gitignored under `data/`. Vendoring 45 MB into a repo
  people are meant to read is antisocial.
- The catalogue carries the bundle's own version and modification date, so a
  report can say which ATT&CK release it was validated against rather than
  implying "current".

Usage:
    uv run python scripts/build_attck_catalogue.py [path-to-bundle.json]

With no argument it reads `data/attack-stix/enterprise-attack.json`, which
`scripts/fetch_attack.py` puts there.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = REPO_ROOT / "data" / "attack-stix" / "enterprise-attack.json"
OUTPUT = REPO_ROOT / "src" / "bishop" / "attck" / "catalogue.json"


def attack_id(obj: dict) -> str | None:
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def attack_url(obj: dict) -> str:
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("url", "")
    return ""


def build(bundle_path: Path) -> dict:
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    objects = bundle["objects"]

    # x-mitre-collection carries the release version. Without it the catalogue
    # cannot honestly name which ATT&CK it came from.
    version = ""
    modified = ""
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version", "")
            modified = obj.get("modified", "")
            break

    tactic_names: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            tactic_names[obj["x_mitre_shortname"]] = obj["name"]

    techniques: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        identifier = attack_id(obj)
        if not identifier:
            continue
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        techniques[identifier] = {
            "id": identifier,
            "name": obj["name"],
            "tactics": tactics,
            "tactic_names": [tactic_names.get(t, t) for t in tactics],
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "parent": identifier.split(".")[0] if "." in identifier else None,
            "deprecated": bool(obj.get("x_mitre_deprecated") or obj.get("revoked")),
            "platforms": obj.get("x_mitre_platforms", []),
            "url": attack_url(obj),
        }

    return {
        "source": "MITRE ATT&CK Enterprise (STIX 2.1)",
        "attack_version": version,
        "bundle_modified": modified,
        "licence": "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
        "technique_count": len(techniques),
        "tactics": tactic_names,
        "techniques": dict(sorted(techniques.items())),
    }


def main() -> int:
    bundle_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_BUNDLE
    if not bundle_path.exists():
        print(f"bundle not found: {bundle_path}", file=sys.stderr)
        print("run `just attack` first to fetch it", file=sys.stderr)
        return 1

    catalogue = build(bundle_path)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(catalogue, indent=1, sort_keys=False, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    size_kb = OUTPUT.stat().st_size / 1024
    print(
        f"wrote {catalogue['technique_count']} techniques from ATT&CK "
        f"v{catalogue['attack_version']} to {OUTPUT.relative_to(REPO_ROOT)} ({size_kb:.0f} KB)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
