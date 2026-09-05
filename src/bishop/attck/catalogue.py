"""Technique validation against the ATT&CK bundle.

`CLAUDE.md` §3: a technique ID reaches a report only after it is confirmed
present in the ATT&CK STIX bundle. A model-proposed ID that fails validation is
rejected and re-prompted — never passed through with a caveat.

That rule exists because a hallucinated technique ID is the most expensive kind
of wrong output this system can produce. It is plausible, it is specific, it
survives being copied into a ticket, and the first person to notice is whoever
tries to look it up during an incident. Everything else Bishop says is hedged
with a confidence score; a technique ID looks like a fact.

The catalogue is `catalogue.json`, generated from the official bundle by
`scripts/build_attck_catalogue.py`. It carries the ATT&CK version it came from,
so a report can name the release it was validated against instead of implying
"whatever is current".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

CATALOGUE_PATH = Path(__file__).resolve().parent / "catalogue.json"

TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_EXTRACT = re.compile(r"\bT(\d{4})(?:\.(\d{1,3}))?\b", re.IGNORECASE)


class TechniqueRejected(ValueError):
    """A proposed technique ID did not survive validation."""


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    tactic_names: tuple[str, ...]
    is_subtechnique: bool
    parent: str | None
    deprecated: bool
    platforms: tuple[str, ...]
    url: str

    @property
    def label(self) -> str:
        return f"{self.id} {self.name}"


@dataclass(frozen=True, slots=True)
class Rejection:
    """Why one proposal was refused. Carried into the audit log."""

    proposed: str
    reason: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Validation:
    accepted: tuple[Technique, ...]
    rejected: tuple[Rejection, ...]
    normalised: tuple[tuple[str, str], ...] = ()

    @property
    def ids(self) -> list[str]:
        return [t.id for t in self.accepted]

    @property
    def ok(self) -> bool:
        return not self.rejected

    def summary(self) -> str:
        if self.ok:
            return f"{len(self.accepted)} technique IDs validated"
        refused = ", ".join(f"{r.proposed} ({r.reason})" for r in self.rejected)
        return f"{len(self.accepted)} validated, {len(self.rejected)} rejected: {refused}"


class TechniqueCatalogue:
    """An immutable snapshot of ATT&CK, loaded once per process."""

    def __init__(self, payload: dict) -> None:
        self._raw = payload
        self.attack_version: str = payload.get("attack_version", "unknown")
        self.bundle_modified: str = payload.get("bundle_modified", "")
        self.source: str = payload.get("source", "MITRE ATT&CK")
        self.tactics: dict[str, str] = dict(payload.get("tactics", {}))
        self._techniques: dict[str, Technique] = {
            identifier: Technique(
                id=entry["id"],
                name=entry["name"],
                tactics=tuple(entry.get("tactics", [])),
                tactic_names=tuple(entry.get("tactic_names", [])),
                is_subtechnique=bool(entry.get("is_subtechnique")),
                parent=entry.get("parent"),
                deprecated=bool(entry.get("deprecated")),
                platforms=tuple(entry.get("platforms", [])),
                url=entry.get("url", ""),
            )
            for identifier, entry in payload.get("techniques", {}).items()
        }

    def __len__(self) -> int:
        return len(self._techniques)

    def __contains__(self, technique_id: str) -> bool:
        return technique_id in self._techniques

    def get(self, technique_id: str) -> Technique | None:
        return self._techniques.get(technique_id)

    def all(self) -> list[Technique]:
        return list(self._techniques.values())

    def tactic_name(self, shortname: str) -> str:
        return self.tactics.get(shortname, shortname)

    def normalise(self, proposal: str) -> tuple[str | None, str | None]:
        """Coerce a proposal into canonical form.

        Returns `(canonical_id, note)`. Only unambiguous reformatting is done —
        case, surrounding prose, and zero-padding a sub-technique number, which
        is always three digits in ATT&CK. Nothing here guesses at a technique.
        """
        if not isinstance(proposal, str):
            return None, None
        match = _EXTRACT.search(proposal)
        if not match:
            return None, None
        base, sub = match.group(1), match.group(2)
        canonical = f"T{base}" if sub is None else f"T{base}.{int(sub):03d}"
        stripped = proposal.strip()
        note = None if stripped == canonical else f"{stripped!r} read as {canonical}"
        return canonical, note

    def validate(self, proposals: list[str] | tuple[str, ...]) -> Validation:
        """Validate proposed technique IDs. Nothing invalid survives this call."""
        accepted: list[Technique] = []
        rejected: list[Rejection] = []
        normalised: list[tuple[str, str]] = []
        seen: set[str] = set()

        for proposal in proposals:
            canonical, note = self.normalise(proposal)
            if canonical is None:
                rejected.append(
                    Rejection(
                        proposed=str(proposal)[:80],
                        reason="malformed",
                        detail="no ATT&CK technique ID of the form T#### or T####.### was present",
                    )
                )
                continue
            if not TECHNIQUE_PATTERN.match(canonical):
                rejected.append(
                    Rejection(proposed=str(proposal)[:80], reason="malformed", detail=canonical)
                )
                continue

            technique = self._techniques.get(canonical)
            if technique is None:
                rejected.append(
                    Rejection(
                        proposed=str(proposal)[:80],
                        reason="not_in_bundle",
                        detail=(
                            f"{canonical} does not exist in ATT&CK v{self.attack_version}; "
                            f"it was invented"
                        ),
                    )
                )
                continue
            if technique.deprecated:
                rejected.append(
                    Rejection(
                        proposed=str(proposal)[:80],
                        reason="deprecated",
                        detail=f"{canonical} ({technique.name}) is deprecated or revoked",
                    )
                )
                continue

            if note:
                normalised.append((str(proposal)[:80], canonical))
            if canonical not in seen:
                seen.add(canonical)
                accepted.append(technique)

        return Validation(
            accepted=tuple(accepted), rejected=tuple(rejected), normalised=tuple(normalised)
        )

    def require(self, proposals: list[str]) -> list[Technique]:
        """Validate, raising on the first rejection. For internal callers only.

        Model output goes through `validate` and a re-prompt, never this.
        Detector `technique_hints` go through this, because a detector shipping
        a bad ID is a bug in Bishop and should fail the test suite loudly.
        """
        result = self.validate(proposals)
        if result.rejected:
            raise TechniqueRejected(result.summary())
        return list(result.accepted)


@lru_cache(maxsize=1)
def load_catalogue(path: Path | None = None) -> TechniqueCatalogue:
    """Load the committed catalogue. Memoised — it never changes at runtime."""
    resolved = path or CATALOGUE_PATH
    if not resolved.exists():
        raise FileNotFoundError(
            f"ATT&CK catalogue missing at {resolved}. "
            f"Run `just attack` to fetch the bundle, then "
            f"`uv run python scripts/build_attck_catalogue.py`."
        )
    return TechniqueCatalogue(json.loads(resolved.read_text(encoding="utf-8")))


def validate_techniques(proposals: list[str]) -> Validation:
    """Convenience wrapper over the loaded catalogue."""
    return load_catalogue().validate(proposals)
