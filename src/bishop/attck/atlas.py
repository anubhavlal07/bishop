"""MITRE ATLAS — the taxonomy for attacks against the analyst, not the estate.

Enterprise ATT&CK has no technique for "the adversary wrote instructions into a
log field to steer the SOC's automated triage", because ATT&CK describes attacks
on infrastructure and this is an attack on the tool reading it. Mapping prompt
injection to a plausible-looking `T####` would be exactly the fabrication that
`CLAUDE.md` §3 forbids, so Bishop does not.

ATLAS covers it properly. The sub-technique that fits Bishop exactly is
`AML.T0051.001`, *Indirect* prompt injection: the attacker never talks to the
model, they write into data the model will later read. A Sysmon command line is
that data.

The IDs below were read out of `dist/v6/ATLAS-2026.08.yaml` in
`mitre-atlas/atlas-data`, not recalled. Keeping this catalogue separate from the
ATT&CK one means an ATLAS ID can never be rendered as though it were an ATT&CK
technique.
"""

from __future__ import annotations

from dataclasses import dataclass

#: The ATLAS release these IDs were read from. Numbering has been reorganised
#: between ATLAS releases before, so a report names the release.
ATLAS_VERSION = "2026.08"
ATLAS_FORMAT_VERSION = "6.0.0"
ATLAS_SOURCE = "https://atlas.mitre.org/"


@dataclass(frozen=True, slots=True)
class AtlasTechnique:
    id: str
    name: str
    #: Why Bishop can claim this one — what it actually observed.
    relevance: str
    parent: str | None = None

    @property
    def url(self) -> str:
        return f"https://atlas.mitre.org/techniques/{self.id.replace('.', '/')}"

    @property
    def label(self) -> str:
        return f"{self.id} {self.name}"


#: Only the techniques Bishop can actually produce evidence for. A wider list
#: would be decoration.
ATLAS_TECHNIQUES: dict[str, AtlasTechnique] = {
    t.id: t
    for t in (
        AtlasTechnique(
            "AML.T0051",
            "LLM Prompt Injection",
            "instructions embedded in an attacker-controlled alert field",
        ),
        AtlasTechnique(
            "AML.T0051.001",
            "LLM Prompt Injection: Indirect",
            "the payload arrived through data Bishop reads, not through a user prompt",
            parent="AML.T0051",
        ),
        AtlasTechnique(
            "AML.T0068",
            "LLM Prompt Obfuscation",
            "the payload was encoded, split or hidden to survive a keyword filter",
        ),
        AtlasTechnique(
            "AML.T0054",
            "LLM Jailbreak",
            "the payload tried to replace the analyst's role or its instructions",
        ),
        AtlasTechnique(
            "AML.T0053",
            "AI Agent Tool Invocation",
            "the payload tried to drive Bishop's tools or its approval gate",
        ),
        AtlasTechnique(
            "AML.T0067",
            "LLM Trusted Output Components Manipulation",
            "the payload tried to dictate the verdict Bishop reports",
        ),
        AtlasTechnique(
            "AML.T0056",
            "Extract LLM System Prompt",
            "the payload asked Bishop to disclose its own instructions",
        ),
    )
}

#: Every injection Bishop catches is indirect by construction — it arrived in a
#: log field, not from a person typing at it.
BASE_INJECTION_TECHNIQUES: tuple[str, ...] = ("AML.T0051", "AML.T0051.001")

#: Injection signal name -> the additional ATLAS techniques it evidences.
SIGNAL_TO_ATLAS: dict[str, tuple[str, ...]] = {
    "instruction_override": ("AML.T0054",),
    "role_hijack": ("AML.T0054",),
    "delimiter_break": (),
    "verdict_manipulation": ("AML.T0067",),
    "tool_coercion": ("AML.T0053",),
    "exfiltration_lure": ("AML.T0053",),
    "prompt_disclosure": ("AML.T0056",),
    "encoding_evasion": ("AML.T0068",),
    "invisible_text": ("AML.T0068",),
    "homoglyph": ("AML.T0068",),
    "multilingual_instruction": ("AML.T0068",),
    # A forged approval is aimed at the output Bishop is trusted to produce.
    "forged_provenance": ("AML.T0067",),
    "oversized_field": (),
}


def atlas_for_signals(signal_names: list[str] | tuple[str, ...]) -> list[AtlasTechnique]:
    """Map injection signal names onto ATLAS techniques, in a stable order.

    The two base techniques come first and always, because anything reaching
    this function is by definition an indirect prompt injection.
    """
    identifiers: list[str] = list(BASE_INJECTION_TECHNIQUES)
    for name in signal_names:
        for identifier in SIGNAL_TO_ATLAS.get(name, ()):
            if identifier not in identifiers:
                identifiers.append(identifier)
    return [ATLAS_TECHNIQUES[i] for i in identifiers if i in ATLAS_TECHNIQUES]


def is_atlas_id(value: object) -> bool:
    return isinstance(value, str) and value.strip().upper().startswith("AML.T")


def validate_atlas(proposals: list[str] | tuple[str, ...]) -> tuple[list[str], list[str]]:
    """Split proposals into `(known, unknown)` ATLAS IDs.

    Same rule as ATT&CK: an ID Bishop cannot confirm does not reach a report.
    """
    known: list[str] = []
    unknown: list[str] = []
    for proposal in proposals:
        canonical = str(proposal).strip().upper()
        if canonical in ATLAS_TECHNIQUES:
            if canonical not in known:
                known.append(canonical)
        else:
            unknown.append(str(proposal)[:80])
    return known, unknown
