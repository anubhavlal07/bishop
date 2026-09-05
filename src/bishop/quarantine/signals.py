"""Deterministic detection of prompt-injection attempts in alert fields.

No model is involved in deciding whether a field carries an injection attempt.
That is not squeamishness about LLMs — it is that the thing being attacked
cannot also be the thing that adjudicates the attack.

Each check is a named pattern set with a weight. A field's risk is the combined
weight of what matched, and every match keeps the excerpt that triggered it so
an analyst can disagree with the call.

The important design decision is in `bishop.quarantine.core`: a match here does
not cause the text to be removed. Injected instructions are preserved, fenced,
and raised as an IOC. Stripping them would destroy the only evidence that
someone is attacking the SOC's tooling.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import Field

from bishop.quarantine.text import (
    BIDI_CONTROLS,
    analysis_forms,
    invisible_characters,
    mixed_script_words,
)
from bishop.schema.alert import BishopModel


class InjectionTechnique(StrEnum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_HIJACK = "role_hijack"
    DELIMITER_BREAK = "delimiter_break"
    VERDICT_MANIPULATION = "verdict_manipulation"
    TOOL_COERCION = "tool_coercion"
    EXFILTRATION_LURE = "exfiltration_lure"
    PROMPT_DISCLOSURE = "prompt_disclosure"
    ENCODING_EVASION = "encoding_evasion"
    INVISIBLE_TEXT = "invisible_text"
    HOMOGLYPH = "homoglyph"
    MULTILINGUAL_INSTRUCTION = "multilingual_instruction"
    OVERSIZED_FIELD = "oversized_field"


class InjectionSignal(BishopModel):
    """One match. Carries enough to argue with."""

    technique: InjectionTechnique
    #: Which transformation of the field matched: raw, despaced, base64, ...
    form: str
    #: The matched text, truncated. Kept verbatim — it is the evidence.
    excerpt: str
    weight: float
    note: str = ""


class FieldRisk(BishopModel):
    """The verdict on one field."""

    field: str
    signals: list[InjectionSignal] = Field(default_factory=list)
    score: float = 0.0

    @property
    def is_injection(self) -> bool:
        return self.score >= INJECTION_THRESHOLD

    @property
    def techniques(self) -> list[str]:
        seen: dict[str, None] = {}
        for signal in self.signals:
            seen.setdefault(signal.technique.value, None)
        return list(seen)


#: Tuned on `fixtures/injection/`. Below this a field is odd but not actionable;
#: at or above it Bishop raises an IOC and tells a human.
INJECTION_THRESHOLD = 0.5

#: Fields that are long by nature. A 4 KB command line is normal; a 4 KB
#: username is not, so the size check is per-field rather than global.
_LENGTH_BUDGET: dict[str, int] = {
    "command_line": 8192,
    "description": 4096,
    "body_excerpt": 8192,
    "url": 2048,
    "value_data": 4096,
    "action": 2048,
    "image_path": 1024,
}
_DEFAULT_LENGTH_BUDGET = 512


def _rx(*patterns: str) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE | re.DOTALL)


# Each entry: technique -> (compiled pattern, weight, note).
# Patterns are deliberately phrase-shaped rather than keyword-shaped. "ignore"
# appears in benign log text constantly; "ignore the above instructions" does not.
_PATTERNS: list[tuple[InjectionTechnique, re.Pattern[str], float, str]] = [
    (
        InjectionTechnique.INSTRUCTION_OVERRIDE,
        _rx(
            r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|preceding|earlier|foregoing)\s+"
            r"(?:instruction|prompt|direction|rule|guideline|context)",
            r"disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|preceding|earlier|system)",
            r"forget\s+(?:everything|all\s+(?:previous|prior)|what\s+you\s+were\s+told)",
            r"(?:new|updated|revised)\s+(?:instruction|directive|system\s+prompt)s?\s*[:\-]",
            r"override\s+(?:your|the|all)\s+(?:previous\s+)?(?:instruction|directive|rule|safety)",
            r"instead\s+of\s+(?:analy[sz]ing|investigating|the\s+above)\s*,?\s*(?:you\s+(?:should|must)|do)",
        ),
        0.6,
        "text instructs the reader to discard its own instructions",
    ),
    (
        InjectionTechnique.ROLE_HIJACK,
        _rx(
            r"you\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\b",
            r"(?:act|behave|respond)\s+as\s+(?:if\s+you\s+(?:are|were)|a|an)\b",
            r"^\s*(?:system|assistant|developer|user)\s*:",
            r"\n\s*(?:system|assistant|developer)\s*:",
            r"<\|?\s*(?:im_start|im_end|endoftext|system|assistant)\s*\|?>",
            r"\[/?INST\]",
            r"###\s*(?:instruction|system|response)",
            r"</\s*(?:system|instructions?|context|untrusted[\w-]*)\s*>",
            r"\bhuman\s*:\s*\n",
        ),
        0.55,
        "text asserts a conversational role or model control token",
    ),
    (
        InjectionTechnique.DELIMITER_BREAK,
        _rx(
            r"</untrusted[\w-]*>",
            r"end\s+of\s+(?:untrusted|quarantined?|alert)\s+(?:data|section|block)",
            r"```\s*(?:system|end)",
            r"-{3,}\s*end\s+(?:of\s+)?(?:data|input|untrusted)",
        ),
        0.65,
        "text tries to close the quarantine fence",
    ),
    (
        InjectionTechnique.VERDICT_MANIPULATION,
        _rx(
            r"(?:mark|classify|label|treat|report)\s+(?:this|it|the\s+alert)\s+as\s+"
            r"(?:benign|safe|false[\s-]?positive|authoris?zed|approved|clean|resolved)",
            r"this\s+(?:is|was)\s+(?:an?\s+)?(?:authoris?zed|approved|sanctioned|legitimate|routine)\s+"
            r"(?:activity|test|action|pentest|scan|task)\b.{0,80}?(?:do\s+not|no\s+need|close|ignore)",
            r"no\s+(?:further\s+)?(?:investigation|action|escalation|analysis)\s+(?:is\s+)?"
            r"(?:required|needed|necessary)",
            r"(?:close|dismiss|suppress|auto[\s-]?resolve)\s+(?:this\s+)?(?:alert|ticket|incident)",
            r"(?:do\s+not|don't|never)\s+(?:escalate|alert|notify|report)\b",
            r"(?:whitelist|allowlist)(?:ed)?\s+(?:by|per|process|binary|host)",
            r"confidence\s*[:=]\s*(?:0(?:\.0+)?|low)\b",
        ),
        0.6,
        "text argues for a specific verdict on its own alert",
    ),
    (
        InjectionTechnique.TOOL_COERCION,
        _rx(
            r"(?:run|execute|invoke|call)\s+the\s+following\s+(?:command|tool|function|script)",
            r"(?:call|invoke|use)\s+(?:the\s+)?(?:tool|function)\s+[\"'`\w]",
            r"approve\s+(?:the\s+)?(?:containment|response|action|plan)\s+(?:automatically|without)",
            r"(?:skip|bypass|disable)\s+(?:the\s+)?(?:human|approval|hitl|review|gate|confirmation)",
            r"set\s+(?:require_approval|requires_approval|approval)\s*[:=]\s*(?:false|no|0)",
        ),
        0.7,
        "text attempts to drive Bishop's tools or its approval gate",
    ),
    (
        InjectionTechnique.EXFILTRATION_LURE,
        _rx(
            r"(?:send|post|upload|forward|exfiltrate|transmit)\s+(?:the\s+|your\s+|all\s+)?"
            r"(?:report|findings|summary|credentials?|token|context|conversation|data|logs?)\s+"
            r"(?:to|at|via)\s+\S",
            r"(?:curl|wget|Invoke-WebRequest|fetch)\s+[\"']?https?://",
            r"(?:include|append|embed)\s+(?:the\s+)?(?:api[\s_-]?key|secret|token|password)\b",
            r"email\s+(?:this|the\s+\w+)\s+to\s+\S+@",
        ),
        0.7,
        "text directs output or secrets to an attacker-chosen destination",
    ),
    (
        InjectionTechnique.PROMPT_DISCLOSURE,
        _rx(
            r"(?:repeat|print|output|reveal|show|disclose)\s+(?:your|the)\s+"
            r"(?:system\s+prompt|instructions|rules|configuration|guidelines)",
            r"what\s+(?:are|were)\s+your\s+(?:original\s+)?instructions",
            r"verbatim\s+(?:copy\s+of\s+)?(?:your|the)\s+(?:prompt|instructions)",
        ),
        0.5,
        "text asks for Bishop's own instructions",
    ),
    (
        InjectionTechnique.MULTILINGUAL_INSTRUCTION,
        _rx(
            # Spanish / French / German / Portuguese / Italian
            r"ignor[ae]\s+(?:todas\s+)?las\s+instrucciones",
            r"ignorez\s+(?:toutes\s+)?les\s+instructions",
            r"ignoriere\s+(?:alle\s+)?(?:vorherigen\s+)?anweisungen",
            r"ignore\s+todas\s+as\s+instru",
            r"ignora\s+(?:tutte\s+)?le\s+istruzioni",
            # Russian / Ukrainian
            r"игнорируй(?:те)?\s+(?:все\s+)?(?:предыдущие\s+)?инструкции",
            # Chinese / Japanese / Korean
            r"忽略(?:以上|之前|所有)?(?:的)?(?:指令|指示)",
            r"以前の指示を無視",
            r"이전\s*지시를?\s*무시",
            # Hindi / Arabic
            r"पिछले\s+निर्देशों?\s+को\s+अनदेखा",
            r"تجاهل\s+(?:كل\s+)?التعليمات",
        ),
        0.6,
        "instruction-shaped text in a non-English script",
    ),
]

#: Instruction keywords that make a *decoded* payload interesting. Applied only
#: to decoded forms, where any imperative at all is suspicious.
_DECODED_IMPERATIVE = _rx(
    r"\bignore\b",
    r"\bdisregard\b",
    r"\binstructions?\b",
    r"\bsystem\s+prompt\b",
    r"\bbenign\b",
    r"\bfalse[\s-]?positive\b",
    r"\byou\s+are\s+now\b",
    r"\bdo\s+not\s+escalate\b",
    r"\bapprove\b",
)


def _excerpt(text: str, start: int, end: int, *, window: int = 60) -> str:
    lo = max(0, start - window // 2)
    hi = min(len(text), end + window // 2)
    snippet = text[lo:hi].replace("\n", "\\n").replace("\r", "")
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) else ""
    return f"{prefix}{snippet}{suffix}"


def scan_text(value: str, *, field: str = "value") -> FieldRisk:
    """Score one string for injection intent.

    Every transformation of the value is scanned — the original, the form with
    invisible characters removed, the de-spaced form, and anything that decoded
    out of it — because `ign\u200bore previous instructions` and its base64
    equivalent are the same attack.
    """
    risk = FieldRisk(field=field)
    if not value:
        return risk

    seen: set[tuple[str, str]] = set()

    for form_name, form_text in analysis_forms(value):
        is_decoded = form_name not in {"raw", "invisible-stripped", "despaced"}

        for technique, pattern, weight, note in _PATTERNS:
            for match in pattern.finditer(form_text):
                key = (technique.value, match.group(0)[:40].lower())
                if key in seen:
                    continue
                seen.add(key)
                # A payload that had to be encoded to get here is worse than the
                # same text in the clear: encoding is evidence of intent.
                bonus = 0.15 if is_decoded else 0.0
                risk.signals.append(
                    InjectionSignal(
                        technique=technique,
                        form=form_name,
                        excerpt=_excerpt(form_text, match.start(), match.end()),
                        weight=min(1.0, weight + bonus),
                        note=note,
                    )
                )

        if is_decoded and (found := _DECODED_IMPERATIVE.search(form_text)):
            key = ("decoded-imperative", form_name)
            if key not in seen:
                seen.add(key)
                risk.signals.append(
                    InjectionSignal(
                        technique=InjectionTechnique.ENCODING_EVASION,
                        form=form_name,
                        excerpt=_excerpt(form_text, found.start(), found.end()),
                        weight=0.55,
                        note=f"{form_name} payload decodes to instruction-shaped text",
                    )
                )

    hidden = invisible_characters(value)
    if hidden:
        overrides = [c for c in hidden if c in BIDI_CONTROLS]
        if overrides:
            # A right-to-left override in a file name is the `exe.doc` trick and
            # has no legitimate use in a Windows path. It stands on its own.
            weight, note = 0.5, f"{len(overrides)} bidirectional override characters"
        else:
            # A stray soft hyphen is not an attack. Weighted below the threshold
            # alone; combined with anything else it pushes the field over.
            weight = 0.35 if len(hidden) < 4 else 0.55
            note = f"{len(hidden)} zero-width characters splitting the visible text"
        risk.signals.append(
            InjectionSignal(
                technique=InjectionTechnique.INVISIBLE_TEXT,
                form="raw",
                excerpt=" ".join(f"U+{ord(c):04X}" for c in hidden[:8]),
                weight=weight,
                note=note,
            )
        )

    if homoglyphs := mixed_script_words(value):
        risk.signals.append(
            InjectionSignal(
                technique=InjectionTechnique.HOMOGLYPH,
                form="raw",
                excerpt=", ".join(homoglyphs[:5]),
                weight=0.4,
                note="words mixing more than one alphabet",
            )
        )

    budget = _LENGTH_BUDGET.get(field.rsplit(".", 1)[-1], _DEFAULT_LENGTH_BUDGET)
    if len(value) > budget:
        risk.signals.append(
            InjectionSignal(
                technique=InjectionTechnique.OVERSIZED_FIELD,
                form="raw",
                excerpt=f"{len(value)} characters (budget {budget})",
                weight=0.3,
                note="field far longer than plausible for its type",
            )
        )

    risk.score = combine(signal.weight for signal in risk.signals)
    return risk


def combine(weights) -> float:
    """Combine independent weights without ever reaching certainty.

    Probabilistic OR: two 0.6 signals give 0.84, not 1.2. Nothing here is
    certain enough to justify a score of 1.0, and a saturating sum would make
    every multi-signal field look identical.
    """
    remaining = 1.0
    for weight in weights:
        remaining *= 1.0 - max(0.0, min(1.0, weight))
    return round(1.0 - remaining, 4)
