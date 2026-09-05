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
    presentation_abuse,
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
    FORGED_PROVENANCE = "forged_provenance"
    OVERSIZED_FIELD = "oversized_field"


class InjectionSignal(BishopModel):
    """One match. Carries enough to argue with."""

    technique: InjectionTechnique
    form: str
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


INJECTION_THRESHOLD = 0.5

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


_IGNORE_VERBS = (
    "ignore",
    "pay no attention",
    "take no notice",
    "disregard",
    "overlook",
    "ignora",
    "ignorez",
    "ignoriere",
    "ignoruj",
    "zignoruj",
    "no tengas en cuenta",
    "omite",
    "pasa por alto",
    "haz caso omiso",
    "desconsidere",
    "desconsidera",
    "non tenere conto",
    "trascura",
    "ne tenez pas compte",
    "negeer",
    "bortse fra",
    "bortse från",
    "ignorer",
    "yoksay",
    "gormezden gel",
    "görmezden gel",
    "dikkate alma",
    "игнорируй",
    "игнорируйте",
    "не обращай внимания",
    "не обращайте внимания",
    "пренебрегай",
    "проигноруй",
    "ігноруй",
    "忽略",
    "无视",
    "無視",
    "不要理会",
    "不要理會",
    "略过",
    "略過",
    "무시",
    "무시하고",
    "무시하십시오",
    "अनदेखा",
    "उपेक्षा",
    "नजरअंदाज",
    "ध्यान मत",
    "تجاهل",
    "لا تلتفت",
    "أهمل",
    "התעלם",
    "אל תשים לב",
    "abaikan",
    "bo qua",
    "bỏ qua",
    "puuza",
    "เพิกเฉย",
    "ละเลย",
    "αγνόησε",
    "αγνοήστε",
    "παράβλεψε",
)

_INSTRUCTION_NOUNS = (
    "instruction",
    "instructions",
    "instrucciones",
    "indicaciones",
    "instrucoes",
    "instruções",
    "istruzioni",
    "anweisungen",
    "instructies",
    "instrukcje",
    "talimat",
    "talimatlari",
    "talimatları",
    "huong dan",
    "hướng dẫn",
    "instruksi",
    "maagizo",
    "regels",
    "reglas",
    "rules",
    "инструкции",
    "инструкций",
    "указания",
    "правила",
    "інструкції",
    "指令",
    "指示",
    "规则",
    "規則",
    "命令",
    "지시",
    "지침",
    "명령",
    "निर्देश",
    "निर्देशों",
    "नियम",
    "التعليمات",
    "الاوامر",
    "الأوامر",
    "הוראות",
    "ההוראות",
    "คำสั่ง",
    "กฎ",
    "οδηγίες",
    "εντολές",
)


def _alt(words: tuple[str, ...]) -> str:
    return "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True))


def _cooccurrence(verbs: tuple[str, ...], nouns: tuple[str, ...]) -> re.Pattern[str]:
    """A verb and a noun within 40 characters, in either order.

    The window is what keeps this from matching a long document that happens to
    contain both words far apart.
    """
    return re.compile(
        rf"(?:{_alt(verbs)}).{{0,40}}?(?:{_alt(nouns)})"
        rf"|(?:{_alt(nouns)}).{{0,40}}?(?:{_alt(verbs)})",
        re.IGNORECASE | re.DOTALL,
    )


def _ascii_only(words: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(w for w in words if w.isascii())


def _non_ascii(words: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(w for w in words if not w.isascii())


_ENGLISH_COOCCURRENCE = _cooccurrence(_ascii_only(_IGNORE_VERBS), _ascii_only(_INSTRUCTION_NOUNS))
_MULTILINGUAL = (
    _cooccurrence(
        _non_ascii(_IGNORE_VERBS) + _ascii_only(_IGNORE_VERBS),
        _non_ascii(_INSTRUCTION_NOUNS),
    )
    if _non_ascii(_INSTRUCTION_NOUNS)
    else _cooccurrence(_non_ascii(_IGNORE_VERBS), _INSTRUCTION_NOUNS)
)

_PATTERNS: list[tuple[InjectionTechnique, re.Pattern[str], float, str]] = [
    (
        InjectionTechnique.INSTRUCTION_OVERRIDE,
        _rx(
            r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|preceding|earlier|foregoing)\s+"
            r"(?:instruction|prompt|direction|rule|guideline|context)",
            r"disregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:\w+\s+)?(?:previous|prior|above|preceding|earlier|system|foregoing)",
            r"forget\s+(?:everything|all\s+(?:previous|prior)|what\s+you\s+were\s+told)",
            r"(?:new|updated|revised)\s+(?:instruction|directive|system\s+prompt)s?\s*[:\-]",
            r"override\s+(?:your|the|all)\s+(?:previous\s+)?(?:instruction|directive|rule|safety)",
            r"instead\s+of\s+\w+ing\b.{0,40}?(?:you\s+(?:should|must|will)|do\s+the|just\s+)",
            r"supersed(?:es?|ing)\s+(?:anything|any|all|everything|the)\b",
            r"(?:everything|all|the\s+text)\s+(?:before|above|preceding)\b.{0,40}?"
            r"(?:example|placeholder|template|sample|test\s+data|not\s+real)",
            r"treat\s+(?:the\s+)?\w+\s+above\s+as\s+(?:an?\s+)?(?:\w+\s+)?(?:example|placeholder|template|sample)",
            r"new\s+task\s*[:\-]",
            r"your\s+(?:real|actual|true|only)\s+task\s+is\b",
            r"from\s+now\s+on[, ]+you\s+(?:only\s+|must\s+|will\s+)?"
            r"(?:output|respond|reply|say|return|answer)",
            r"(?:priority\s+)?directive\s+from\s+(?:the\s+)?\w+",
            r"suspend\s+(?:the\s+)?(?:triage|analysis|heuristic|check|rule|detection)",
            r"stop\s+(?:your\s+)?(?:analysis|triage|investigation)\s+(?:here|now)",
        ),
        0.6,
        "text instructs the reader to discard its own instructions",
    ),
    (
        InjectionTechnique.INSTRUCTION_OVERRIDE,
        _ENGLISH_COOCCURRENCE,
        0.6,
        "text instructs the reader to discard its own instructions",
    ),
    (
        InjectionTechnique.ROLE_HIJACK,
        _rx(
            r"you\s+are\s+(?:now|no\s+longer)\s+(?:a|an|the)\b",
            r"(?:act|behave|respond)\s+as\s+(?:if\s+you\s+(?:are|were)|a|an)\b",
            r"^\s*(?:system|assistant|developer|user)\s*:",
            r"\n\s*(?:system|assistant|developer|user|human)\s*:",
            r"<\|?\s*(?:im_start|im_end|endoftext|system|assistant)\s*\|?>",
            r"<<\s*/?\s*SYS\s*>>",
            r"<\|\s*(?:start|end)_header_id\s*\|>",
            r"<\|\s*(?:eot_id|eom_id|begin_of_text|end_of_text|reserved_special_token)\w*\s*\|>",
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
            r"</\s*untrusted[\w-]*(?:\s[^>]*)?>",
            r"<\s*untrusted[\w-]*(?:\s[^>]*)?>",
            r"\[!!\s*flagged",
            r"\[\s*(?:cleared|reviewed|dismissed)\s+by\s+analyst",
            r"</?\s*(?:detector-results|injection-findings|incident-context|"
            r"investigator-reports|proposed-verdict|settled-verdict|validation-failure)"
            r"(?:\s[^>]*)?>",
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
            r"(?:mark|classify|label|treat|report|record|set|flag)\s+"
            r"(?:this|it|that|the)(?:\s+\w+){0,3}\s+as\s+(?:an?\s+)?"
            r"(?:benign|safe|false[\s_-]?positive|authoris?zed|approved|clean|resolved|"
            r"expected|informational|low[\s-]?risk|non[\s-]?malicious)",
            r"this\s+(?:is|was)\s+(?:an?\s+)?(?:authoris?zed|approved|sanctioned|legitimate|routine)\s+"
            r"(?:activity|test|action|pentest|scan|task)\b.{0,80}?(?:do\s+not|no\s+need|close|ignore)",
            r"no\s+(?:further\s+)?(?:investigation|action|escalation|analysis)\s+(?:is\s+)?"
            r"(?:required|needed|necessary)",
            r"(?:close|dismiss|suppress|auto[\s-]?resolve)\s+(?:this\s+)?(?:alert|ticket|incident)",
            r"(?:do\s+not|don't|never)\s+(?:escalate|alert|notify|report)\b",
            r"(?:whitelist|allowlist)(?:ed)?\s+(?:by|per|process|binary|host)",
            r"confidence\s*[:=]\s*(?:0(?:\.0+)?|low)\b",
            r"(?:the\s+)?(?:correct\s+|final\s+|previous\s+)?verdict\s+(?:for\s+\w+(?:\s+\w+)?\s+)?is\s+"
            r"(?:an?\s+)?(?:benign|false[\s_-]?positive|true[\s_-]?positive|authoris?zed|approved)",
            r"this\s+(?:alert|incident|event|activity|detection)\s+is\s+(?:an?\s+)?"
            r"(?:false[\s_-]?positive|benign|expected|routine|authoris?zed|approved|known[\s-]good)",
            r"[\"']?(?:label|verdict|classification)[\"']?\s*[:=]\s*[\"']?"
            r"(?:false_positive|benign|benign_true_positive|no[_\s-]?action)",
            r"[\"']?(?:assessed_severity|severity|priority|queue)[\"']?\s*[:=]\s*[\"']?"
            r"(?:informational|none|p5|auto[_\s-]?close|suppress)",
        ),
        0.6,
        "text argues for a specific verdict on its own alert",
    ),
    (
        InjectionTechnique.FORGED_PROVENANCE,
        _rx(
            r"approved\s+by\s+\S",
            r"authoris?zed[\s-]+by[\s:=]+\S",
            r"--?authoris?ed[\s-]by[\s=]",
            r"sign(?:ed)?[\s-]?off\s+(?:by|on)\b",
            r"change\s+(?:advisory\s+board|ticket|request)\s+(?:approved|authoris?zed|CHG-)",
            r"\b(?:CHG|CR|RFC|INC|TICKET)[\s-]?\d{3,}\b.{0,60}?"
            r"(?:approved|authoris?zed|sanctioned|sign(?:ed)?[\s-]?off|auto[\s-]?close)",
            r"(?:approved|authoris?zed|sanctioned).{0,60}?\b(?:CHG|CR|RFC|INC|TICKET)[\s-]?\d{3,}\b",
            r"(?:previously|already)\s+(?:triaged|reviewed|investigated|assessed)\b",
            r"clos(?:ed|ure)\s+as\s+(?:benign|false[\s_-]?positive|no[\s-]?action|duplicate)",
            r"duplicate\s+of\s+(?:INC|TICKET|CASE)[\s-]?\d+",
            r"\b(?:engagement|rules?\s+of\s+engagement|roe)\b[\s:=-]+\S+.{0,40}?"
            r"(?:in[\s-]?scope|authoris?ed|approved)",
            r"[\\/](?:allow[\s_-]?list(?:ed)?|white[\s_-]?list(?:ed)?|approved[\s_-]?binaries|"
            r"known[\s_-]?good|trusted|sanctioned)[\\/]",
        ),
        0.45,
        "text asserts an approval, an owner, or a prior decision that Bishop cannot confirm",
    ),
    (
        InjectionTechnique.TOOL_COERCION,
        _rx(
            r"(?:run|execute|invoke|call)\s+the\s+following\s+(?:command|tool|function|script)",
            r"(?:call|invoke|use)\s+(?:the\s+)?(?:tool|function)\s+[\"'`\w]",
            r"approve\s+(?:the\s+)?(?:containment|response|action|plan)\s+(?:automatically|without)",
            r"(?:skip|bypass|disable)\s+(?:the\s+)?(?:human|approval|hitl|review|gate|confirmation)",
            r"set\s+(?:require_approval|requires_approval|approval)\s*[:=]\s*(?:false|no|0)",
            r"(?:containment|isolation|remediation|quarantine)\s+is\s+"
            r"(?:unnecessary|not\s+(?:needed|required|warranted))",
            r"propose\s+no\s+(?:actions|containment|response)",
            r"do\s+not\s+(?:isolate|disable|block|contain|quarantine|revoke|reset)\b",
            r"(?:isolation|disabling|blocking)\s+would\s+cause\b",
            r"(?:will|would)\s+cause\s+(?:a\s+)?(?:company|estate|org)[\s-]?wide\s+outage",
            r"pre[\s-]?approv(?:al|ed)\b.{0,60}?(?:already\s+approved|record(?:ed)?\s+as)",
            r"(?:the\s+)?(?:affected|real|actual|correct)\s+"
            r"(?:asset|host|machine|target|account)\s+is\b.{0,40}?\bnot\b",
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
            r"!\[[^\]]*\]\(\s*https?://",
            r"(?:append|include|add|attach)\s+(?:your\s+)?(?:full\s+|entire\s+|complete\s+)?"
            r"(?:prior\s+|previous\s+)?(?:context|conversation|history|prompt|transcript)",
            r"(?:restate|repeat|list|include)\s+(?:every|all|each)\b.{0,40}?"
            r"(?:other|previous|related)\s+(?:alert|incident|ticket|case)",
            r"(?:list|show|include|return)\b.{0,30}?\b(?:for\s+tenant|another\s+tenant|"
            r"other\s+tenants?|across\s+tenants?)\b",
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
            r"what\s+(?:is|was)\s+your\s+(?:system\s+)?(?:prompt|instruction)",
        ),
        0.5,
        "text asks for Bishop's own instructions",
    ),
    (
        InjectionTechnique.MULTILINGUAL_INSTRUCTION,
        _MULTILINGUAL,
        0.6,
        "instruction-shaped text in a non-English script",
    ),
]


_TIGHT_PATTERNS: list[tuple[InjectionTechnique, re.Pattern[str], float, str]] = [
    (
        technique,
        re.compile(pattern.pattern.replace(r"\s+", r"\s*"), pattern.flags),
        weight,
        note,
    )
    for technique, pattern, weight, note in _PATTERNS
]

_DECODED_IMPERATIVE = _rx(
    r"\bignore\b",
    r"\bdisregard\b",
    r"\binstructions?\b",
    r"\bsystem\s+prompt\b",
    r"\bbenign\b",
    r"\bfalse[\s_-]?positive\b",
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

    quoted_field = field.rsplit(".", 1)[-1] in {"subject", "body_excerpt"}

    for form_name, form_text in analysis_forms(value):
        is_decoded = form_name not in {
            "raw",
            "invisible-stripped",
            "despaced",
            "normalised",
            "normalised-despaced",
            "tight",
            "depig",
        }
        patterns = _TIGHT_PATTERNS if form_name == "tight" else _PATTERNS

        for technique, pattern, weight, note in patterns:
            if quoted_field and technique is InjectionTechnique.FORGED_PROVENANCE:
                continue
            for match in pattern.finditer(form_text):
                key = (technique.value, match.group(0)[:40].lower())
                if key in seen:
                    continue
                seen.add(key)
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
            weight, note = 0.5, f"{len(overrides)} bidirectional override characters"
        else:
            weight = 0.35 if len(hidden) < 3 else 0.55
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

    if (folded := presentation_abuse(value)) >= 4:
        risk.signals.append(
            InjectionSignal(
                technique=InjectionTechnique.ENCODING_EVASION,
                form="raw",
                excerpt=value[:60],
                weight=0.5,
                note=(
                    f"{folded} letters written in a non-standard Unicode presentation form "
                    f"(mathematical, fullwidth or small-capital), which folds to ordinary "
                    f"text for a model and has no legitimate use in this field"
                ),
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
