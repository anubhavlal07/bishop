"""Text utilities the quarantine boundary is built on.

Two jobs, kept separate from detection so both are testable on their own:

1. Expose what a string is *hiding* — zero-width characters, bidirectional
   overrides, mixed scripts, base64 and percent-encoded payloads. Bishop looks
   at the decoded form when deciding whether a field carries an instruction.

2. Make a string safe to place inside a fenced block without letting it close
   the fence.

Note the asymmetry: decoding is used for *detection*, never for rendering.
The analyst and the model both see the original bytes. Silently normalising an
attacker's payload before showing it would destroy the evidence.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from contextlib import suppress
from urllib.parse import unquote

#: Characters with no visible width, used to break up keywords or smuggle text.
ZERO_WIDTH = {
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "⁠",  # word joiner
    "﻿",  # zero width no-break space
    "­",  # soft hyphen
    "᠎",  # Mongolian vowel separator
    "⁡",  # function application
    "⁢",  # invisible times
    "⁣",  # invisible separator
    "⁤",  # invisible plus
    "͏",  # combining grapheme joiner
    "ᅟ",  # Hangul choseong filler
    "ᅠ",  # Hangul jungseong filler
    "ㅤ",  # Hangul filler
    "ﾠ",  # halfwidth Hangul filler
}

#: Variation selectors. Invisible, and enough of them can encode a whole
#: message; the VS15/VS16 pair also flips emoji presentation, which is how a
#: keyword can be split without a zero-width character.
VARIATION_SELECTORS = range(0xFE00, 0xFE10)

#: Bidirectional controls. The RTL override is the classic filename-spoofing trick.
BIDI_CONTROLS = {
    "‪",
    "‫",
    "‬",
    "‭",
    "‮",  # RLO — "cod.exe" renders as "exe.doc"
    "⁦",
    "⁧",
    "⁨",
    "⁩",
    "‎",
    "‏",
}

#: Unicode tag characters. Invisible to a human, tokenised by a model.
TAG_RANGE = range(0xE0000, 0xE0080)

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){12,}")
_PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2}){4,}")
_UNICODE_ESCAPE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")


def invisible_characters(text: str) -> list[str]:
    """Return the zero-width, bidi and tag characters present, in order."""
    found: list[str] = []
    for char in text:
        if char in ZERO_WIDTH or char in BIDI_CONTROLS or ord(char) in TAG_RANGE:
            found.append(char)
    return found


def strip_invisible(text: str) -> str:
    """Remove characters that hide structure, leaving the visible text."""
    return "".join(
        c
        for c in text
        if c not in ZERO_WIDTH and c not in BIDI_CONTROLS and ord(c) not in TAG_RANGE
    )


def script_of(char: str) -> str:
    """A coarse script name for one character, via its Unicode name.

    Good enough to spot a Cyrillic 'а' sitting inside a Latin word, which is all
    the homoglyph check needs.
    """
    if not char.isalpha():
        return "common"
    try:
        name = unicodedata.name(char)
    except ValueError:
        return "unknown"
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC"):
        if name.startswith(script):
            return script.lower()
    return "other"


def mixed_script_words(text: str) -> list[str]:
    """Words built from more than one alphabet — a homoglyph substitution.

    `pаypal` with a Cyrillic 'а' looks identical to `paypal` and hashes
    differently, which is the entire point of the trick.
    """
    suspicious: list[str] = []
    for word in re.findall(r"\w{3,}", text, flags=re.UNICODE):
        scripts = {script_of(c) for c in word if c.isalpha()}
        scripts.discard("common")
        scripts.discard("unknown")
        if len(scripts) > 1:
            suspicious.append(word)
    return suspicious


#: Latin lookalikes from other alphabets. Not exhaustive — Unicode's confusables
#: table has thousands of entries — but these are the substitutions that actually
#: appear, because they are the ones that render identically in a sans-serif UI.
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0445": "x",
        "\u0443": "y",
        "\u0456": "i",
        "\u0455": "s",
        "\u0501": "d",
        "\u043d": "h",
        "\u043a": "k",
        "\u043c": "m",
        "\u0442": "t",
        "\u0432": "b",
        "\u0410": "A",
        "\u0415": "E",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0425": "X",
        "\u0423": "Y",
        "\u0406": "I",
        "\u041d": "H",
        "\u041a": "K",
        "\u041c": "M",
        "\u0422": "T",
        "\u0412": "B",
        # Greek
        "\u03b1": "a",
        "\u03bf": "o",
        "\u03c1": "p",
        "\u03bd": "v",
        "\u03b5": "e",
        "\u03c4": "t",
        "\u03b9": "i",
        "\u03ba": "k",
        "\u03c5": "u",
        "\u03c7": "x",
        "\u0391": "A",
        "\u039f": "O",
        "\u03a1": "P",
        "\u0395": "E",
        "\u03a4": "T",
        "\u0399": "I",
        "\u039a": "K",
        "\u03a7": "X",
        "\u0392": "B",
        "\u039c": "M",
        # Armenian and others that turn up
        "\u0561": "a",
        "\u0585": "o",
        "\u04cf": "l",
        "\u217c": "l",
        "\u2170": "i",
    }
)


def nfkc(text: str) -> str:
    """Compatibility-normalise.

    This is what collapses fullwidth Latin, mathematical alphanumerics and
    small-capital letterforms back to ASCII. A model reads all three as ordinary
    words; without this pass the scanner sees a single-script string with no
    keyword in it and says nothing.
    """
    return unicodedata.normalize("NFKC", text)


def confusable_fold(text: str) -> str:
    """Map common cross-alphabet lookalikes onto their Latin equivalents.

    Complements `mixed_script_words`, which only *reports* that a word mixes
    alphabets. Folding lets the phrase patterns match the word an analyst would
    read, so a Cyrillic-spelled instruction is caught by the instruction rules
    rather than only by the weaker homoglyph signal.
    """
    return text.translate(_CONFUSABLES)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def _is_utf16le(data: bytes) -> bool:
    """True when the bytes look like ASCII text encoded UTF-16LE."""
    if len(data) < 8 or len(data) % 2:
        return False
    if any(data[i] for i in range(1, len(data), 2)):
        return False
    return _printable_ratio(data[0::2]) >= 0.85


def decoded_candidates(text: str, *, max_candidates: int = 8) -> list[tuple[str, str]]:
    """Decode embedded payloads and return `(encoding, decoded_text)` pairs.

    Only decodings that produce mostly-printable text are returned; a base64
    run that decodes to binary is a hash or a blob, not a hidden sentence.
    """
    results: list[tuple[str, str]] = []

    def add(encoding: str, value: str) -> None:
        if len(results) >= max_candidates:
            return
        cleaned = value.strip()
        if len(cleaned) >= 8 and cleaned != text:
            results.append((encoding, cleaned))

    for match in _B64_RUN.findall(text)[:max_candidates]:
        padded = match + "=" * (-len(match) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if _is_utf16le(raw):
            # PowerShell `-EncodedCommand` is UTF-16LE, so half the bytes are
            # nulls and the printable-ratio test below would reject it.
            with suppress(UnicodeDecodeError):
                add("base64-utf16", raw.decode("utf-16-le", errors="strict"))
            continue
        if _printable_ratio(raw) < 0.85:
            continue
        try:
            add("base64", raw.decode("utf-8", errors="strict"))
        except UnicodeDecodeError:
            continue

    for match in _PERCENT.findall(text)[:max_candidates]:
        add("percent", unquote(match))

    for match in _HEX_RUN.findall(text)[:max_candidates]:
        compact = re.sub(r"[\s:]", "", match)
        if len(compact) % 2:
            compact = compact[:-1]
        try:
            raw = bytes.fromhex(compact)
        except ValueError:
            continue
        if _printable_ratio(raw) >= 0.85:
            add("hex", raw.decode("utf-8", errors="replace"))

    if _UNICODE_ESCAPE.search(text):
        with suppress(UnicodeDecodeError, ValueError):
            add("unicode-escape", text.encode("ascii", "ignore").decode("unicode_escape"))

    return results


#: A run of at least six single characters, each followed by one to four
#: separators. Ordinary prose never matches: "The" fails at the first unit,
#: because 'T' is followed by a word character rather than a separator.
_SPLIT_RUN = re.compile(r"(?:\w[\s.\-_*]{1,4}){5,}\w")


def despaced(text: str) -> str:
    """Collapse character-splitting evasion: `i g n o r e` becomes `ignore`.

    Word boundaries are reconstructed rather than discarded, because
    `ignoreallprevious` matches none of the phrase patterns that
    `ignore all previous` does — and reconstructing them is what makes the
    evasion visible.

    Attackers separate letters with one character and words with more, so a
    longer separator run marks a word gap. When the letter separator is not
    whitespace (`i.g.n.o.r.e a.l.l`), whitespace itself marks the gap.
    """

    def collapse(match: re.Match[str]) -> str:
        run = match.group(0)
        gap = r"\s+" if re.search(r"[.\-_*]", run) else r"[\s.\-_*]{2,}"
        words = (re.sub(r"[\s.\-_*]", "", part) for part in re.split(gap, run))
        return " ".join(word for word in words if word)

    return _SPLIT_RUN.sub(collapse, text)


def analysis_forms(text: str) -> list[tuple[str, str]]:
    """Every form of a string the signal checks should look at.

    Returns `(form_name, text)` pairs: the original, the invisible-stripped
    form, the de-spaced form, the Unicode-normalised and confusable-folded
    forms, and anything that decoded out of it. Duplicates are dropped, so a
    plain ASCII value costs one scan rather than seven.
    """
    forms: list[tuple[str, str]] = [("raw", text)]
    seen = {text}

    def add(name: str, value: str) -> None:
        if value not in seen:
            seen.add(value)
            forms.append((name, value))

    stripped = strip_invisible(text)
    add("invisible-stripped", stripped)
    add("despaced", despaced(stripped))

    # Normalisation last, over the already-stripped form, so a payload that
    # combines tricks — fullwidth letters split by zero-width spaces — still
    # reduces to something the phrase patterns can match.
    normalised = confusable_fold(nfkc(stripped))
    add("normalised", normalised)
    add("normalised-despaced", despaced(normalised))

    for encoding, decoded in decoded_candidates(stripped):
        add(encoding, decoded)
    return forms


def shannon_entropy(text: str) -> float:
    """Bits per character. Used by the DNS and encoding checks."""
    if not text:
        return 0.0
    from collections import Counter
    from math import log2

    counts = Counter(text)
    length = len(text)
    bits = -sum((c / length) * log2(c / length) for c in counts.values())
    return abs(bits)  # a single repeated character yields -0.0 otherwise
