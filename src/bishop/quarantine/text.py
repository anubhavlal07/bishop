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

ZERO_WIDTH = {
    "​",
    "‌",
    "‍",
    "⁠",
    "﻿",
    "­",
    "᠎",
    "⁡",
    "⁢",
    "⁣",
    "⁤",
    "͏",
    "ᅟ",
    "ᅠ",
    "ㅤ",
    "ﾠ",
}

VARIATION_SELECTORS = range(0xFE00, 0xFE10)

BIDI_CONTROLS = {
    "‪",
    "‫",
    "‬",
    "‭",
    "‮",
    "⁦",
    "⁧",
    "⁨",
    "⁩",
    "‎",
    "‏",
}

TAG_RANGE = range(0xE0000, 0xE0080)

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]?){5,}")
_PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2})")
_UNICODE_ESCAPE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")


def _is_invisible(char: str) -> bool:
    """One predicate, so the set cannot drift between detection and stripping."""
    return (
        char in ZERO_WIDTH
        or char in BIDI_CONTROLS
        or ord(char) in TAG_RANGE
        or ord(char) in VARIATION_SELECTORS
    )


def invisible_characters(text: str) -> list[str]:
    """Return the zero-width, bidi, tag and variation-selector characters."""
    return [c for c in text if _is_invisible(c)]


def strip_invisible(text: str) -> str:
    """Remove characters that hide structure, leaving the visible text."""
    return "".join(c for c in text if not _is_invisible(c))


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


_CONFUSABLES = str.maketrans(
    {
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


def presentation_abuse(text: str) -> int:
    """Count letters written in a non-standard Unicode presentation form.

    Mathematical bold, fullwidth Latin and small-capital letterforms all fold to
    plain ASCII under NFKC, and a model reads every one of them as ordinary
    words. None of them has any business in a command line or a file name, so
    the *presence* of them is a signal even when the folded text is too short
    to match a phrase pattern — `\U0001d422\U0001d420\U0001d427\U0001d428\U0001d42b\U0001d41e all previous` carries no
    "instructions" for a pattern to find, and is still obviously an attempt.
    """
    return sum(
        1
        for c in text
        if c.isalpha() and (folded := unicodedata.normalize("NFKC", c)) != c and folded.isascii()
    )


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


ROT13 = str.maketrans(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM",
)

_B32_RUN = re.compile(r"[A-Z2-7]{16,}={0,6}")
_HTML_ENTITY = re.compile(r"(?:&#x?[0-9a-fA-F]{1,6};){3,}")
_DECIMAL_CODES = re.compile(r"(?:\b\d{2,3}\b[\s,]+){5,}\b\d{2,3}\b")
_HEX_ESCAPE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")
_ASCII85 = re.compile(r"[!-u]{20,}")


def _decode_html_entities(text: str) -> str:
    import html

    return html.unescape(text)


def _decode_decimal_codes(text: str) -> str:
    codes = [int(n) for n in re.findall(r"\b\d{2,3}\b", text)]
    return "".join(chr(c) for c in codes if 9 <= c < 127)


def transform_candidates(text: str) -> list[tuple[str, str]]:
    """Reinterpretations of a string, for scanning only.

    Distinct from `decoded_candidates`, which answers "was something *encoded*
    here" and is used as evidence by the `encoded_command` detector. rot13 and
    reversal are involutions: they always produce output, so treating them as
    decodings made every ordinary command line look like it carried a payload.

    Applying them unconditionally is still right for *scanning* — a wrong
    application produces gibberish that matches no pattern.
    """
    return [
        ("rot13", text.translate(ROT13)),
        ("reversed", text[::-1]),
    ]


def _b64(chunk: str) -> bytes:
    return base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)


def _b32(chunk: str) -> bytes:
    return base64.b32decode(chunk + "=" * (-len(chunk) % 8), casefold=True)


def _is_utf16le_bytes(data: bytes) -> bool:
    return _is_utf16le(data)


def _try_alignments(run: str, decoder) -> list[bytes]:
    """Decode a run, trying each leading offset.

    A regex match for a base64 run starts wherever the preceding non-alphabet
    character was, and that boundary rarely falls on the codec's block
    alignment — `x.exe -e aWdub…` compacts to `…-eaWdub…`, so the run begins one
    character early and every subsequent quantum decodes to noise. Trying the
    first few offsets costs nothing and recovers the payload.
    """
    out: list[bytes] = []
    for offset in range(8):
        chunk = run[offset:].rstrip("=")
        if len(chunk) < 12:
            break
        try:
            raw = decoder(chunk)
        except (binascii.Error, ValueError):
            continue
        if _printable_ratio(raw) >= 0.85 or _is_utf16le(raw):
            out.append(raw)
    return out


def decoded_candidates(text: str, *, max_candidates: int = 12) -> list[tuple[str, str]]:
    """Decode embedded payloads and return `(encoding, decoded_text)` pairs.

    Only decodings that produce mostly-printable text are returned; a base64
    run that decodes to binary is a hash or a blob, not a hidden sentence.

    The codec list is long because the red-team corpus made it long. Each entry
    is one that got a payload past a shorter list: base32, rot13, reversal,
    ascii85, HTML entities, decimal character codes, backslash-x escapes, and base64
    that had been chunked with spaces to defeat a run-length threshold.
    """
    results: list[tuple[str, str]] = []

    def add(encoding: str, value: str) -> None:
        if len(results) >= max_candidates:
            return
        cleaned = value.strip()
        if len(cleaned) >= 8 and cleaned != text and all(cleaned != v for _, v in results):
            results.append((encoding, cleaned))

    compact = re.sub(r"\s", "", text)
    for candidate, label in ((text, "base64"), (compact, "base64-chunked")):
        for match in _B64_RUN.findall(candidate)[:max_candidates]:
            for decoded in _try_alignments(match, _b64):
                if _is_utf16le_bytes(decoded):
                    with suppress(UnicodeDecodeError):
                        add("base64-utf16", decoded.decode("utf-16-le", errors="strict"))
                    continue
                with suppress(UnicodeDecodeError):
                    add(label, decoded.decode("utf-8", errors="strict"))

    for match in _B32_RUN.findall(compact.upper())[:max_candidates]:
        for decoded in _try_alignments(match, _b32):
            with suppress(UnicodeDecodeError):
                add("base32", decoded.decode("utf-8", errors="strict"))

    with suppress(ValueError, binascii.Error):
        for match in _ASCII85.findall(text)[:2]:
            raw = base64.a85decode(match, adobe=False)
            if _printable_ratio(raw) >= 0.85:
                with suppress(UnicodeDecodeError):
                    add("ascii85", raw.decode("utf-8", errors="strict"))

    if _HTML_ENTITY.search(text):
        add("html-entities", _decode_html_entities(text))

    if _DECIMAL_CODES.search(text):
        add("decimal-codes", _decode_decimal_codes(text))

    if _HEX_ESCAPE.search(text):
        with suppress(UnicodeDecodeError, ValueError):
            add("hex-escape", text.encode("ascii", "ignore").decode("unicode_escape"))

    if _PERCENT.search(text):
        add("percent", unquote(text))

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


_SEP = r"[\s.\-_*/|,+:;~^]"

_SPLIT_RUN = re.compile(rf"(?:\w{_SEP}{{1,4}}){{5,}}\w")


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
        gap = r"\s+" if re.search(r"[.\-_*/|,+:;~^]", run) else rf"{_SEP}{{2,}}"
        words = (re.sub(_SEP, "", part) for part in re.split(gap, run))
        return " ".join(word for word in words if word)

    return _SPLIT_RUN.sub(collapse, text)


def tighten(text: str) -> str | None:
    """Remove every separator inside a split run, or `None` if there is none.

    `despaced` reconstructs word gaps by treating a wider separator run as a
    space, which fails when the attacker uses a single space between *every*
    character — `i g n o r e a l l p r e v i o u s` has no wider gap to find.
    The fully-collapsed form matches nothing on its own, so the phrase patterns
    are also compiled in a whitespace-optional variant and run against this.

    Returns `None` when no split run is present, so an ordinary value is not
    scanned twice for nothing — and, more importantly, so prose is never
    de-spaced into an accidental keyword.
    """
    if not _SPLIT_RUN.search(text):
        return None
    return _SPLIT_RUN.sub(lambda m: re.sub(_SEP, "", m.group(0)), text)


def depig(text: str) -> str | None:
    """Undo pig latin, which a model reads fluently and no pattern covers.

    `ignoreway allway eviouspray` is `ignore all previous`. Words ending `way`
    lose it; words ending `ay` had their leading consonant cluster moved to the
    end, so try moving one to three characters back.
    """
    words = re.findall(r"\b\w+ay\b", text)
    if len(words) < 3:
        return None

    def restore(match: re.Match[str]) -> str:
        word = match.group(0)
        if word.endswith("way") and len(word) > 4:
            return word[:-3]
        stem = word[:-2]
        for size in (2, 1, 3):
            if len(stem) > size:
                return stem[-size:] + stem[:-size]
        return word

    return re.sub(r"\b\w+ay\b", restore, text)


def analysis_forms(text: str, *, depth: int = 0) -> list[tuple[str, str]]:
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

    normalised = confusable_fold(nfkc(stripped))
    add("normalised", normalised)
    add("normalised-despaced", despaced(normalised))

    for name, transformed in transform_candidates(stripped):
        add(name, transformed)

    if (tight := tighten(stripped)) is not None:
        add("tight", tight)
    if (pig := depig(stripped)) is not None:
        add("depig", pig)

    for encoding, decoded in decoded_candidates(stripped):
        add(encoding, decoded)
        if depth < 1:
            for inner_encoding, inner in decoded_candidates(decoded):
                add(f"{encoding}+{inner_encoding}", inner)

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
    return abs(bits)
