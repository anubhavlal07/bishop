#!/usr/bin/env python3
"""Compress the Public Suffix List into the file Bishop ships.

**Why Bishop needs one at all.** An egress block names a domain, and blocking a
domain blocks everything beneath it. Deciding whether a name is a registrable
domain (`evil.com.pl`, safe to block) or a registry (`com.pl`, an outage) is not
something that can be worked out from the string — it is a fact about the world,
and this is the file that records it.

Two hand-written attempts at that fact both shipped and both were wrong. A
label-boundary suffix rule permitted `com`. Reusing the tunnelling detector's
`_registrable_parts`, whose two-part-TLD table has seven entries, permitted
`co.za` and `ac.uk`. A 127-entry hand-written list then permitted `com.pl`,
`sch.uk`, `github.io` and `herokuapp.com`. Each fix narrowed the hole and none
of them closed it, because the shape of the mistake was guessing at a registry
boundary rather than looking it up.

**Both sections are kept.** ICANN gives the registry boundaries; PRIVATE gives
the shared parents — `github.io`, `herokuapp.com`, `pages.dev` — where blocking
the parent takes out every tenant. For this purpose those are the same hazard,
so they are treated the same way.

**Wildcards and exceptions.** `*.ck` means every child of `ck` is itself a
suffix; `!www.ck` carves one back out. Both are kept and applied at lookup, so
`a.b.ck` resolves the way the list says rather than the way a simplification
would.

Licence: the PSL is MPL 2.0. The generated file carries that notice and the
source URL, and this script regenerates it — the list is committed rather than
fetched at start-up because `CLAUDE.md` makes offline the default and a control
that needs the network fails closed on a plane and open in a hurry.

Usage:
    uv run python scripts/build_public_suffixes.py [path-to-public_suffix_list.dat]

With no argument it downloads from publicsuffix.org.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

SOURCE = "https://publicsuffix.org/list/public_suffix_list.dat"
REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "src" / "bishop" / "graph" / "public_suffixes.json"


def read_source(argv: list[str]) -> str:
    if argv:
        return Path(argv[0]).read_text(encoding="utf-8")
    print(f"fetching {SOURCE}")
    with urllib.request.urlopen(SOURCE, timeout=60) as response:
        return response.read().decode("utf-8")


def to_ascii(name: str) -> str:
    """The A-label form of a rule, which is what a resolver log records.

    The first version of this script skipped every line containing a non-ASCII
    character, on the stated belief that the list carries punycode alongside
    Unicode. **It does not** — IDN suffixes appear in Unicode form only. That
    dropped 459 rules, 260 of them second-level registries under an ASCII TLD,
    and each one then derived as a blockable "registrable domain": `公司.cn`
    went missing, so `deadbeef.xn--55qx5d.cn` parented to `xn--55qx5d.cn` and
    the whole Chinese commercial namespace could be cut off.

    Encoding rather than skipping is the fix. Anything that will not encode
    fails the build, because a rule silently absent from this file is a
    registry silently available to block.
    """
    encoded = []
    for label in name.split("."):
        if label.isascii():
            encoded.append(label.lower())
            continue
        ascii_label = label.encode("idna").decode("ascii")
        # `str.encode("idna")` is IDNA2003, and where it disagrees with IDNA2008
        # it disagrees *silently*: `straße` becomes `strasse`, a final sigma
        # folds, a zero-width joiner vanishes. A rule encoded to the wrong
        # A-label is as absent as one that was skipped, and absent is what let
        # 260 registries become blockable. The round trip catches every one of
        # those cases, and anything it catches fails the build.
        if ascii_label.encode("ascii").decode("idna") != label.lower():
            raise UnicodeError(f"{label!r} does not round-trip through IDNA")
        encoded.append(ascii_label.lower())
    return ".".join(encoded)


def parse(text: str) -> dict[str, list[str]]:
    rules: set[str] = set()
    wildcards: set[str] = set()
    exceptions: set[str] = set()

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        # "Each line is only read up to the first whitespace" — the PSL's own
        # line format. Taking the whole line works only while no upstream rule
        # has a trailing comment, and the day one does, `com.pl // ICANN` is
        # stored as a rule that matches nothing, `com.pl` goes missing, and the
        # parent of `a1b2.evil.com.pl` derives as `com.pl` again. Dormant is not
        # the same as handled.
        line = line.split()[0]

        target, body = rules, line
        if line.startswith("!"):
            target, body = exceptions, line[1:]
        elif line.startswith("*."):
            target, body = wildcards, line[2:]

        try:
            target.add(to_ascii(body))
        except UnicodeError as exc:
            raise SystemExit(f"line {number}: cannot encode {body!r} as ASCII — {exc}") from exc

    return {
        "rules": sorted(rules),
        "wildcards": sorted(wildcards),
        "exceptions": sorted(exceptions),
    }


#: Special-use names the PSL does not carry, because they are not delegated to
#: anyone. They behave as registry boundaries for this purpose all the same: an
#: `internal` or `example` is somebody's whole namespace, and blocking it is the
#: same outage as blocking `com`. RFC 2606 and RFC 6761.
#:
#: An organisation's own internal TLDs belong in `never_block` in the
#: environment policy rather than here — this file is regenerated from an
#: external source and would lose them.
SPECIAL_USE = ("example", "invalid", "local", "localhost", "test", "internal", "home", "corp")


_RULE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


def main(argv: list[str]) -> int:
    parsed = parse(read_source(argv))
    parsed["rules"] = sorted(set(parsed["rules"]) | set(SPECIAL_USE))

    # A third belt, and the cheapest. Every emitted rule has to be a plain
    # lowercase hostname; anything else means the parser mangled a line rather
    # than rejecting it, and a mangled rule is a missing rule.
    for kind, entries in parsed.items():
        for entry in entries:
            if not _RULE.match(entry):
                raise SystemExit(f"{kind}: {entry!r} is not a hostname — the parser mangled a line")
    payload = {
        "_source": SOURCE,
        "_licence": "Mozilla Public License 2.0 — https://mozilla.org/MPL/2.0/",
        "_readme": (
            "Where registries end. Bishop uses this to decide whether an egress "
            "block names a registrable domain or a whole registry. Regenerate "
            "with scripts/build_public_suffixes.py."
        ),
        **parsed,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(
        json.dumps(payload, indent=1, sort_keys=False) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        f"wrote {OUT_PATH} — {len(parsed['rules'])} rules, "
        f"{len(parsed['wildcards'])} wildcards, {len(parsed['exceptions'])} exceptions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
