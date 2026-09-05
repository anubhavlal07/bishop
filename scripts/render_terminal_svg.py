#!/usr/bin/env python3
"""Render captured terminal output as an SVG, for the README.

A static SVG rather than a GIF, for one reason: it is generated from real
command output by a script anyone can rerun, so it cannot drift from what
Bishop actually prints. A GIF is a recording of one moment on one machine and
nothing checks it again.

`scripts/record_demo.sh` produces the animated version for anyone who wants it.

Usage:
    uv run python scripts/render_terminal_svg.py <command...> --out docs/demo/x.svg
"""

from __future__ import annotations

import argparse
import html
import os
import re
import subprocess
import sys
from pathlib import Path

FONT = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace"
CHAR_W = 8.05
LINE_H = 19
PAD = 22
TOP = 46

THEME = {
    "bg": "#0b0d10",
    "chrome": "#15181d",
    "edge": "#262b33",
    "text": "#c9d1d9",
    "dim": "#7d8590",
    "red": "#f2555a",
    "green": "#3fb950",
    "yellow": "#e3b341",
    "cyan": "#39c5cf",
    "bold": "#e6edf3",
}

ANSI = re.compile(r"\x1b\[([0-9;]*)m")

CODE_TO_ROLE = {
    "1": "bold",
    "2": "dim",
    "31": "red",
    "32": "green",
    "33": "yellow",
    "36": "cyan",
}


def spans(line: str) -> list[tuple[str, str]]:
    """Split one line into (text, role) runs, honouring simple ANSI colour."""
    out: list[tuple[str, str]] = []
    role = "text"
    position = 0
    for match in ANSI.finditer(line):
        if match.start() > position:
            out.append((line[position : match.start()], role))
        codes = [c for c in match.group(1).split(";") if c]
        if not codes or "0" in codes:
            role = "text"
        else:
            for code in codes:
                if code in CODE_TO_ROLE:
                    role = CODE_TO_ROLE[code]
        position = match.end()
    if position < len(line):
        out.append((line[position:], role))
    return out or [("", "text")]


HIGHLIGHT: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\$ .*"), "green"),
    (re.compile(r"^\s*──.*"), "dim"),
    (re.compile(r"TRUE_POSITIVE|IRREVERSIBLE|MISSED|no detector can examine"), "red"),
    (re.compile(r"FALSE_POSITIVE|detectors can examine this|correct"), "green"),
    (re.compile(r"ESCALATE|HUMAN APPROVAL REQUIRED|defaulted|escalate"), "yellow"),
    (re.compile(r"^\s*ATT&CK|^\s*WHAT BISHOP READ|^\s*decision>"), "cyan"),
    (re.compile(r"^\s{6}\S|\(kept in raw"), "dim"),
]


def colourise(line: str) -> str:
    """Apply the colours the CLI would use, which a subprocess cannot capture.

    The CLI only emits ANSI when stdout is a terminal, so a captured run is
    always plain. This re-applies the same semantics to the same text — nothing
    here changes a word, only how it is painted.
    """
    if ANSI.search(line):
        return line
    for pattern, role in HIGHLIGHT:
        if pattern.search(line):
            code = next(c for c, r in CODE_TO_ROLE.items() if r == role)
            return f"\x1b[{code}m{line}\x1b[0m"
    return line


def render(lines: list[str], title: str) -> str:
    lines = [colourise(line) for line in lines]
    width_chars = max((len(ANSI.sub("", line)) for line in lines), default=80)
    width_chars = max(72, min(width_chars, 104))
    width = int(width_chars * CHAR_W) + PAD * 2
    height = TOP + len(lines) * LINE_H + PAD

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(title)}">',
        f'<rect width="{width}" height="{height}" rx="10" fill="{THEME["bg"]}" '
        f'stroke="{THEME["edge"]}"/>',
        f'<path d="M0 10a10 10 0 0 1 10-10h{width - 20}a10 10 0 0 1 10 10v24H0z" '
        f'fill="{THEME["chrome"]}"/>',
        f'<line x1="0" y1="34" x2="{width}" y2="34" stroke="{THEME["edge"]}"/>',
    ]
    for index, colour in enumerate(("#f2555a", "#e3b341", "#3fb950")):
        parts.append(f'<circle cx="{20 + index * 17}" cy="17" r="5.5" fill="{colour}"/>')
    parts.append(
        f'<text x="{width / 2}" y="21" font-family="{FONT}" font-size="11.5" '
        f'fill="{THEME["dim"]}" text-anchor="middle">{html.escape(title)}</text>'
    )

    parts.append(f'<g font-family="{FONT}" font-size="12.5">')
    for row, line in enumerate(lines):
        y = TOP + row * LINE_H + 12
        x = PAD
        for text, role in spans(line):
            if not text:
                continue
            weight = ' font-weight="600"' if role == "bold" else ""
            opacity = ' opacity="0.62"' if role == "dim" else ""
            parts.append(
                f'<text x="{x:.1f}" y="{y}" fill="{THEME[role]}"{weight}{opacity} '
                f'xml:space="preserve">{html.escape(text)}</text>'
            )
            x += len(text) * CHAR_W
    parts.append("</g></svg>")
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs=argparse.REMAINDER)
    parser.add_argument("--out", required=True)
    parser.add_argument("--title", default="")
    parser.add_argument("--max-lines", type=int, default=46)
    parser.add_argument("--skip", type=int, default=0)
    args = parser.parse_args()

    command = [c for c in args.command if c != "--"]
    if not command:
        print("give a command to run", file=sys.stderr)
        return 1

    environment = dict(os.environ, NO_COLOR="1", COLUMNS="100")
    completed = subprocess.run(
        command, capture_output=True, text=True, env=environment, encoding="utf-8"
    )
    raw = (completed.stdout + completed.stderr).replace("\r\n", "\n").split("\n")
    body = [line.rstrip() for line in raw][args.skip : args.skip + args.max_lines]
    while body and not body[-1].strip():
        body.pop()

    title = args.title or f"$ {' '.join(command[-3:])}"
    prompt = f"$ {' '.join(command)}"
    lines = [prompt, "", *body]

    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render(lines, title), encoding="utf-8", newline="\n")
    print(f"wrote {target} ({len(lines)} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
