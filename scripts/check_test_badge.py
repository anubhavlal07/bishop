"""Fail if the README's test-count badge disagrees with the suite.

A hand-written number in a badge is a claim like any other, and it rots the
moment someone adds a test file. The badge said 1050 while 1355 passed.

It reads the JUnit XML the test run already produces rather than counting tests
itself, so it costs nothing and cannot disagree with the run it is describing.
Without one it runs the suite, which is the slow path and only for local use.

The badge counts *passing* tests, not collected ones: skips and xfails are not
passes and claiming them would be the same kind of inflation this exists to
stop.

Usage:  uv run pytest --junitxml=.pytest-report.xml
        uv run python scripts/check_test_badge.py .pytest-report.xml
"""

from __future__ import annotations

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BADGE = re.compile(r"!\[tests\]\(https://img\.shields\.io/badge/tests-(\d+)%20passing-")


def passed_from_report(path: Path) -> int:
    """Passes are the cases that are neither skipped, failed nor errored."""
    suite = ET.parse(path).getroot()
    if suite.tag == "testsuites":
        suite = suite.find("testsuite")
    if suite is None:
        raise SystemExit(f"no <testsuite> in {path}")
    total = int(suite.get("tests", 0))
    not_passing = sum(int(suite.get(key, 0)) for key in ("failures", "errors", "skipped"))
    return total - not_passing


def passed_by_running() -> int:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-o", "addopts=", "-q", "--color=no"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    match = re.search(r"(\d+) passed", result.stdout)
    if match is None:
        raise SystemExit(f"could not read a pass count from pytest:\n{result.stdout[-2000:]}")
    return int(match.group(1))


def main(argv: list[str]) -> int:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    match = BADGE.search(readme)
    if match is None:
        print("no test-count badge in README.md")
        return 1

    report = Path(argv[0]) if argv else None
    actual = passed_from_report(report) if report and report.exists() else passed_by_running()
    claimed = int(match.group(1))

    if claimed != actual:
        print(f"README badge claims {claimed} passing tests; the suite passes {actual}.")
        print(f"Update the badge to tests-{actual}%20passing.")
        return 1

    print(f"badge and suite agree: {actual} passing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
