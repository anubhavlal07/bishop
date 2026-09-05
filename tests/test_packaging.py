"""The container has to carry the files the running code reads.

Written after `/scorecard` returned 404 in production for as long as the API had
been deployed. The endpoint reports the committed baseline rather than running
the corpus on a web request, and the Dockerfile never copied `eval/results/`, so
the console's scorecard page was blank for every live visitor. Nothing caught it
because every test runs from a checkout, where the file is always there.

So these tests read the Dockerfile. That is unusual for a unit test and it is
the only place the defect exists: the code was correct, the image was wrong.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "Dockerfile"


def repo_root_paths() -> set[str]:
    """Every `parents[3] / ...` path the source reads, as a repo-relative path.

    `src/bishop/<pkg>/<module>.py` has the repo root at `parents[3]`, and that
    is how the corpus, the policy file and the scorecard are found at runtime.
    Each one is a file the image has to contain.
    """
    found: set[str] = set()
    for path in (REPO_ROOT / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
                continue
            segments: list[str] = []
            current: ast.expr = node
            while isinstance(current, ast.BinOp) and isinstance(current.op, ast.Div):
                if not isinstance(current.right, ast.Constant):
                    break
                segments.insert(0, str(current.right.value))
                current = current.left
            if not segments or "parents" not in ast.dump(current):
                continue
            if "[3]" not in ast.unparse(current):
                continue
            found.add("/".join(segments))
    # `ast.walk` visits the inner nodes of `root / "a" / "b"` as well as the
    # whole expression, so `a` arrives alongside `a/b`. Only the complete path
    # is a real read.
    return {
        path for path in found if not any(o != path and o.startswith(path + "/") for o in found)
    }


class TestTheImageCarriesWhatTheCodeReads:
    def test_the_source_reads_only_paths_this_test_knows_about(self):
        """A new repo-root path is a new thing to copy. Fail loudly rather than
        let it reach production and 404 there."""
        assert repo_root_paths() == {
            "fixtures/environment/policy.json",
            "fixtures/alerts",
            "fixtures/holdout",
            "eval/results",
        }

    @pytest.mark.parametrize(
        "needle",
        ["fixtures", "eval/results/baseline.json"],
        ids=["fixtures", "scorecard-baseline"],
    )
    def test_the_dockerfile_copies_it(self, needle):
        copies = [
            line
            for line in DOCKERFILE.read_text(encoding="utf-8").splitlines()
            if line.startswith("COPY") and needle in line
        ]
        assert copies, f"the Dockerfile never copies {needle}; it will be missing at runtime"

    def test_the_build_context_is_not_the_whole_repo(self):
        """Without a .dockerignore the context carries `.venv`, `node_modules`
        and all of `.git` — hundreds of megabytes pushed to change one file."""
        ignore = REPO_ROOT / ".dockerignore"
        assert ignore.exists()
        entries = {
            line.strip()
            for line in ignore.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
        assert {".git", ".venv", "console"} <= entries


class TestThePublishedNumberMatchesTheCorpus:
    def test_the_baseline_covers_every_labelled_alert(self):
        """`/scorecard` serves this file, and the README quotes it. A fixture
        added without re-running `just eval --save` leaves the served number
        describing a corpus that no longer exists."""
        baseline = json.loads(
            (REPO_ROOT / "eval" / "results" / "baseline.json").read_text(encoding="utf-8")
        )
        on_disk = len(list((REPO_ROOT / "fixtures" / "alerts").glob("*.json")))
        assert baseline["corpus_size"] == on_disk, (
            f"the committed baseline scores {baseline['corpus_size']} alerts but the "
            f"corpus holds {on_disk}. Re-run `just eval --save` and copy the result "
            f"over eval/results/baseline.json."
        )

    def test_the_readme_quotes_the_committed_number(self):
        baseline = json.loads(
            (REPO_ROOT / "eval" / "results" / "baseline.json").read_text(encoding="utf-8")
        )
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        assert f"| Alerts | {baseline['corpus_size']} |" in readme
