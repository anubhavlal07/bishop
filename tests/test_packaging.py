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
import importlib
import json
import re
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


class TestTheCommittedSuffixListIsIntact:
    """184 KB of third-party data on a control path.

    `registrable()` derives a parent from this file and puts it into the set of
    destinations Bishop will offer to block, so a rule missing from it is a
    registry silently available to cut off. Three hand-written subsets each
    looked complete enough; these are the properties that make the real list
    checkable rather than trusted.
    """

    def suffixes(self) -> dict:
        return json.loads(
            (REPO_ROOT / "src" / "bishop" / "graph" / "public_suffixes.json").read_text(
                encoding="utf-8"
            )
        )

    def test_it_is_the_whole_list_and_not_a_subset(self):
        data = self.suffixes()
        assert len(data["rules"]) > 9000
        assert len(data["wildcards"]) > 250
        assert len(data["exceptions"]) >= 8

    def test_the_internationalised_rules_survived_the_parser(self):
        """The PSL writes IDN suffixes in Unicode only. A parser that skipped
        non-ASCII lines dropped 459 rules, 260 of them second-level registries
        that then derived as blockable domains."""
        punycode = [rule for rule in self.suffixes()["rules"] if "xn--" in rule]
        assert len(punycode) > 400
        for expected in ("xn--55qx5d.cn", "xn--io0a7i.cn", "xn--mgba3a4f16a.ir"):
            assert expected in punycode

    def test_every_rule_is_a_plain_hostname(self):
        """A mangled rule is a missing rule. The PSL's line format is 'read up
        to the first whitespace', and a rule stored as `com.pl // ICANN` matches
        nothing while `com.pl` goes missing."""
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        pattern = re.compile(rf"^{label}(?:\.{label})*$")
        data = self.suffixes()
        for kind in ("rules", "wildcards", "exceptions"):
            for entry in data[kind]:
                assert pattern.match(entry), f"{kind}: {entry!r} is not a hostname"

    def test_it_carries_its_source_and_licence(self):
        data = self.suffixes()
        assert "publicsuffix.org" in data["_source"]
        assert "Mozilla Public License" in data["_licence"]


CONSOLE_TYPES = REPO_ROOT / "console" / "lib" / "types.ts"


def declared_fields(interface: str) -> set[str]:
    """The field names one `export interface` declares, ignoring nested shapes.

    Nested object literals are skipped by brace depth, so `verdict: {...}`
    contributes `verdict` and not its members — those belong to a different
    payload and are checked separately where it matters.
    """
    source = CONSOLE_TYPES.read_text(encoding="utf-8")
    match = re.search(rf"export interface {interface} \{{(.*?)\n\}}", source, re.S)
    assert match, f"no `export interface {interface}` in console/lib/types.ts"

    fields: set[str] = set()
    depth = 0
    for line in match.group(1).splitlines():
        stripped = line.strip()
        if depth == 0 and (found := re.match(r"([A-Za-z_][A-Za-z0-9_]*)\??:", stripped)):
            fields.add(found.group(1))
        depth += (
            stripped.count("{") + stripped.count("<") - stripped.count("}") - stripped.count(">")
        )
    return fields


class TestTheConsoleContractMatchesTheApi:
    """TypeScript describes the API; nothing was checking that it was right.

    An API response is cast to these interfaces, not validated against them, so
    a field the console declares and the server never sends reads as `undefined`
    at runtime and `tsc` says nothing. `BlastRadius.timing_context` was declared
    required, never sent, never set and never read — a contract that promised
    Bishop knew whether an action was happening at 03:00 on a Sunday.
    """

    def approval_request(self) -> dict:
        import time

        from fastapi.testclient import TestClient

        app = importlib.import_module("bishop.api.app").app
        client = TestClient(app)
        run = client.post("/runs", json={"alert_id": "TP-01-credential-dumping"}).json()
        for _ in range(200):
            state = client.get(f"/runs/{run['run_id']}").json()
            if state["status"] != "running":
                break
            time.sleep(0.02)
        assert state["approval_request"], "the gate produced no approval request to check"
        return state["approval_request"]

    def test_every_declared_approval_field_is_sent(self):
        request = self.approval_request()
        missing = declared_fields("ApprovalRequest") - set(request)
        assert not missing, f"console declares {sorted(missing)}; the API does not send them"

    def test_every_declared_verdict_field_is_sent(self):
        verdict = self.approval_request()["verdict"]
        expected = {"label", "confidence", "rationale", "counter_arguments", "technique_ids"}
        assert expected <= set(verdict)

    def test_every_declared_blast_radius_field_is_sent(self):
        action = self.approval_request()["actions"][0]
        missing = declared_fields("BlastRadius") - set(action["blast_radius"])
        assert not missing, f"console declares {sorted(missing)}; the API does not send them"

    def test_every_declared_action_field_is_sent(self):
        action = self.approval_request()["actions"][0]
        expected = {
            "action_id",
            "action_type",
            "target",
            "rationale",
            "irreversible",
            "rollback",
            "blast_radius",
        }
        assert expected <= set(action)
