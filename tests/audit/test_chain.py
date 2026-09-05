"""Audit chain tests.

The chain's whole value is that tampering is detectable. These tests tamper —
in every way a chain can be tampered with — and assert it is caught. A test
suite that only ever appends is testing the happy path of a security control,
which is the one path that does not matter.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest

from bishop.audit import (
    GENESIS_HASH,
    AuditAction,
    AuditChain,
    ChainBroken,
    hash_payload,
    load_chain,
)

START = datetime(2026, 3, 1, 9, 0, 0, tzinfo=UTC)


def fixed_clock():
    """A deterministic clock. Two runs of a test must produce identical hashes."""
    state = {"n": 0}

    def tick() -> datetime:
        state["n"] += 1
        return START + timedelta(seconds=state["n"])

    return tick


@pytest.fixture
def chain() -> AuditChain:
    return AuditChain(run_id="run-1", clock=fixed_clock())


def populate(chain: AuditChain) -> None:
    chain.append("ingest", AuditAction.ALERT_INGESTED, {"alert_id": "A-1"})
    chain.append("quarantine", AuditAction.QUARANTINE_APPLIED, {"fields": 3})
    chain.append("synthesis", AuditAction.VERDICT_REACHED, {"label": "true_positive"})


class TestAppend:
    def test_first_entry_points_at_genesis(self, chain):
        entry = chain.append("ingest", AuditAction.ALERT_INGESTED, {"alert_id": "A-1"})
        assert entry.seq == 0
        assert entry.prev_hash == GENESIS_HASH

    def test_each_entry_points_at_the_one_before(self, chain):
        populate(chain)
        entries = chain.entries()
        for earlier, later in pairwise(entries):
            assert later.prev_hash == earlier.entry_hash

    def test_head_tracks_the_last_entry(self, chain):
        assert chain.head == GENESIS_HASH
        populate(chain)
        assert chain.head == chain.entries()[-1].entry_hash

    def test_a_populated_chain_verifies(self, chain):
        populate(chain)
        chain.verify()
        assert chain.is_intact()

    def test_hashing_is_reproducible_across_runs(self):
        first = AuditChain(run_id="run-1", clock=fixed_clock())
        second = AuditChain(run_id="run-1", clock=fixed_clock())
        populate(first)
        populate(second)
        assert first.head == second.head

    def test_payload_key_order_does_not_change_the_hash(self, chain):
        assert hash_payload({"a": 1, "b": 2}) == hash_payload({"b": 2, "a": 1})

    def test_entries_are_queryable_by_action(self, chain):
        populate(chain)
        assert len(chain.by_action(AuditAction.VERDICT_REACHED)) == 1


class TestTamperDetection:
    def test_editing_a_payload_breaks_the_chain(self, chain):
        populate(chain)
        chain.entries()[1].payload["fields"] = 99
        # The mutation has to be applied to the live list, not a copy.
        chain._entries[1].payload["fields"] = 99
        with pytest.raises(ChainBroken, match="payload does not match"):
            chain.verify()

    def test_removing_an_entry_breaks_the_chain(self, chain):
        populate(chain)
        del chain._entries[1]
        with pytest.raises(ChainBroken):
            chain.verify()

    def test_reordering_entries_breaks_the_chain(self, chain):
        populate(chain)
        chain._entries[1], chain._entries[2] = chain._entries[2], chain._entries[1]
        with pytest.raises(ChainBroken):
            chain.verify()

    def test_rewriting_an_entry_hash_breaks_the_chain(self, chain):
        populate(chain)
        chain._entries[1].entry_hash = "f" * 64
        with pytest.raises(ChainBroken):
            chain.verify()

    def test_appending_a_forged_entry_breaks_the_chain(self, chain):
        populate(chain)
        forged = chain._entries[-1]
        forged.prev_hash = "0" * 64
        with pytest.raises(ChainBroken, match="rewritten or removed"):
            chain.verify()


class TestCorrections:
    def test_a_correction_appends_rather_than_edits(self, chain):
        populate(chain)
        original = chain.entries()[2]
        correction = chain.correct("analyst", 2, reason="verdict was wrong on review")

        assert len(chain) == 4
        assert correction.action is AuditAction.CORRECTION
        # The original is untouched, byte for byte.
        assert chain.entries()[2].entry_hash == original.entry_hash
        assert chain.entries()[2].payload == {"label": "true_positive"}
        chain.verify()

    def test_a_correction_references_what_it_corrects(self, chain):
        populate(chain)
        correction = chain.correct("analyst", 0, reason="wrong alert id", corrected_to="A-2")
        assert correction.payload["corrects_seq"] == 0
        assert correction.payload["corrects_entry_hash"] == chain.entries()[0].entry_hash
        assert correction.payload["reason"] == "wrong alert id"
        assert correction.payload["corrected_to"] == "A-2"

    def test_correcting_a_nonexistent_entry_raises(self, chain):
        populate(chain)
        with pytest.raises(IndexError):
            chain.correct("analyst", 99, reason="no such entry")

    def test_the_chain_offers_no_way_to_mutate_or_delete(self):
        # If either of these ever appears, the append-only guarantee is gone.
        assert not hasattr(AuditChain, "update")
        assert not hasattr(AuditChain, "delete")
        assert not hasattr(AuditChain, "remove")


class TestPersistence:
    def test_a_chain_round_trips_through_disk(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        chain = AuditChain(run_id="run-1", path=path, clock=fixed_clock())
        populate(chain)

        reloaded = load_chain(path)
        assert len(reloaded) == 3
        assert reloaded.head == chain.head
        assert reloaded.run_id == "run-1"
        reloaded.verify()

    def test_tampering_with_the_file_is_caught_on_reload(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        chain = AuditChain(run_id="run-1", path=path, clock=fixed_clock())
        populate(chain)

        # Edit the stored row the way someone with database access would: parse
        # it, change the payload, write it back as valid JSON. A string replace
        # is not a realistic tamper and can silently fail to match.
        lines = path.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[1])
        assert row["payload"]["fields"] == 3
        row["payload"]["fields"] = 99
        lines[1] = json.dumps(row, sort_keys=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(ChainBroken, match="payload does not match"):
            load_chain(path).verify()

    def test_a_tamperer_who_recomputes_the_payload_hash_is_still_caught(self, tmp_path):
        """The next thing an attacker tries: fix the payload hash too.

        That still fails, because the entry hash commits to the payload hash and
        the following entry commits to the entry hash. To get away with it they
        would have to rewrite every subsequent link — which is exactly the limit
        `chain.py` documents rather than pretends away.
        """
        path = tmp_path / "audit.jsonl"
        chain = AuditChain(run_id="run-1", path=path, clock=fixed_clock())
        populate(chain)

        lines = path.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[1])
        row["payload"]["fields"] = 99
        row["payload_hash"] = hash_payload(row["payload"])
        lines[1] = json.dumps(row, sort_keys=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(ChainBroken, match="entry hash does not match"):
            load_chain(path).verify()

    def test_reopening_a_chain_continues_it(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        first = AuditChain(run_id="run-1", path=path, clock=fixed_clock())
        populate(first)
        head_before = first.head

        second = AuditChain(run_id="run-1", path=path, clock=fixed_clock())
        entry = second.append("report", AuditAction.RUN_COMPLETED, {"ok": True})
        assert entry.seq == 3
        assert entry.prev_hash == head_before
        second.verify()


class TestTruncation:
    """A chain verified from genesis says nothing about its own end.

    Deleting the last entries is the cheapest possible tamper — it removes the
    record of what was executed and requires recomputing nothing, because a
    truncated chain is a shorter valid chain.
    """

    def test_truncating_the_tail_passes_a_naive_verify(self, chain):
        populate(chain)
        del chain._entries[2:]
        chain.verify()  # no exception: this is the gap, stated as a fact

    def test_a_retained_head_catches_truncation(self, chain):
        populate(chain)
        head = chain.head
        del chain._entries[2:]
        with pytest.raises(ChainBroken, match="truncated"):
            chain.verify(expected_head=head)

    def test_a_retained_length_catches_truncation(self, chain):
        populate(chain)
        del chain._entries[2:]
        with pytest.raises(ChainBroken, match="removed from the end"):
            chain.verify(expected_length=3)

    def test_is_intact_takes_the_expected_head(self, chain):
        populate(chain)
        head = chain.head
        assert chain.is_intact(expected_head=head)
        del chain._entries[2:]
        assert not chain.is_intact(expected_head=head)

    def test_an_intact_chain_still_verifies_against_its_own_head(self, chain):
        populate(chain)
        chain.verify(expected_head=chain.head, expected_length=len(chain))
