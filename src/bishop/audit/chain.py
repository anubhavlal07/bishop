"""The hash-chained, append-only audit log.

Every agent step, model call, evidence artefact and human decision is written
here, and each entry commits to the one before it. Change any earlier entry and
every hash after it stops matching, so tampering is detectable without trusting
the storage layer.

`CLAUDE.md` §3: **the chain is append-only. Never rewrite, reorder, or backfill
a link. A correction is a new entry that references the old one.** That is why
there is no `update`, no `delete`, and why `correct()` appends rather than
edits. An audit log you can quietly fix is not an audit log — it is a note.

What this does and does not give you. It detects tampering by anyone who cannot
recompute the whole chain, which covers accidental corruption, a partial
overwrite, and an attacker who edits one row in the database. It does *not*
defend against someone who can rewrite the entire file and recompute every hash
forward; that needs the head published somewhere Bishop does not control —
`docs/ARCHITECTURE.md` says so plainly rather than overselling this.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

#: The `prev_hash` of the first entry. A chain always starts somewhere.
GENESIS_HASH = "0" * 64


class AuditAction(StrEnum):
    """What happened. Kept closed so the log stays greppable."""

    RUN_STARTED = "run_started"
    ALERT_INGESTED = "alert_ingested"
    QUARANTINE_APPLIED = "quarantine_applied"
    INJECTION_DETECTED = "injection_detected"
    INVESTIGATOR_DISPATCHED = "investigator_dispatched"
    DETECTOR_RAN = "detector_ran"
    EVIDENCE_RECORDED = "evidence_recorded"
    MODEL_CALLED = "model_called"
    TECHNIQUE_VALIDATED = "technique_validated"
    TECHNIQUE_REJECTED = "technique_rejected"
    VERDICT_REACHED = "verdict_reached"
    CRITIQUE_APPLIED = "critique_applied"
    RESPONSE_PROPOSED = "response_proposed"
    APPROVAL_REQUESTED = "approval_requested"
    HUMAN_DECIDED = "human_decided"
    ACTION_EXECUTED = "action_executed"
    ACTION_REFUSED = "action_refused"
    RUN_COMPLETED = "run_completed"
    RUN_FAILED = "run_failed"
    CORRECTION = "correction"


class ChainBroken(RuntimeError):
    """The chain does not verify. Something was rewritten."""


def canonical(payload: Any) -> str:
    """Stable JSON. Two equal payloads must hash identically on any machine.

    `sort_keys` because dict order is not semantic, and `default=str` so a
    datetime or an enum in a payload cannot break the chain at write time.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def hash_payload(payload: Any) -> str:
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


class AuditEntry:
    """One immutable link.

    Deliberately not a Pydantic model: nothing may mutate an entry after
    construction, and `__slots__` plus no setters is the bluntest way to say so.
    """

    __slots__ = (
        "action",
        "actor",
        "entry_hash",
        "payload",
        "payload_hash",
        "prev_hash",
        "run_id",
        "seq",
        "timestamp",
    )

    def __init__(
        self,
        *,
        seq: int,
        timestamp: str,
        run_id: str,
        actor: str,
        action: AuditAction | str,
        payload: dict[str, Any],
        prev_hash: str,
    ) -> None:
        self.seq = seq
        self.timestamp = timestamp
        self.run_id = run_id
        self.actor = actor
        self.action = AuditAction(action) if not isinstance(action, AuditAction) else action
        self.payload = payload
        self.payload_hash = hash_payload(payload)
        self.prev_hash = prev_hash
        self.entry_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        # The payload enters via its hash, so the link is verifiable even if the
        # payload itself is later redacted for privacy.
        return hashlib.sha256(
            canonical(
                {
                    "seq": self.seq,
                    "timestamp": self.timestamp,
                    "run_id": self.run_id,
                    "actor": self.actor,
                    "action": str(self.action),
                    "payload_hash": self.payload_hash,
                    "prev_hash": self.prev_hash,
                }
            ).encode("utf-8")
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "actor": self.actor,
            "action": str(self.action),
            "payload": self.payload,
            "payload_hash": self.payload_hash,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        entry = cls(
            seq=int(data["seq"]),
            timestamp=str(data["timestamp"]),
            run_id=str(data["run_id"]),
            actor=str(data["actor"]),
            action=str(data["action"]),
            payload=data.get("payload") or {},
            prev_hash=str(data["prev_hash"]),
        )
        # Preserve what was stored so verification compares rather than assumes.
        stored_hash = str(data.get("entry_hash", ""))
        if stored_hash and stored_hash != entry.entry_hash:
            entry.entry_hash = stored_hash
        stored_payload_hash = str(data.get("payload_hash", ""))
        if stored_payload_hash and stored_payload_hash != entry.payload_hash:
            entry.payload_hash = stored_payload_hash
        return entry

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"AuditEntry(seq={self.seq}, action={self.action}, hash={self.entry_hash[:12]}…)"


class AuditChain:
    """An append-only chain, optionally persisted as JSON Lines.

    JSON Lines rather than a table because appending a line is the one file
    operation that is hard to get wrong, and a chain whose storage layer can
    reorder rows has already lost.
    """

    def __init__(
        self,
        *,
        run_id: str,
        path: Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.run_id = run_id
        self.path = path
        #: Injectable so tests and the offline demo produce identical bytes.
        self._clock = clock or (lambda: datetime.now(UTC))
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                self._entries = list(_read_jsonl(path))

    # ── writing ─────────────────────────────────────────────────────────────

    def append(
        self, actor: str, action: AuditAction | str, payload: dict[str, Any] | None = None
    ) -> AuditEntry:
        """Add a link. The only way to write to the chain."""
        with self._lock:
            entry = AuditEntry(
                seq=len(self._entries),
                timestamp=self._clock().isoformat(),
                run_id=self.run_id,
                actor=actor,
                action=action,
                payload=payload or {},
                prev_hash=self._entries[-1].entry_hash if self._entries else GENESIS_HASH,
            )
            self._entries.append(entry)
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry.to_dict(), sort_keys=True, default=str) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            return entry

    def correct(self, actor: str, corrects_seq: int, reason: str, **detail: Any) -> AuditEntry:
        """Record that an earlier entry was wrong, without touching it.

        The only sanctioned way to change what the log says. The original stays
        exactly where it is; readers reconcile by following `corrects_seq`.
        """
        if not 0 <= corrects_seq < len(self._entries):
            raise IndexError(f"cannot correct seq {corrects_seq}: no such entry")
        original = self._entries[corrects_seq]
        return self.append(
            actor,
            AuditAction.CORRECTION,
            {
                "corrects_seq": corrects_seq,
                "corrects_entry_hash": original.entry_hash,
                "corrects_action": str(original.action),
                "reason": reason,
                **detail,
            },
        )

    # ── reading ─────────────────────────────────────────────────────────────

    @property
    def head(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[AuditEntry]:
        return iter(list(self._entries))

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def by_action(self, action: AuditAction | str) -> list[AuditEntry]:
        wanted = AuditAction(action) if not isinstance(action, AuditAction) else action
        return [e for e in self._entries if e.action is wanted]

    # ── verification ────────────────────────────────────────────────────────

    def verify(self) -> None:
        """Recompute the chain. Raises `ChainBroken` at the first bad link."""
        verify_entries(self._entries)

    def is_intact(self) -> bool:
        try:
            self.verify()
        except ChainBroken:
            return False
        return True


def verify_entries(entries: list[AuditEntry]) -> None:
    """Verify a sequence of entries links correctly, from genesis."""
    previous = GENESIS_HASH
    for index, entry in enumerate(entries):
        if entry.seq != index:
            raise ChainBroken(
                f"entry at position {index} claims seq {entry.seq}: reordered or dropped"
            )
        if entry.prev_hash != previous:
            raise ChainBroken(
                f"entry {entry.seq} points at {entry.prev_hash[:12]}… but the previous entry "
                f"hashes to {previous[:12]}…: an entry was rewritten or removed"
            )
        if entry.payload_hash != hash_payload(entry.payload):
            raise ChainBroken(f"entry {entry.seq}: payload does not match its recorded hash")
        if entry.entry_hash != entry._compute_hash():
            raise ChainBroken(f"entry {entry.seq}: entry hash does not match its own contents")
        previous = entry.entry_hash


def _read_jsonl(path: Path) -> Iterator[AuditEntry]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield AuditEntry.from_dict(json.loads(line))


def load_chain(path: Path, *, run_id: str = "") -> AuditChain:
    """Load a persisted chain for verification. Does not append."""
    chain = AuditChain(run_id=run_id, path=None)
    chain._entries = list(_read_jsonl(path))
    if chain._entries and not run_id:
        chain.run_id = chain._entries[0].run_id
    return chain
