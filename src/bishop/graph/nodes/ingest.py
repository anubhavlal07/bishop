"""Ingest — normalise, quarantine, and raise injection findings.

The first node, and the only one that ever touches raw alert fields. Everything
downstream sees the fenced block this produces, never the alert's own strings.

Injection findings are put into their own state field here rather than being
folded into an investigator's report, because an alert whose only notable
feature is an injected instruction produces no detector hits at all. If the
finding travelled with the investigator reports it would arrive empty and the
most interesting alert in the corpus would come back clean.
"""

from __future__ import annotations

from typing import Any, Optional

from langchain_core.runnables import RunnableConfig

from bishop.audit import AuditAction
from bishop.graph.runtime import get_runtime
from bishop.graph.state import BishopState
from bishop.quarantine import injection_evidence, quarantine_alert, render_block
from bishop.schema import Evidence


def ingest(state: BishopState, config: Optional[RunnableConfig] = None) -> dict[str, Any]:
    runtime = get_runtime(config)
    alerts = state.get("alerts") or []
    run_id = state["run_id"]

    runtime.chain.append(
        "ingest",
        AuditAction.RUN_STARTED,
        {
            "run_id": run_id,
            "incident_id": state.get("incident_id"),
            "alert_ids": [a.alert_id for a in alerts],
            "provider": runtime.provider.name,
            "model": runtime.provider.model_id,
        },
    )

    blocks: list[str] = []
    evidence: list[Evidence] = []
    summary: dict[str, Any] = {
        "fields_quarantined": 0,
        "fields_flagged": 0,
        "max_score": 0.0,
        "techniques": [],
    }

    for alert in alerts:
        report = quarantine_alert(alert, run_id=run_id)
        blocks.append(render_block(report))

        summary["fields_quarantined"] += len(report.fields)
        summary["fields_flagged"] += len(report.injections)
        summary["max_score"] = max(summary["max_score"], report.max_score)
        for field in report.injections:
            for technique in field.risk.techniques:
                if technique not in summary["techniques"]:
                    summary["techniques"].append(technique)

        runtime.chain.append(
            "quarantine",
            AuditAction.QUARANTINE_APPLIED,
            {
                "alert_id": alert.alert_id,
                "fields": [f.path for f in report.fields],
                "flagged": [f.path for f in report.injections],
                "max_score": report.max_score,
            },
        )

        found = injection_evidence(report, alert_id=alert.alert_id)
        evidence.extend(found)
        for item in found:
            runtime.chain.append(
                "quarantine",
                AuditAction.INJECTION_DETECTED,
                {
                    "alert_id": alert.alert_id,
                    "evidence_id": item.evidence_id,
                    "field": item.facts.get("field"),
                    "confidence": item.confidence,
                    "techniques": item.signals[0].facts.get("techniques") if item.signals else [],
                },
            )
            runtime.emit(
                "injection_detected",
                field=item.facts.get("field"),
                confidence=item.confidence,
            )

        runtime.chain.append(
            "ingest",
            AuditAction.ALERT_INGESTED,
            {
                "alert_id": alert.alert_id,
                "source": alert.source,
                "rule_name": alert.rule_name,
                "severity": str(alert.severity),
                "category": str(alert.category),
            },
        )

    runtime.emit(
        "ingested",
        alerts=len(alerts),
        quarantined_fields=summary["fields_quarantined"],
        flagged=summary["fields_flagged"],
    )

    return {
        "quarantine_block": "\n\n".join(blocks),
        "quarantine_evidence": evidence,
        "quarantine_summary": summary,
        "audit_head": runtime.chain.head,
    }
