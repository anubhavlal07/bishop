"""The triage supervisor — decide who investigates.

Deterministic, not a model call. Dispatch is routing, and routing an alert to
the wrong specialist is a failure the model cannot detect afterwards: the
endpoint investigator asked about a login has nothing to say and will honestly
report nothing, which reads identically to "nothing happened".

The rule is deliberately generous. A surface is dispatched when the alert
carries *any* data that surface can read, because an investigator that runs and
finds nothing costs one cheap model call, and one that never ran costs a missed
intrusion. `PLAN.md` calls the multi-agent split load-bearing for exactly this
reason — the four surfaces have genuinely disjoint inputs.
"""

from __future__ import annotations

from typing import Any, Optional

from langchain_core.runnables import RunnableConfig

from bishop.audit import AuditAction
from bishop.graph.runtime import get_runtime
from bishop.graph.state import BishopState
from bishop.schema import Alert, AlertCategory


def _has_identity_data(alert: Alert) -> bool:
    return (
        bool(alert.auth_events) or bool(alert.principal) or alert.category is AlertCategory.IDENTITY
    )


def _has_endpoint_data(alert: Alert) -> bool:
    return any(
        [
            alert.process,
            alert.parent_process,
            alert.grandparent_process,
            alert.child_processes,
            alert.file,
            alert.registry_changes,
            alert.scheduled_tasks,
            alert.service_installs,
            alert.raw.get("TargetImage"),
            alert.category is AlertCategory.ENDPOINT,
        ]
    )


def _has_network_data(alert: Alert) -> bool:
    return (
        bool(alert.connections) or bool(alert.dns_events) or alert.category is AlertCategory.NETWORK
    )


def _has_intel_data(alert: Alert) -> bool:
    """Threat intel needs an indicator to look up — a hash, a domain, an IP."""
    if alert.connections or alert.dns_events:
        return True
    if alert.file and alert.file.sha256:
        return True
    if alert.email and (alert.email.links or alert.email.attachment_names):
        return True
    return any(
        p and p.sha256 for p in (alert.process, alert.parent_process, alert.grandparent_process)
    )


def _always(alert: Alert) -> bool:
    """Context runs on every alert.

    An alert where nobody looked for an innocent explanation is not the same as
    one where somebody looked and found none, and only the second is a finding.
    """
    return True


SURFACE_TESTS = {
    "identity": _has_identity_data,
    "endpoint": _has_endpoint_data,
    "network": _has_network_data,
    "threatintel": _has_intel_data,
    "context": _always,
}


def triage_supervisor(
    state: BishopState, config: Optional[RunnableConfig] = None
) -> dict[str, Any]:
    runtime = get_runtime(config)
    alerts = state.get("alerts") or []
    available = runtime.settings.surfaces

    dispatch: list[str] = []
    reasons: list[str] = []
    for surface in available:
        test = SURFACE_TESTS.get(surface)
        if test is None:
            continue
        if any(test(alert) for alert in alerts):
            dispatch.append(surface)
        else:
            reasons.append(f"{surface} (no data on that surface)")

    if not dispatch:
        dispatch = ["endpoint"]
        reasons.append("fell back to endpoint: no surface matched the alert's contents")

    rationale = f"dispatched {', '.join(dispatch)}"
    if reasons:
        rationale += f"; skipped {', '.join(reasons)}"
    if len(alerts) > 1:
        rationale = f"{len(alerts)} correlated alerts in this incident; " + rationale

    runtime.chain.append(
        "triage_supervisor",
        AuditAction.INVESTIGATOR_DISPATCHED,
        {
            "dispatched": dispatch,
            "skipped": reasons,
            "alert_ids": [a.alert_id for a in alerts],
        },
    )
    runtime.emit("dispatched", surfaces=dispatch, rationale=rationale)

    return {"dispatch": dispatch, "dispatch_rationale": rationale}
