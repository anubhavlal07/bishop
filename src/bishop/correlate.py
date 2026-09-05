"""Grouping alerts into incidents.

Bishop triaged one alert at a time, which is the part of the job a tier-1
analyst does and not the part a tier-2 analyst is paid for. The interesting
reasoning is across alerts: a failed login here, a service install there, and an
outbound connection an hour later are three low-severity alerts and one
intrusion.

**An incident is a connected component.** Two alerts belong together if they
share a host or an account and fall inside the same time window; belonging is
transitive, so an attacker moving from `alice@WKSTN-1` to `alice@SRV-2` to
`svc_backup@SRV-2` links all three, even though the first and last share
nothing directly. That transitivity is the whole value — it is what follows a
lateral movement chain — and it is also the risk, so the window bounds it.

**Why not cluster on more than this.** Correlating on cleverer similarity
merges unrelated activity, and a wrongly merged incident is worse than two
separate ones: it buries a real finding inside a larger story that explains it
away, and an analyst who spots one wrong join stops trusting every join. Shared
identity within a window is the join an analyst would make by hand, and it is
the one they can check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from bishop.schema import Alert

#: Alerts further apart than this are not correlated even if they share a host.
#: An hour is a compromise: long enough to span a hands-on-keyboard sequence,
#: short enough that a laptop generating one alert a day does not accumulate a
#: month-long "incident".
DEFAULT_WINDOW = timedelta(hours=1)


def _entities(alert: Alert) -> set[str]:
    """The identities an alert touches, namespaced so a host cannot collide
    with a username that happens to match it."""
    found: set[str] = set()
    if alert.device and alert.device.hostname:
        found.add(f"host:{str(alert.device.hostname).strip().lower()}")
    if alert.principal and alert.principal.username:
        found.add(f"user:{str(alert.principal.username).strip().lower()}")
    for event in alert.auth_events:
        if event.username:
            found.add(f"user:{str(event.username).strip().lower()}")
    return found


@dataclass
class Incident:
    """A correlated group, with the reason it was grouped."""

    alerts: list[Alert] = field(default_factory=list)
    entities: set[str] = field(default_factory=set)

    @property
    def key(self) -> str:
        return "+".join(sorted(self.entities)) or "unknown"

    @property
    def span_seconds(self) -> float:
        if len(self.alerts) < 2:
            return 0.0
        times = sorted(a.detected_at for a in self.alerts)
        return (times[-1] - times[0]).total_seconds()

    def rationale(self) -> str:
        if len(self.alerts) == 1:
            return "single alert; nothing else in the window shares a host or an account"
        shared = ", ".join(sorted(self.entities)[:4])
        return (
            f"{len(self.alerts)} alerts correlated over {self.span_seconds / 60:.0f} minutes, "
            f"linked by {shared}"
        )


def correlate(alerts: list[Alert], *, window: timedelta = DEFAULT_WINDOW) -> list[Incident]:
    """Group alerts into incidents by shared entity within a time window.

    Union-find over entities, restricted to pairs inside the window. Alerts are
    processed in time order and each is compared only against those still inside
    the window behind it, so this is linear in practice rather than quadratic
    over the whole corpus.
    """
    ordered = sorted(alerts, key=lambda a: a.detected_at)
    parent: dict[int, int] = {i: i for i in range(len(ordered))}

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    entities = [_entities(alert) for alert in ordered]

    for index in range(len(ordered)):
        for earlier in range(index - 1, -1, -1):
            if ordered[index].detected_at - ordered[earlier].detected_at > window:
                break  # everything before this is further away still
            if entities[index] & entities[earlier]:
                union(earlier, index)

    grouped: dict[int, Incident] = {}
    for index, alert in enumerate(ordered):
        root = find(index)
        incident = grouped.setdefault(root, Incident())
        incident.alerts.append(alert)
        incident.entities |= entities[index]

    return [grouped[root] for root in sorted(grouped)]


def incident_for(alert_id: str, alerts: list[Alert], *, window: timedelta = DEFAULT_WINDOW):
    """The incident containing one alert, correlated against the rest."""
    for incident in correlate(alerts, window=window):
        if any(a.alert_id == alert_id for a in incident.alerts):
            return incident
    return None
