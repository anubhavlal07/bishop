"""The untrusted-input boundary.

`CLAUDE.md` §3: every attacker-influenced field passes through here before it
reaches a prompt, and an injection attempt is escalated as an IOC rather than
stripped. `docs/THREAT-MODEL.md` argues for the shape of it.
"""

from bishop.quarantine.core import (
    INJECTION_THRESHOLD,
    MAX_RENDERED_CHARS,
    QuarantinedField,
    QuarantineReport,
    UntrustedLeakError,
    assert_no_untrusted,
    contains_untrusted,
    fence_nonce,
    injection_evidence,
    quarantine,
    quarantine_alert,
    render_block,
)
from bishop.quarantine.signals import (
    FieldRisk,
    InjectionSignal,
    InjectionTechnique,
    scan_text,
)

__all__ = [
    "INJECTION_THRESHOLD",
    "MAX_RENDERED_CHARS",
    "FieldRisk",
    "InjectionSignal",
    "InjectionTechnique",
    "QuarantineReport",
    "QuarantinedField",
    "UntrustedLeakError",
    "assert_no_untrusted",
    "contains_untrusted",
    "fence_nonce",
    "injection_evidence",
    "quarantine",
    "quarantine_alert",
    "render_block",
    "scan_text",
]
