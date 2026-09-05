"""Endpoint detectors — the process tree, what ran, and what it left behind.

The recurring shape here is *context beats identity*. `rundll32.exe` is not
suspicious; `rundll32.exe` with `comsvcs.dll MiniDump` against the LSASS process
id is. `powershell.exe` is not suspicious; `powershell.exe` started by
`winword.exe` is. Every detector below scores the combination, and the facts it
returns are the combination, so an analyst can see the reasoning rather than a
verdict.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from bishop.detectors.base import clear, miss, register
from bishop.detectors.catalogues import (
    ABUSED_HOSTING,
    ARCHIVE_TOOLS,
    CREDENTIAL_TOOLS,
    EXPECTED_PARENTS,
    LOLBIN_ARGUMENT_TELLS,
    LOLBINS,
    NEVER_SPAWNS_SHELL,
    PERSISTENCE_REGISTRY_KEYS,
    SHELLS,
    STAGING_DIRECTORIES,
    SYSTEM_BINARY_HOMES,
)
from bishop.quarantine.text import decoded_candidates, invisible_characters
from bishop.schema.alert import Alert, Process
from bishop.schema.evidence import DetectorResult


def _basename(value: str | None) -> str:
    """Last path component, lowercased. Handles both separators."""
    if not value:
        return ""
    return str(value).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].strip().lower()


def _name_of(process: Process | None) -> str:
    if process is None:
        return ""
    return _basename(process.name) or _basename(process.path)


def _cmd_of(process: Process | None) -> str:
    if process is None or not process.command_line:
        return ""
    return str(process.command_line)


def _all_processes(alert: Alert) -> Iterator[tuple[str, Process]]:
    if alert.grandparent_process:
        yield "grandparent_process", alert.grandparent_process
    if alert.parent_process:
        yield "parent_process", alert.parent_process
    if alert.process:
        yield "process", alert.process
    for index, child in enumerate(alert.child_processes):
        yield f"child_processes[{index}]", child


@register(
    surface="endpoint",
    summary=(
        "A signed Microsoft binary used as an execution proxy, scored on the "
        "arguments rather than on the binary's name alone."
    ),
    techniques=["T1218", "T1059"],
    references=["https://lolbas-project.github.io/", "https://attack.mitre.org/techniques/T1218/"],
)
def lolbin_abuse(alert: Alert) -> DetectorResult:
    """Living-off-the-land binaries invoked in the ways that matter.

    The binary being a LOLBin is worth very little on its own — `rundll32.exe`
    runs constantly on a healthy Windows host. The detector scores low for mere
    presence and high for the argument patterns that have no benign reading.
    """
    examined = 0
    findings: list[dict[str, object]] = []

    for where, process in _all_processes(alert):
        name = _name_of(process)
        if name not in LOLBINS:
            continue
        examined += 1
        command = _cmd_of(process).lower()
        tells = [
            {"argument": pattern, "meaning": meaning}
            for pattern, meaning in LOLBIN_ARGUMENT_TELLS.get(name, ())
            if pattern in command
        ]
        findings.append(
            {
                "where": where,
                "binary": name,
                "capability": LOLBINS[name],
                "tells": tells,
                "command_line": _cmd_of(process)[:400],
            }
        )

    if not examined:
        processes = sum(1 for _ in _all_processes(alert))
        if not processes:
            return miss("lolbin_abuse", "the alert carries no process tree to examine")
        return clear(
            "lolbin_abuse",
            "no living-off-the-land binaries in the process tree",
            processes_examined=processes,
        )

    with_tells = [f for f in findings if f["tells"]]
    facts = {"findings": findings, "lolbins_seen": examined, "with_argument_tells": len(with_tells)}

    if not with_tells:
        names = ", ".join(sorted({str(f["binary"]) for f in findings}))
        return DetectorResult(
            detector="lolbin_abuse",
            fired=True,
            score=0.25,
            facts=facts,
            rationale=(
                f"{names} present in the process tree with no suspicious arguments — "
                f"capable of proxying execution, but nothing here says it did"
            ),
            technique_hints=["T1218"],
        )

    top = max(with_tells, key=lambda f: len(f["tells"]))  # type: ignore[arg-type]
    tell_count = sum(len(f["tells"]) for f in with_tells)  # type: ignore[arg-type]
    meanings = "; ".join(str(t["meaning"]) for t in top["tells"][:2])  # type: ignore[index]

    hints = ["T1218"]
    if top["binary"] == "regsvr32.exe":
        hints.append("T1218.010")
    elif top["binary"] == "rundll32.exe":
        hints.append("T1218.011")
    elif top["binary"] == "mshta.exe":
        hints.append("T1218.005")
    elif top["binary"] == "msiexec.exe":
        hints.append("T1218.007")
    elif top["binary"] == "msbuild.exe":
        hints.append("T1127.001")
    elif top["binary"] == "wmic.exe":
        hints.append("T1047")

    return DetectorResult(
        detector="lolbin_abuse",
        fired=True,
        score=round(min(0.9, 0.55 + 0.12 * tell_count), 3),
        facts=facts,
        rationale=f"{top['binary']} invoked in a way that has no routine explanation: {meanings}",
        technique_hints=hints,
    )


@register(
    surface="endpoint",
    summary=(
        "A parent process starting a child it has no business starting — an Office "
        "document spawning a shell, or a system binary with an unexpected parent."
    ),
    techniques=["T1059", "T1566.001"],
    references=["https://attack.mitre.org/techniques/T1059/"],
)
def suspicious_parent_child(alert: Alert) -> DetectorResult:
    """Process lineage that does not occur in normal operation.

    Two rules, in decreasing confidence. A document reader spawning a shell is
    close to unambiguous. A system binary with an unusual parent is worth
    flagging but has benign explanations — management agents do odd things.
    """
    pairs: list[tuple[str, Process | None, Process | None]] = [
        ("process/parent", alert.parent_process, alert.process),
        ("parent/grandparent", alert.grandparent_process, alert.parent_process),
    ]
    for index, child in enumerate(alert.child_processes):
        pairs.append((f"child_processes[{index}]/process", alert.process, child))

    findings: list[dict[str, object]] = []
    for where, parent, child in pairs:
        parent_name, child_name = _name_of(parent), _name_of(child)
        if not parent_name or not child_name:
            continue

        if parent_name in NEVER_SPAWNS_SHELL and child_name in SHELLS:
            findings.append(
                {
                    "where": where,
                    "parent": parent_name,
                    "child": child_name,
                    "kind": "document_reader_spawned_shell",
                    "weight": 0.8,
                    "note": (
                        f"{NEVER_SPAWNS_SHELL[parent_name]} started {child_name}; document "
                        f"readers do not launch interpreters in normal use"
                    ),
                }
            )
            continue

        expected = EXPECTED_PARENTS.get(child_name)
        if expected is not None and parent_name not in expected:
            findings.append(
                {
                    "where": where,
                    "parent": parent_name,
                    "child": child_name,
                    "kind": "unexpected_parent",
                    "weight": 0.45,
                    "note": (
                        f"{child_name} was started by {parent_name}, which is outside its "
                        f"usual parents ({', '.join(sorted(expected)[:4])}…)"
                    ),
                }
            )

    if not pairs or all(not _name_of(p) or not _name_of(c) for _, p, c in pairs):
        return miss("suspicious_parent_child", "the alert carries no parent/child process pair")

    if not findings:
        return clear(
            "suspicious_parent_child",
            "every parent/child pair in the tree is an ordinary one",
            pairs_examined=len(pairs),
        )

    strongest = max(findings, key=lambda f: float(f["weight"]))  # type: ignore[arg-type]
    hints = ["T1059"]
    if strongest["kind"] == "document_reader_spawned_shell":
        hints.append("T1566.001")
    if strongest["child"] in {"powershell.exe", "pwsh.exe"}:
        hints.append("T1059.001")
    elif strongest["child"] == "cmd.exe":
        hints.append("T1059.003")
    elif strongest["child"] in {"wscript.exe", "cscript.exe"}:
        hints.append("T1059.005")

    return DetectorResult(
        detector="suspicious_parent_child",
        fired=True,
        score=float(strongest["weight"]),  # type: ignore[arg-type]
        facts={"findings": findings, "pairs_examined": len(pairs)},
        rationale=str(strongest["note"]),
        technique_hints=hints,
    )


_LSASS_DUMP_PATTERNS: tuple[tuple[str, str], ...] = (
    ("comsvcs.dll", "calling the MiniDump export in comsvcs.dll"),
    ("minidump", "requesting a process minidump"),
    ("-ma lsass", "ProcDump with a full memory dump of LSASS"),
    ("/ma lsass", "ProcDump with a full memory dump of LSASS"),
    ("sekurlsa::logonpasswords", "the Mimikatz command that reads logon passwords"),
    ("lsadump::sam", "the Mimikatz command that reads the SAM"),
    ("lsadump::dcsync", "a DCSync replication request"),
    ("ntds.dit", "the Active Directory database file"),
    ("\\\\.\\pipe\\", "a named pipe, as used by several dumpers"),
    ("reg save hklm\\sam", "exporting the SAM hive"),
    ("reg save hklm\\system", "exporting the SYSTEM hive"),
    ("reg save hklm\\security", "exporting the SECURITY hive"),
    ("vssadmin create shadow", "creating a shadow copy to read locked hives"),
)

_DANGEROUS_LSASS_MASKS = {0x1010, 0x1410, 0x1438, 0x143A, 0x1FFFFF, 0x0010}


@register(
    surface="endpoint",
    summary=(
        "Reads of credential material: LSASS memory access, registry hive exports, "
        "and the tools whose only purpose is either."
    ),
    techniques=["T1003.001", "T1003.002", "T1003.003"],
    references=["https://attack.mitre.org/techniques/T1003/"],
)
def credential_dumping(alert: Alert) -> DetectorResult:
    """Attempts to read credentials out of memory or off disk.

    Three independent routes to the same tactic: a tool by name, a command-line
    pattern, or a raw handle to LSASS with a mask that permits memory reads. The
    third is the one that survives renaming the binary.
    """
    findings: list[dict[str, object]] = []

    for where, process in _all_processes(alert):
        command = _cmd_of(process).lower()
        name = _name_of(process)
        haystack = f"{name} {command}"

        for token, description in CREDENTIAL_TOOLS.items():
            if token in haystack:
                findings.append(
                    {
                        "where": where,
                        "kind": "known_tool",
                        "match": token,
                        "note": f"{description} referenced in {where}",
                        "weight": 0.85,
                    }
                )
        for pattern, description in _LSASS_DUMP_PATTERNS:
            if pattern in command:
                weight = 0.8 if "lsass" in command or "ntds" in pattern else 0.6
                findings.append(
                    {
                        "where": where,
                        "kind": "command_pattern",
                        "match": pattern,
                        "note": f"{description}",
                        "weight": weight,
                    }
                )

    target = str(alert.raw.get("TargetImage") or alert.raw.get("target_image") or "").lower()
    granted = alert.raw.get("GrantedAccess") or alert.raw.get("granted_access")
    if "lsass.exe" in target and granted is not None:
        try:
            mask = int(str(granted), 16) if isinstance(granted, str) else int(granted)
        except (TypeError, ValueError):
            mask = None
        if mask is not None:
            readable = bool(mask & 0x0010)
            findings.append(
                {
                    "where": "raw.GrantedAccess",
                    "kind": "process_access",
                    "match": hex(mask),
                    "note": (
                        f"a handle to lsass.exe was opened with access mask {hex(mask)}"
                        + (", which permits reading its memory" if readable else "")
                    ),
                    "weight": 0.9 if (readable or mask in _DANGEROUS_LSASS_MASKS) else 0.4,
                }
            )

    if not findings:
        examined = sum(1 for _ in _all_processes(alert))
        if not examined and not (target or granted):
            return miss(
                "credential_dumping",
                "the alert carries neither a process tree nor process-access data",
            )
        return clear(
            "credential_dumping",
            "no credential-dumping tools, command patterns or LSASS handles observed",
            processes_examined=examined,
        )

    strongest = max(findings, key=lambda f: float(f["weight"]))  # type: ignore[arg-type]
    combined = min(0.95, float(strongest["weight"]) + 0.05 * (len(findings) - 1))  # type: ignore[arg-type]

    hints = ["T1003"]
    joined = " ".join(f"{f['match']} {f['note']}" for f in findings).lower()
    if "lsass" in joined or "comsvcs" in joined or "minidump" in joined:
        hints.append("T1003.001")
    if "sam" in joined:
        hints.append("T1003.002")
    if "ntds" in joined or "dcsync" in joined:
        hints.append("T1003.003")

    return DetectorResult(
        detector="credential_dumping",
        fired=True,
        score=round(combined, 3),
        facts={"findings": findings},
        rationale=str(strongest["note"]),
        technique_hints=hints,
    )


@register(
    surface="endpoint",
    summary=(
        "Changes that survive a reboot: Run keys, service registration, scheduled "
        "tasks and logon scripts."
    ),
    techniques=["T1547.001", "T1543.003", "T1053.005"],
    references=["https://attack.mitre.org/tactics/TA0003/"],
)
def persistence(alert: Alert) -> DetectorResult:
    """Anything written that will run again after the machine restarts.

    Persistence is the tactic where a false positive is cheapest to check and a
    false negative is most expensive, so this fires on the mechanism and leaves
    the "was it legitimate" judgement to synthesis, where the rest of the
    context lives.
    """
    findings: list[dict[str, object]] = []

    for index, change in enumerate(alert.registry_changes):
        key = str(change.key).lower().replace("/", "\\")
        for fragment, (technique, label) in PERSISTENCE_REGISTRY_KEYS.items():
            if fragment in key:
                data = str(change.value_data or "")
                staged = any(d in data.lower() for d in STAGING_DIRECTORIES)
                findings.append(
                    {
                        "where": f"registry_changes[{index}]",
                        "kind": "registry",
                        "mechanism": label,
                        "technique": technique,
                        "key": str(change.key)[:200],
                        "value_name": str(change.value_name or "")[:120],
                        "value_data": data[:300],
                        "points_at_staging_directory": staged,
                        "weight": 0.75 if staged else 0.6,
                    }
                )
                break

    for index, task in enumerate(alert.scheduled_tasks):
        action = str(task.action or "").lower()
        staged = any(d in action for d in STAGING_DIRECTORIES)
        encoded = "-enc" in action or "frombase64" in action
        findings.append(
            {
                "where": f"scheduled_tasks[{index}]",
                "kind": "scheduled_task",
                "mechanism": "scheduled task",
                "technique": "T1053.005",
                "name": str(task.name)[:120],
                "action": str(task.action or "")[:300],
                "points_at_staging_directory": staged,
                "weight": 0.8 if (staged or encoded) else 0.55,
            }
        )

    for index, service in enumerate(alert.service_installs):
        image = str(service.image_path or "").lower()
        staged = any(d in image for d in STAGING_DIRECTORIES)
        findings.append(
            {
                "where": f"service_installs[{index}]",
                "kind": "service",
                "mechanism": "service installation",
                "technique": "T1543.003",
                "name": str(service.name)[:120],
                "image_path": str(service.image_path or "")[:300],
                "points_at_staging_directory": staged,
                "weight": 0.8 if staged else 0.6,
            }
        )

    for where, process in _all_processes(alert):
        command = _cmd_of(process).lower()
        if "schtasks" in command and "/create" in command:
            findings.append(
                {
                    "where": where,
                    "kind": "scheduled_task",
                    "mechanism": "schtasks /create",
                    "technique": "T1053.005",
                    "action": _cmd_of(process)[:300],
                    "points_at_staging_directory": any(d in command for d in STAGING_DIRECTORIES),
                    "weight": 0.65,
                }
            )
        if "sc.exe" in command and ("create" in command or "config" in command):
            remote = "\\\\" in command
            findings.append(
                {
                    "where": where,
                    "kind": "service",
                    "mechanism": "sc create on a remote host" if remote else "sc create",
                    "technique": "T1021.002" if remote else "T1543.003",
                    "action": _cmd_of(process)[:300],
                    "points_at_staging_directory": any(d in command for d in STAGING_DIRECTORIES),
                    "weight": 0.65,
                }
            )
        if "reg.exe" in command and "add" in command:
            for fragment, (technique, label) in PERSISTENCE_REGISTRY_KEYS.items():
                if fragment.lstrip("\\") in command.replace("/", "\\"):
                    findings.append(
                        {
                            "where": where,
                            "kind": "registry",
                            "mechanism": f"reg add ({label})",
                            "technique": technique,
                            "action": _cmd_of(process)[:300],
                            "points_at_staging_directory": any(
                                d in command for d in STAGING_DIRECTORIES
                            ),
                            "weight": 0.7,
                        }
                    )
                    break

    if not findings:
        surfaces = (
            len(alert.registry_changes)
            + len(alert.scheduled_tasks)
            + len(alert.service_installs)
            + sum(1 for _ in _all_processes(alert))
        )
        if not surfaces:
            return miss(
                "persistence",
                "the alert carries no registry changes, scheduled tasks, service "
                "installs or processes to examine",
            )
        return clear(
            "persistence",
            "no reboot-surviving changes observed in this alert",
            registry_changes=len(alert.registry_changes),
            scheduled_tasks=len(alert.scheduled_tasks),
            service_installs=len(alert.service_installs),
        )

    strongest = max(findings, key=lambda f: float(f["weight"]))  # type: ignore[arg-type]
    mechanisms = sorted({str(f["mechanism"]) for f in findings})
    hints = sorted({str(f["technique"]) for f in findings})

    rationale = f"persistence established via {strongest['mechanism']}"
    if strongest.get("points_at_staging_directory"):
        rationale += ", pointing at a world-writable directory"
    if len(mechanisms) > 1:
        rationale += f"; {len(mechanisms)} distinct mechanisms in one alert"

    return DetectorResult(
        detector="persistence",
        fired=True,
        score=round(min(0.95, float(strongest["weight"]) + 0.08 * (len(mechanisms) - 1)), 3),  # type: ignore[arg-type]
        facts={"findings": findings, "mechanisms": mechanisms},
        rationale=rationale,
        technique_hints=hints,
    )


_OBFUSCATION_TELLS: tuple[tuple[str, str], ...] = (
    ("-enc", "an encoded PowerShell command"),
    ("-encodedcommand", "an encoded PowerShell command"),
    ("-e ", "an abbreviated encoded-command switch"),
    ("frombase64string", "base64 decoding at runtime"),
    ("convert::frombase64", "base64 decoding at runtime"),
    ("-w hidden", "a hidden window"),
    ("-windowstyle hidden", "a hidden window"),
    ("-nop", "profile loading suppressed"),
    ("-noprofile", "profile loading suppressed"),
    ("-ep bypass", "the execution policy bypassed"),
    ("-executionpolicy bypass", "the execution policy bypassed"),
    ("iex(", "Invoke-Expression on a constructed string"),
    ("invoke-expression", "Invoke-Expression on a constructed string"),
    ("downloadstring", "code fetched and run from a URL"),
    ("downloadfile", "a file fetched from a URL"),
    ("invoke-webrequest", "a web request from the shell"),
    ("[char]", "string assembly from character codes"),
    ("-join", "string assembly by joining fragments"),
    ("-bxor", "an XOR decoding loop"),
    ("gzipstream", "an in-memory decompression stage"),
    ("reflection.assembly", "an assembly loaded reflectively"),
)


@register(
    surface="endpoint",
    summary=(
        "Command lines built to be unreadable: encoded payloads, hidden windows, "
        "runtime string assembly, and execution-policy bypasses."
    ),
    techniques=["T1027", "T1059.001", "T1140"],
    references=["https://attack.mitre.org/techniques/T1027/"],
)
def encoded_command(alert: Alert) -> DetectorResult:
    """Obfuscation in a command line, and what it decodes to.

    Where a base64 payload decodes cleanly, the decoded text is returned in the
    facts. That is the single most useful thing this detector produces: an
    analyst gets the actual command rather than a note that one was encoded.
    """
    findings: list[dict[str, object]] = []

    carriers: list[tuple[str, str]] = [
        (where, _cmd_of(process)) for where, process in _all_processes(alert)
    ]
    for index, change in enumerate(alert.registry_changes):
        carriers.append((f"registry_changes[{index}].value_data", str(change.value_data or "")))
    for index, task in enumerate(alert.scheduled_tasks):
        carriers.append((f"scheduled_tasks[{index}].action", str(task.action or "")))
    for index, service in enumerate(alert.service_installs):
        carriers.append((f"service_installs[{index}].image_path", str(service.image_path or "")))

    for where, raw_command in carriers:
        if not raw_command:
            continue
        command = raw_command.lower()
        tells = [note for token, note in _OBFUSCATION_TELLS if token in command]
        hidden = invisible_characters(raw_command)
        decoded = decoded_candidates(raw_command)

        if not tells and not decoded and not hidden:
            continue

        finding: dict[str, object] = {
            "where": where,
            "command_line": raw_command[:400],
            "tells": tells,
            "invisible_characters": len(hidden),
        }
        if decoded:
            finding["decoded"] = [
                {"encoding": encoding, "text": text[:500]} for encoding, text in decoded
            ]
        findings.append(finding)

    if not findings:
        if not any(text for _, text in carriers):
            return miss(
                "encoded_command",
                "the alert carries no command lines, registry values, task actions "
                "or service paths to decode",
            )
        return clear(
            "encoded_command",
            "no obfuscation or encoded payloads in the observed commands, registry "
            "values, task actions or service paths",
            carriers_examined=len(carriers),
        )

    tell_total = sum(len(f["tells"]) for f in findings)  # type: ignore[arg-type]
    decoded_any = [f for f in findings if f.get("decoded")]

    score = min(0.9, 0.2 + 0.15 * tell_total)
    if decoded_any:
        score = min(0.92, score + 0.2)

    if decoded_any:
        first = decoded_any[0]["decoded"][0]  # type: ignore[index]
        rationale = (
            f"an encoded payload in {decoded_any[0]['where']} decoded from "
            f"{first['encoding']} to: {str(first['text'])[:160]}"
        )
    else:
        rationale = (
            f"{tell_total} obfuscation techniques in one command line: "
            f"{', '.join(findings[0]['tells'][:3])}"  # type: ignore[index]
        )

    hints = ["T1027"]
    if decoded_any:
        hints.append("T1140")
    everything = " ".join(
        [_name_of(p) for _, p in _all_processes(alert)] + [c for _, c in carriers]
    ).lower()
    if "powershell" in everything or "pwsh" in everything:
        hints.append("T1059.001")

    return DetectorResult(
        detector="encoded_command",
        fired=True,
        score=round(score, 3),
        facts={"findings": findings},
        rationale=rationale,
        technique_hints=hints,
    )


_DOUBLE_EXTENSION = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|gif|rtf|csv|zip)\s*"
    r"\.(?:exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|lnk|ps1|jar|msi)$",
    re.IGNORECASE,
)


@register(
    surface="endpoint",
    summary=(
        "A file pretending to be something else: a system binary outside its "
        "directory, a double extension, or a right-to-left override."
    ),
    techniques=["T1036.005", "T1036.002", "T1036.007"],
    references=["https://attack.mitre.org/techniques/T1036/"],
)
def masquerading(alert: Alert) -> DetectorResult:
    """Names and paths chosen to be misread by a human or a rule.

    The right-to-left override case is the one worth knowing: a file named
    `invoice\\u202egpj.exe` displays as `invoiceexe.jpg` in every Windows file
    listing, and the extension a user sees is not the one that executes.
    """
    findings: list[dict[str, object]] = []

    candidates: list[tuple[str, str, str]] = []
    for where, process in _all_processes(alert):
        candidates.append((where, _name_of(process), str(process.path or "")))
    if alert.file:
        candidates.append(
            (
                "file",
                _basename(alert.file.name) or _basename(alert.file.path),
                str(alert.file.path or ""),
            )
        )
    if alert.email:
        for index, attachment in enumerate(alert.email.attachment_names):
            candidates.append(
                (f"email.attachment_names[{index}]", _basename(attachment), str(attachment))
            )

    for where, name, path in candidates:
        if not name:
            continue
        display = f"{name} {path}".strip()
        lowered_path = path.lower().replace("/", "\\")

        overrides = [
            c for c in invisible_characters(display) if c in {"\u202e", "\u202b", "\u2067"}
        ]
        if overrides:
            findings.append(
                {
                    "where": where,
                    "kind": "right_to_left_override",
                    "value": display[:200],
                    "note": (
                        "the name contains a right-to-left override, so the extension a user "
                        "sees is not the extension that executes"
                    ),
                    "weight": 0.85,
                }
            )

        if _DOUBLE_EXTENSION.search(name) or _DOUBLE_EXTENSION.search(_basename(path)):
            findings.append(
                {
                    "where": where,
                    "kind": "double_extension",
                    "value": name[:200],
                    "note": f"{name} carries a document extension in front of an executable one",
                    "weight": 0.7,
                }
            )

        homes = SYSTEM_BINARY_HOMES.get(name)
        if homes and lowered_path and not any(lowered_path.startswith(h) for h in homes):
            findings.append(
                {
                    "where": where,
                    "kind": "system_binary_outside_its_directory",
                    "value": path[:200],
                    "note": (f"{name} normally only exists in {homes[0]}; this copy is at {path}"),
                    "weight": 0.75,
                }
            )

    for where, process in _all_processes(alert):
        if process.signed is False and _name_of(process) in SYSTEM_BINARY_HOMES:
            findings.append(
                {
                    "where": where,
                    "kind": "unsigned_system_binary",
                    "value": _name_of(process),
                    "note": f"{_name_of(process)} is unsigned, and the genuine binary is signed",
                    "weight": 0.7,
                }
            )

    if not candidates:
        return miss("masquerading", "the alert names no file or process to examine")
    if not findings:
        return clear(
            "masquerading",
            "no name or path anomalies among the observed files and processes",
            candidates_examined=len(candidates),
        )

    strongest = max(findings, key=lambda f: float(f["weight"]))  # type: ignore[arg-type]
    kinds = {str(f["kind"]) for f in findings}
    hints = ["T1036"]
    if "right_to_left_override" in kinds:
        hints.append("T1036.002")
    if "double_extension" in kinds:
        hints.append("T1036.007")
    if "system_binary_outside_its_directory" in kinds or "unsigned_system_binary" in kinds:
        hints.append("T1036.005")

    return DetectorResult(
        detector="masquerading",
        fired=True,
        score=round(min(0.95, float(strongest["weight"]) + 0.06 * (len(findings) - 1)), 3),  # type: ignore[arg-type]
        facts={"findings": findings},
        rationale=str(strongest["note"]),
        technique_hints=hints,
    )


@register(
    surface="endpoint",
    summary="Data collected into an archive in a staging directory, ahead of exfiltration.",
    techniques=["T1560.001", "T1074.001"],
    references=["https://attack.mitre.org/techniques/T1560/001/"],
)
def data_staging(alert: Alert) -> DetectorResult:
    """Archive creation, weighted by where the archive landed and how big it is.

    Backup software does this all day, so the detector reports the shape and
    leaves the judgement to synthesis — but an archive written to
    `C:\\Users\\Public` by a process that also touched credentials is a
    different thing from one written to a backup share.
    """
    findings: list[dict[str, object]] = []

    for where, process in _all_processes(alert):
        name = _name_of(process)
        command = _cmd_of(process).lower()
        if name not in ARCHIVE_TOOLS and not any(
            token in command for token in ("compress-archive", "makecab", "tar -c", "zip -r")
        ):
            continue
        staged = [d for d in STAGING_DIRECTORIES if d in command]
        has_password = " -p" in command or "-hp" in command
        findings.append(
            {
                "where": where,
                "kind": "archive_created",
                "tool": name or "shell built-in",
                "command_line": _cmd_of(process)[:400],
                "staging_directories": staged,
                "password_protected": has_password,
                "weight": 0.6 if staged else 0.35,
            }
        )

    if alert.file and alert.file.path:
        path = str(alert.file.path).lower()
        if path.endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".cab")):
            staged = [d for d in STAGING_DIRECTORIES if d in path]
            size = alert.file.size_bytes or 0
            findings.append(
                {
                    "where": "file",
                    "kind": "archive_written",
                    "path": str(alert.file.path)[:300],
                    "size_bytes": size,
                    "staging_directories": staged,
                    "weight": 0.55 if staged else 0.3,
                }
            )

    if not findings:
        if not any(_cmd_of(p) for _, p in _all_processes(alert)) and alert.file is None:
            return miss("data_staging", "the alert carries no commands or files to examine")
        return clear("data_staging", "no archive creation observed in this alert")

    strongest = max(findings, key=lambda f: float(f["weight"]))  # type: ignore[arg-type]
    staged_any = any(f.get("staging_directories") for f in findings)
    protected = any(f.get("password_protected") for f in findings)

    score = float(strongest["weight"])  # type: ignore[arg-type]
    if protected:
        score = min(0.85, score + 0.2)

    rationale = f"an archive was created by {strongest.get('tool', 'an archive utility')}"
    if staged_any:
        rationale += " in a world-writable staging directory"
    if protected:
        rationale += ", password-protected, which prevents inspection in transit"

    return DetectorResult(
        detector="data_staging",
        fired=True,
        score=round(score, 3),
        facts={"findings": findings},
        rationale=rationale,
        technique_hints=["T1560.001"] + (["T1074.001"] if staged_any else []),
    )


@register(
    surface="endpoint",
    summary=(
        "An executable written to or run from a world-writable directory, where "
        "no installed software lives."
    ),
    techniques=["T1204.002", "T1074.001"],
    references=["https://attack.mitre.org/techniques/T1204/002/"],
)
def suspicious_execution_path(alert: Alert) -> DetectorResult:
    """Execution out of a directory that any user can write to.

    Installed software lives under Program Files. A binary running from
    `%TEMP%`, `C:\\Users\\Public` or `/dev/shm` was put there by something, and
    the interesting question is what.
    """
    findings: list[dict[str, object]] = []
    examined = 0

    for where, process in _all_processes(alert):
        path = str(process.path or "").lower().replace("/", "\\")
        if not path:
            continue
        examined += 1
        staged = [d for d in STAGING_DIRECTORIES if d.replace("/", "\\") in path]
        if not staged:
            continue
        findings.append(
            {
                "where": where,
                "kind": "executed_from_staging_directory",
                "path": str(process.path)[:300],
                "directories": staged,
                "signed": process.signed,
                "weight": 0.6 if process.signed is not True else 0.35,
            }
        )

    if not examined:
        return miss("suspicious_execution_path", "no process paths in the alert to examine")
    if not findings:
        return clear(
            "suspicious_execution_path",
            "every process ran from an ordinary installation directory",
            processes_examined=examined,
        )

    strongest = max(findings, key=lambda f: float(f["weight"]))  # type: ignore[arg-type]
    return DetectorResult(
        detector="suspicious_execution_path",
        fired=True,
        score=round(min(0.85, float(strongest["weight"]) + 0.08 * (len(findings) - 1)), 3),  # type: ignore[arg-type]
        facts={"findings": findings, "processes_examined": examined},
        rationale=(
            f"{_basename(str(strongest['path']))} ran from {strongest['directories'][0]}, "  # type: ignore[index]
            f"a directory any user can write to"
        ),
        technique_hints=["T1204.002"],
    )


@register(
    surface="endpoint",
    summary="Connections to file-sharing and tunnelling services frequently used to front C2.",
    techniques=["T1102", "T1567"],
    references=["https://attack.mitre.org/techniques/T1102/"],
)
def abused_hosting_contact(alert: Alert) -> DetectorResult:
    """Contact with services that host arbitrary user content.

    Explicitly weak on its own — plenty of legitimate traffic goes to GitHub
    and Discord. It exists so synthesis can raise the weight of a connection
    that is already suspicious for another reason.
    """
    hits: list[dict[str, object]] = []
    for index, connection in enumerate(alert.connections):
        host = str(connection.hostname or "").lower()
        url = str(connection.url or "").lower()
        for domain in ABUSED_HOSTING:
            if domain in host or domain in url:
                hits.append(
                    {
                        "where": f"connections[{index}]",
                        "domain": domain,
                        "hostname": str(connection.hostname or "")[:200],
                        "bytes_out": connection.bytes_out,
                    }
                )
                break

    for _, process in _all_processes(alert):
        command = _cmd_of(process).lower()
        for domain in ABUSED_HOSTING:
            if domain in command:
                hits.append({"where": "process.command_line", "domain": domain, "hostname": domain})
                break

    if not alert.connections and not any(_cmd_of(p) for _, p in _all_processes(alert)):
        return miss(
            "abused_hosting_contact", "the alert carries no network connections or commands"
        )
    if not hits:
        return clear(
            "abused_hosting_contact",
            "no contact with commonly abused hosting services",
            connections_examined=len(alert.connections),
        )

    domains = sorted({str(h["domain"]) for h in hits})
    uploaded = sum(int(h.get("bytes_out") or 0) for h in hits)
    hints = ["T1102"]
    if uploaded > 1_000_000:
        hints.append("T1567")

    return DetectorResult(
        detector="abused_hosting_contact",
        fired=True,
        score=0.35,
        facts={"hits": hits, "domains": domains},
        rationale=(
            f"contact with {', '.join(domains[:3])} — services that host arbitrary content and "
            f"are commonly used to front command and control, though most traffic to them is benign"
        ),
        technique_hints=hints,
    )


#: Commands that destroy the ability to roll a machine back, grouped by the
#: mechanism they attack. An operator doing maintenance touches one of these;
#: ransomware preparation sweeps several in a row.
_RECOVERY_DESTRUCTION = (
    ("shadow copies", re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows", re.I)),
    ("shadow copies", re.compile(r"wmic\s+shadowcopy\s+delete", re.I)),
    ("shadow copies", re.compile(r"Get-WmiObject\s+Win32_Shadowcopy.{0,40}\bDelete\b", re.I)),
    (
        "backup catalogue",
        re.compile(r"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)", re.I),
    ),
    ("boot recovery", re.compile(r"bcdedit(?:\.exe)?.{0,60}recoveryenabled\s+no", re.I)),
    (
        "boot recovery",
        re.compile(r"bcdedit(?:\.exe)?.{0,60}bootstatuspolicy\s+ignoreallfailures", re.I),
    ),
    ("event log", re.compile(r"wevtutil(?:\.exe)?\s+cl\s+\S", re.I)),
    ("restore points", re.compile(r"Disable-ComputerRestore", re.I)),
)

_UNATTENDED = re.compile(r"/quiet|-quiet|/q\b", re.I)


@register(
    surface="endpoint",
    summary=(
        "Commands that destroy a machine's ability to recover - shadow copies, "
        "the backup catalogue, boot recovery. Scored on how many independent "
        "recovery mechanisms are attacked, not on any single command."
    ),
    techniques=["T1490", "T1070.001"],
    references=[
        "https://attack.mitre.org/techniques/T1490/",
        "https://attack.mitre.org/techniques/T1070/001/",
    ],
)
def recovery_destruction(alert: Alert) -> DetectorResult:
    """Deleting the ways back to a working machine.

    Written because the held-out set caught Bishop closing a shadow-copy
    deletion as a false positive: no detector had jurisdiction, the evidence
    table came back empty, and ransomware preparation read as nothing to see.

    **Why the count matters more than the command.** `vssadmin delete shadows`
    has a narrow legitimate use - an administrator reclaiming disk on a server
    genuinely runs it. What has no benign reading is doing that *and* deleting
    the backup catalogue *and* disabling boot recovery in one command line:
    those are three different recovery mechanisms, and an operator freeing
    space attacks one. So a single mechanism scores as suspicion and several
    score as intent.

    **`/quiet` is weighted for what it is for.** It exists to suppress the
    confirmation prompt. An administrator at a console does not need it;
    something running with nobody present does.
    """
    findings: list[dict[str, object]] = []
    carriers = [(where, _cmd_of(process)) for where, process in _all_processes(alert)]
    carriers += [
        (f"scheduled_tasks[{index}].action", str(task.action or ""))
        for index, task in enumerate(alert.scheduled_tasks)
    ]

    for where, command in carriers:
        if not command:
            continue
        for mechanism, pattern in _RECOVERY_DESTRUCTION:
            if match := pattern.search(command):
                findings.append(
                    {
                        "where": where,
                        "mechanism": mechanism,
                        "match": match.group(0)[:120],
                        "unattended": bool(_UNATTENDED.search(command)),
                    }
                )

    if not findings:
        if not any(command for _, command in carriers):
            return miss(
                "recovery_destruction",
                "the alert carries no command lines or task actions to examine",
            )
        return clear(
            "recovery_destruction",
            "no commands that delete shadow copies, backups or boot recovery",
            carriers_examined=len(carriers),
        )

    mechanisms = sorted({str(f["mechanism"]) for f in findings})
    unattended = any(f["unattended"] for f in findings)

    # One mechanism is suspicious and has a maintenance reading. Two or more is
    # a deliberate sweep of every way back, which maintenance never is.
    score = 0.55 if len(mechanisms) == 1 else 0.9
    if unattended:
        score = min(0.95, score + 0.05)

    hints = ["T1490"]
    if any(f["mechanism"] == "event log" for f in findings):
        hints.append("T1070.001")

    listed = ", ".join(mechanisms)
    plural = "s" if len(mechanisms) > 1 else ""
    reading = (
        ". Attacking several at once has no maintenance reading - freeing disk space touches one."
        if len(mechanisms) > 1
        else ". A single mechanism has a narrow administrative use, so this is suspicion "
        "rather than a conclusion."
    )
    return DetectorResult(
        detector="recovery_destruction",
        fired=True,
        score=round(score, 3),
        facts={"findings": findings, "mechanisms": mechanisms, "unattended": unattended},
        rationale=(
            f"{len(mechanisms)} recovery mechanism{plural} destroyed ({listed})"
            + (", with the confirmation prompt suppressed" if unattended else "")
            + reading
        ),
        technique_hints=hints,
    )
