"""The untrusted-string type.

Bishop's inputs are attacker-controlled by definition. A file name, a command
line, a DNS query and a user-agent string are all written by whoever triggered
the alert, and in the interesting cases that is the adversary.

`UntrustedStr` marks those values in the type system so the boundary is
mechanical rather than a matter of remembering. It is a `str` subclass, so it
behaves normally everywhere Python expects a string — but every prompt-rendering
path in Bishop refuses to accept one directly. The only way an untrusted value
reaches a model is through `bishop.quarantine`, which frames it as data.

See `docs/THREAT-MODEL.md` for why this is the shape of the defence.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import GetCoreSchemaHandler
from pydantic_core import core_schema


class UntrustedStr(str):
    """A string that came from an attacker-influenced field.

    Identical to `str` for every ordinary purpose. The type exists so that
    `bishop.quarantine.assert_no_untrusted` can find these values by instance
    check anywhere in a prompt argument tree.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"UntrustedStr({str.__repr__(self)})"

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_after_validator_function(
            cls,
            core_schema.str_schema(),
            serialization=core_schema.plain_serializer_function_ser_schema(
                str, return_schema=core_schema.str_schema()
            ),
        )


#: Use in Pydantic models for any attacker-influenced field.
Untrusted = Annotated[UntrustedStr, "attacker-influenced"]


def is_untrusted(value: object) -> bool:
    """True if `value` is a string carrying the untrusted marker."""
    return isinstance(value, UntrustedStr)


def walk_untrusted(
    value: object, *, _path: str = "", _depth: int = 0
) -> list[tuple[str, UntrustedStr]]:
    """Walk a value tree and yield `(path, value)` for every untrusted string.

    Paths are dotted and list-indexed — `auth_events[2].user_agent` — because
    the analyst needs to know *which* field carried a payload, not just that one
    did. Depth-limited so a pathological structure cannot hang the caller.
    """
    if _depth > 12:
        return []
    if isinstance(value, UntrustedStr):
        return [(_path or "$", value)]
    if isinstance(value, str | bytes):
        return []

    found: list[tuple[str, UntrustedStr]] = []

    def descend(key: str, item: object, *, index: bool = False) -> None:
        child = f"{_path}[{key}]" if index else (f"{_path}.{key}" if _path else key)
        found.extend(walk_untrusted(item, _path=child, _depth=_depth + 1))

    if isinstance(value, dict):
        for key, item in value.items():
            descend(str(key), item)
        return found
    if isinstance(value, list | tuple | set):
        for position, item in enumerate(value):
            descend(str(position), item, index=True)
        return found

    fields = getattr(value, "__dict__", None)
    if isinstance(fields, dict):
        for key, item in fields.items():
            descend(key, item)
    return found


def find_untrusted(value: object, *, _path: str = "$") -> list[str]:
    """The paths at which untrusted strings appear. See `walk_untrusted`."""
    return [path for path, _ in walk_untrusted(value, _path="" if _path == "$" else _path)]
