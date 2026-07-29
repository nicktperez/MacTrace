"""Privacy-preserving metadata helpers."""

from __future__ import annotations

import re
import shlex

SENSITIVE_FLAGS = re.compile(
    r"(?i)^(--?(?:password|passwd|token|secret|api[_-]?key|authorization|cookie)(?:=|$))"
)
ENCODED_BLOB = re.compile(r"^[A-Za-z0-9+/=_-]{40,}$")


def sanitize_command_line(args: list[str] | None, max_chars: int = 320) -> str:
    """Return a bounded command line with likely secrets and long payloads removed."""
    if not args:
        return ""
    output: list[str] = []
    redact_next = False
    for index, arg in enumerate(args[:40]):
        if redact_next:
            output.append("[REDACTED]")
            redact_next = False
            continue
        if index and SENSITIVE_FLAGS.match(arg):
            if "=" in arg:
                output.append(f"{arg.split('=', 1)[0]}=[REDACTED]")
            else:
                output.append(arg)
                redact_next = True
            continue
        if index and (len(arg) > 120 or ENCODED_BLOB.fullmatch(arg)):
            output.append("[LONG_ARGUMENT_REDACTED]")
            continue
        output.append(shlex.quote(arg))
    rendered = " ".join(output)
    if len(rendered) > max_chars:
        return rendered[: max_chars - 1] + "…"
    return rendered

