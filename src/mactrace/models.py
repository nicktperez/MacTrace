"""Shared domain models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class Event:
    event_type: str
    timestamp: str = field(default_factory=utc_now)
    pid: int | None = None
    ppid: int | None = None
    process_name: str | None = None
    executable: str | None = None
    command_line: str | None = None
    ancestry: list[dict[str, Any]] = field(default_factory=list)
    local_address: str | None = None
    remote_address: str | None = None
    local_port: int | None = None
    remote_port: int | None = None
    connection_state: str | None = None
    file_path: str | None = None
    action: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    synthetic: bool = False
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Alert:
    rule_id: str
    rule_name: str
    description: str
    severity: str
    explanation: str
    supporting_event_ids: list[int]
    recommended_steps: list[str]
    timestamp: str = field(default_factory=utc_now)
    process_name: str | None = None
    pid: int | None = None
    status: str = "new"
    analyst_note: str = ""
    synthetic: bool = False
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

