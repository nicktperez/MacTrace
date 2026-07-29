"""Safe configuration loading for MacTrace."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class Settings:
    mode: str = "live"
    database_path: Path = Path("data/mactrace.db")
    poll_interval: float = 2.0
    network_poll_interval: float = 4.0
    retention_days: int = 30
    retention_check_interval_hours: int = 6
    max_database_mb: int = 256
    command_line_max_chars: int = 320
    signing_inspection_workers: int = 2
    signing_inspection_queue_size: int = 256
    assessment_window_hours: int = 24
    baseline_learning_observations: int = 100
    suppressed_rule_ids: set[str] = field(default_factory=set)
    allowlisted_executable_prefixes: list[str] = field(default_factory=list)
    allowlisted_process_names: set[str] = field(default_factory=set)
    allowlisted_remote_addresses: set[str] = field(default_factory=set)
    watch_paths: list[Path] = field(
        default_factory=lambda: [
            Path("~/Library/LaunchAgents").expanduser(),
            Path("~/.ssh").expanduser(),
            Path("~/Downloads").expanduser(),
        ]
    )

    @classmethod
    def load(cls, path: Path | None = None, mode: str | None = None) -> "Settings":
        values: dict = {}
        chosen = path or Path("config.local.toml")
        if chosen.exists():
            with chosen.open("rb") as handle:
                values = tomllib.load(handle).get("mactrace", {})
        settings = cls()
        for key in (
            "poll_interval",
            "network_poll_interval",
            "retention_days",
            "retention_check_interval_hours",
            "max_database_mb",
            "command_line_max_chars",
            "signing_inspection_workers",
            "signing_inspection_queue_size",
            "assessment_window_hours",
            "baseline_learning_observations",
        ):
            if key in values:
                setattr(settings, key, values[key])
        if "database_path" in values:
            settings.database_path = Path(values["database_path"]).expanduser()
        if "watch_paths" in values:
            settings.watch_paths = [Path(p).expanduser() for p in values["watch_paths"]]
        settings.suppressed_rule_ids = set(values.get("suppressed_rule_ids", []))
        settings.allowlisted_executable_prefixes = [
            str(Path(p).expanduser()) for p in values.get("allowlisted_executable_prefixes", [])
        ]
        settings.allowlisted_process_names = {
            str(name).lower() for name in values.get("allowlisted_process_names", [])
        }
        settings.allowlisted_remote_addresses = set(
            values.get("allowlisted_remote_addresses", [])
        )
        settings.mode = mode or values.get("mode", settings.mode)
        if settings.mode == "demo" and "database_path" not in values:
            settings.database_path = Path("data/demo.db")
        return settings
