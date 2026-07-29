"""Selected-path metadata collection via watchdog."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ..models import Event

log = logging.getLogger(__name__)


class MetadataHandler(FileSystemEventHandler):
    def __init__(self, emit: Callable[[Event], None]) -> None:
        self.emit = emit

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        action = "moved" if event.event_type == "moved" else event.event_type
        source = getattr(event, "dest_path", None) or event.src_path
        self.emit(
            Event(
                event_type="file_change",
                file_path=str(Path(source)),
                action=action,
                metadata={"watched": True},
            )
        )


class FileCollector:
    def __init__(self, paths: list[Path], emit: Callable[[Event], None]) -> None:
        self.paths = paths
        self.observer = Observer()
        self.handler = MetadataHandler(emit)
        self.watched_paths: list[str] = []
        self.missing_paths: list[str] = []
        self.errors: list[str] = []
        self.started_at: str | None = None

    def start(self) -> None:
        scheduled = 0
        for path in self.paths:
            try:
                if path.exists():
                    self.observer.schedule(self.handler, str(path), recursive=True)
                    scheduled += 1
                    self.watched_paths.append(str(path))
                else:
                    self.missing_paths.append(str(path))
            except OSError as exc:
                self.errors.append(f"{path}: {exc}")
                log.warning("Cannot watch %s: %s", path, exc)
        if scheduled:
            self.observer.start()
            self.started_at = datetime.now(UTC).isoformat()

    def health(self) -> dict:
        status = (
            "restricted"
            if self.errors and not self.watched_paths
            else "healthy"
            if self.watched_paths
            else "inactive"
        )
        return {
            "id": "files",
            "name": "File metadata",
            "status": status,
            "last_poll": self.started_at,
            "events_observed": None,
            "detail": (
                f"Watching {len(self.watched_paths)} path(s); "
                f"{len(self.missing_paths)} unavailable"
            ),
            "errors": self.errors,
        }

    def persistence_snapshot(self) -> list[Event]:
        """Inventory persistence file names without reading their contents."""
        events: list[Event] = []
        for root in self.paths:
            root_text = str(root).lower()
            if not root.exists() or not (
                "launchagents" in root_text or "launchdaemons" in root_text
            ):
                continue
            try:
                for path in root.glob("*.plist"):
                    events.append(
                        Event(
                            event_type="persistence_observed",
                            file_path=str(path),
                            action="observed",
                            metadata={"watched": True, "inventory_snapshot": True},
                        )
                    )
            except OSError as exc:
                self.errors.append(f"{root}: {exc}")
        return events

    def stop(self) -> None:
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=3)
