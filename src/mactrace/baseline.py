"""Persistent local behavioral baseline and novelty scoring."""

from __future__ import annotations

from .models import Event
from .storage import Storage


class BaselineService:
    def __init__(self, storage: Storage, learning_observations: int = 100) -> None:
        self.storage = storage
        self.learning_observations = max(10, learning_observations)

    def assess_and_record(self, event: Event) -> None:
        keys = self._keys(event)
        if not keys:
            return
        summary = self.storage.baseline_summary()
        reasons: list[str] = []
        score = 0
        weights = {
            "executable": (30, "Executable has not been observed before"),
            "parent_relationship": (25, "Process parent relationship is new"),
            "remote_destination": (20, "Remote destination is new"),
            "listener": (30, "Listening address and port are new"),
        }
        for kind, key, details in keys:
            if self.storage.baseline_get(kind, key) is None:
                weight, reason = weights[kind]
                score += weight
                reasons.append(reason)
            self.storage.baseline_record(kind, key, event.timestamp, details)
        learning = (
            summary["observations"] < self.learning_observations and not event.synthetic
        )
        event.metadata["novelty"] = {
            "score": min(100, score),
            "reasons": reasons,
            "learning": learning,
            "baseline_observations": summary["observations"],
        }

    @staticmethod
    def _keys(event: Event) -> list[tuple[str, str, dict]]:
        keys: list[tuple[str, str, dict]] = []
        if event.event_type == "process_start":
            if event.executable:
                keys.append(
                    (
                        "executable",
                        event.executable,
                        {"process_name": event.process_name},
                    )
                )
            parent = event.ancestry[0] if event.ancestry else None
            if parent and event.executable:
                keys.append(
                    (
                        "parent_relationship",
                        f"{parent.get('name')}->{event.executable}",
                        {
                            "parent_name": parent.get("name"),
                            "process_name": event.process_name,
                        },
                    )
                )
        elif event.event_type == "network_connection" and event.remote_address:
            keys.append(
                (
                    "remote_destination",
                    f"{event.remote_address}:{event.remote_port or 0}",
                    {"process_name": event.process_name},
                )
            )
        elif event.event_type == "network_listen":
            keys.append(
                (
                    "listener",
                    f"{event.local_address or '*'}:{event.local_port or 0}",
                    {"process_name": event.process_name},
                )
            )
        return keys
