"""Detection engine orchestration."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from ..models import Alert, Event
from ..config import Settings
from ..storage import Storage
from .rules import Rule, default_rules


class DetectionEngine:
    def __init__(
        self,
        storage: Storage,
        rules: list[Rule] | None = None,
        on_alert: Callable[[Alert], None] | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.storage = storage
        self.rules = rules or default_rules()
        self.on_alert = on_alert
        self.settings = settings or Settings()

    def evaluate(self, event: Event) -> list[Alert]:
        alerts: list[Alert] = []
        for rule in self.rules:
            rule_setting = self.storage.rule_setting(rule.rule_id)
            if not rule_setting["enabled"]:
                continue
            if rule.rule_id in self.settings.suppressed_rule_ids:
                continue
            if self.storage.is_rule_suppressed(rule.rule_id):
                continue
            if self._is_allowlisted(event, rule.rule_id):
                continue
            alert = rule.evaluate(event)
            if not alert:
                continue
            if rule_setting["severity_override"]:
                alert.severity = rule_setting["severity_override"]
            # De-duplicate a behavioral signal for the same subject during this database
            # session. Event IDs intentionally stay out of the fingerprint: polling and
            # demo replay may create fresh observations of an unchanged behavior.
            basis = (
                f"{alert.rule_id}:{alert.pid}:{event.executable}:{event.file_path}:"
                f"{event.remote_address}:{event.remote_port}:{event.local_port}"
            )
            fingerprint = hashlib.sha256(basis.encode()).hexdigest()
            if self.storage.add_alert(alert, fingerprint) is not None:
                alerts.append(alert)
                if self.on_alert:
                    self.on_alert(alert)
        return alerts

    def _is_allowlisted(self, event: Event, rule_id: str) -> bool:
        if self.storage.event_is_allowlisted(event, rule_id):
            return True
        executable = event.executable or ""
        if any(
            executable.startswith(prefix)
            for prefix in self.settings.allowlisted_executable_prefixes
        ):
            return True
        if (event.process_name or "").lower() in self.settings.allowlisted_process_names:
            return True
        return (
            event.remote_address is not None
            and event.remote_address in self.settings.allowlisted_remote_addresses
        )
