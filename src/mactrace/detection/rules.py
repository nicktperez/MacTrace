"""Modular, evidence-oriented detection rules."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

from ..models import Alert, Event


class Rule(ABC):
    rule_id: str
    name: str
    description: str
    severity: str
    steps: list[str]

    @abstractmethod
    def evaluate(self, event: Event) -> Alert | None: ...

    def alert(self, event: Event, explanation: str, event_ids: list[int] | None = None) -> Alert:
        return Alert(
            rule_id=self.rule_id,
            rule_name=self.name,
            description=self.description,
            severity=self.severity,
            explanation=explanation,
            supporting_event_ids=event_ids or ([event.id] if event.id else []),
            recommended_steps=self.steps,
            process_name=event.process_name,
            pid=event.pid,
            synthetic=event.synthetic,
        )


class LaunchFromWritableLocation(Rule):
    rule_id = "MT-PROC-001"
    name = "Executable launched from user-writable staging area"
    description = "A process started from Downloads or a temporary directory."
    severity = "medium"
    steps = [
        "Confirm whether the user expected this program to run.",
        "Inspect the file's source, quarantine attributes, and signature.",
        "Review child processes and nearby network activity.",
    ]

    def evaluate(self, event: Event) -> Alert | None:
        path = (event.executable or "").lower()
        markers = ("/downloads/", "/tmp/", "/private/tmp/", "/var/folders/")
        if event.event_type == "process_start" and any(marker in path for marker in markers):
            return self.alert(
                event,
                f"{event.process_name or 'A process'} started from {event.executable}. "
                "User-writable staging locations are common for legitimate installers and "
                "also deserve extra review.",
            )
        return None


class LaunchAgentChanged(Rule):
    rule_id = "MT-PERSIST-001"
    name = "LaunchAgent created or modified"
    description = "A file changed in a user LaunchAgents directory."
    severity = "high"
    steps = [
        "Inspect the plist metadata and referenced executable without running it.",
        "Use launchctl print gui/$(id -u) to review the loaded job.",
        "Confirm the change with the user and inspect related process activity.",
    ]

    def evaluate(self, event: Event) -> Alert | None:
        path = (event.file_path or "").lower()
        if (
            event.event_type == "file_change"
            and "/library/launchagents/" in path
            and event.action in {"created", "modified", "moved"}
        ):
            return self.alert(
                event,
                f"{event.action.title()} LaunchAgent metadata was observed at "
                f"{event.file_path}. LaunchAgents are a legitimate persistence mechanism, "
                "so the change should be attributed.",
            )
        return None


class EncodedCommand(Rule):
    rule_id = "MT-CMD-001"
    name = "Suspiciously encoded interpreter command"
    description = "A shell or Python process used encoding or inline execution patterns."
    severity = "high"
    steps = [
        "Review the sanitized command and its parent process.",
        "Locate the originating script or application if available.",
        "Do not decode unknown payloads on a production system.",
    ]
    _pattern = re.compile(
        r"(?i)(base64\s+(?:--decode|-d)|frombase64string|python\S*\s+-c\s+.{0,80}"
        r"(?:b64decode|base64)|(?:bash|sh)\s+-c\s+.{0,80}(?:base64|eval))"
    )

    def evaluate(self, event: Event) -> Alert | None:
        command = event.command_line or ""
        if event.event_type == "process_start" and self._pattern.search(command):
            return self.alert(
                event,
                "The sanitized command line combines an interpreter with an encoding or "
                "inline-execution pattern. This can be administrative automation, but it "
                "reduces transparency and warrants review.",
            )
        return None


class NewListeningPort(Rule):
    rule_id = "MT-NET-001"
    name = "New listening port"
    description = "A process began listening on a port not observed earlier in this session."
    severity = "medium"
    steps = [
        "Identify the process and confirm the service is expected.",
        "Check whether the socket is bound to loopback or all interfaces.",
        "Review the process signature and launch source.",
    ]

    def __init__(self) -> None:
        self.seen: set[tuple[int | None, str | None, int | None]] = set()

    def evaluate(self, event: Event) -> Alert | None:
        if event.event_type != "network_listen":
            return None
        key = (event.pid, event.local_address, event.local_port)
        if key in self.seen:
            return None
        self.seen.add(key)
        return self.alert(
            event,
            f"{event.process_name or 'A process'} began listening on "
            f"{event.local_address or '*'}:{event.local_port}. A new listener expands the "
            "host's reachable surface and should be attributed.",
        )


class UnusualShellParent(Rule):
    rule_id = "MT-PROC-002"
    name = "Shell launched by unusual parent"
    description = "A command shell was launched by an application that is not a typical terminal."
    severity = "medium"
    steps = [
        "Review the full ancestry and the initiating application.",
        "Confirm whether the application legitimately runs helper scripts.",
        "Inspect sibling and child processes for related activity.",
    ]
    shells = {"sh", "bash", "zsh", "fish", "dash"}
    normal_parents = {
        "terminal",
        "iterm2",
        "warp",
        "code",
        "cursor",
        "pycharm",
        "login",
        "sshd",
        "python",
        "python3",
    }

    def evaluate(self, event: Event) -> Alert | None:
        if event.event_type != "process_start" or (event.process_name or "").lower() not in self.shells:
            return None
        parent = ""
        if event.ancestry:
            parent = str(event.ancestry[0].get("name", "")).lower()
        if parent and parent not in self.normal_parents:
            return self.alert(
                event,
                f"{event.process_name} was launched by {parent}. Some desktop applications "
                "legitimately invoke shells, but this parent-child relationship is less common.",
            )
        return None


class SigningTrust(Rule):
    rule_id = "MT-TRUST-001"
    name = "Executable lacks trusted signing evidence"
    description = "macOS signing inspection reported an unsigned or untrusted executable."
    severity = "medium"
    steps = [
        "Run codesign -dv --verbose=4 on the executable.",
        "Check Gatekeeper assessment with spctl --assess.",
        "Verify provenance before allowing the program to run again.",
    ]

    def evaluate(self, event: Event) -> Alert | None:
        signing = event.metadata.get("signing")
        if event.event_type in {"process_start", "executable_trust"} and signing in {
            "unsigned",
            "untrusted",
        }:
            return self.alert(
                event,
                f"Available macOS signing checks classified {event.executable} as {signing}. "
                "Unsigned software is not inherently malicious, especially during development.",
            )
        return None


class RapidExecution(Rule):
    rule_id = "MT-PROC-003"
    name = "Rapid repeated process execution"
    description = "The same executable started repeatedly within a short interval."
    severity = "medium"
    steps = [
        "Check whether a scheduled task or software updater explains the repetition.",
        "Review the parent process and command-line variation.",
        "Inspect persistence mechanisms if execution continues.",
    ]

    def __init__(self, threshold: int = 5, window_seconds: int = 20) -> None:
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.history: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)

    def evaluate(self, event: Event) -> Alert | None:
        if event.event_type != "process_start":
            return None
        key = event.executable or event.process_name or ""
        now = datetime.fromisoformat(event.timestamp)
        records = self.history[key]
        records.append((now, event.id or 0))
        while records and now - records[0][0] > self.window:
            records.popleft()
        if len(records) == self.threshold:
            return self.alert(
                event,
                f"{Path(key).name or key} started {self.threshold} times within "
                f"{self.window.seconds} seconds. Repetition may indicate a crash loop, job, "
                "or automated execution.",
                [event_id for _, event_id in records if event_id],
            )
        return None


class EarlyNetworkConnection(Rule):
    rule_id = "MT-NET-002"
    name = "New process quickly initiated a network connection"
    description = "A recently observed process made a remote connection soon after start."
    severity = "low"
    steps = [
        "Confirm the destination is expected for this application.",
        "Review the process launch source and signature.",
        "Correlate with file and persistence events in the timeline.",
    ]

    def __init__(self, seconds: int = 15) -> None:
        self.window = timedelta(seconds=seconds)
        self.starts: dict[int, tuple[datetime, int]] = {}

    def evaluate(self, event: Event) -> Alert | None:
        when = datetime.fromisoformat(event.timestamp)
        if event.event_type == "process_start" and event.pid is not None:
            self.starts[event.pid] = (when, event.id or 0)
            return None
        if event.event_type == "network_connection" and event.pid in self.starts:
            started, start_id = self.starts[event.pid]
            if timedelta(0) <= when - started <= self.window and event.remote_address:
                return self.alert(
                    event,
                    f"{event.process_name or 'The process'} connected to "
                    f"{event.remote_address}:{event.remote_port} within "
                    f"{int((when - started).total_seconds())} seconds of appearing. This is "
                    "common for networked software but useful when correlated with other signals.",
                    [value for value in (start_id, event.id) if value],
                )
        return None


class NovelBehavior(Rule):
    rule_id = "MT-BASE-001"
    name = "Multiple locally novel behaviors"
    description = "Activity differs from the endpoint's learned local baseline."
    severity = "medium"
    steps = [
        "Review which baseline dimensions were new.",
        "Confirm the executable, parent relationship, or destination is expected.",
        "Mark the alert benign after attribution so future assessments stay focused.",
    ]

    def evaluate(self, event: Event) -> Alert | None:
        novelty = event.metadata.get("novelty", {})
        if novelty.get("learning") or novelty.get("score", 0) < 50:
            return None
        reasons = novelty.get("reasons", [])
        return self.alert(
            event,
            f"{event.process_name or 'Activity'} scored {novelty['score']}/100 for local "
            f"novelty because {'; '.join(reasons)}. Novelty is not malicious by itself, "
            "but several new dimensions appearing together deserve attribution.",
        )


def default_rules() -> list[Rule]:
    return [
        LaunchFromWritableLocation(),
        LaunchAgentChanged(),
        EncodedCommand(),
        NewListeningPort(),
        UnusualShellParent(),
        SigningTrust(),
        RapidExecution(),
        EarlyNetworkConnection(),
        NovelBehavior(),
    ]
