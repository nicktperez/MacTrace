"""Process and network polling using psutil."""

from __future__ import annotations

import logging
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import psutil

from ..models import Event
from ..privacy import sanitize_command_line

log = logging.getLogger(__name__)


class ProcessCollector:
    def __init__(self, command_line_max_chars: int = 320) -> None:
        self.known: dict[int, float] = {}
        self.command_line_max_chars = command_line_max_chars
        self._permission_warned = False
        self._signing_cache: dict[str, str] = {}
        self._quarantine_cache: dict[str, dict] = {}
        self._observed_executables: set[str] = set()
        self.last_error: str | None = None
        self.last_poll: str | None = None
        self.events_observed = 0

    def poll(self) -> list[Event]:
        current: dict[int, float] = {}
        events: list[Event] = []
        try:
            processes = psutil.process_iter(
                ["pid", "ppid", "name", "exe", "cmdline", "create_time"]
            )
            # Force enumeration here so a sandbox-level sysctl denial is handled cleanly.
            processes = list(processes)
        except (PermissionError, psutil.AccessDenied, OSError) as exc:
            self.last_error = str(exc)
            self.last_poll = datetime.now(UTC).isoformat()
            if not self._permission_warned:
                log.warning(
                    "Process collection is unavailable with current macOS permissions: %s", exc
                )
                self._permission_warned = True
            return []
        for process in processes:
            try:
                info = process.info
                pid = int(info["pid"])
                created = float(info.get("create_time") or 0)
                current[pid] = created
                if self.known.get(pid) == created:
                    continue
                executable = info.get("exe") or ""
                newly_observed = bool(
                    executable and executable not in self._observed_executables
                )
                if executable:
                    self._observed_executables.add(executable)
                events.append(
                    Event(
                        event_type="process_start",
                        pid=pid,
                        ppid=info.get("ppid"),
                        process_name=info.get("name"),
                        executable=executable,
                        command_line=sanitize_command_line(
                            info.get("cmdline"), self.command_line_max_chars
                        ),
                        ancestry=self._ancestry(process),
                        metadata={
                            "signing": "pending" if executable else "unavailable",
                            "quarantine": {
                                "present": None,
                                "status": "pending" if executable else "unavailable",
                            },
                            "newly_observed_executable": newly_observed,
                        },
                    )
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                continue
        for pid in self.known.keys() - current.keys():
            events.append(Event(event_type="process_stop", pid=pid))
        self.known = current
        self.last_error = None
        self.last_poll = datetime.now(UTC).isoformat()
        self.events_observed += len(events)
        return events

    def inspect_executable(self, executable: str) -> dict:
        """Perform potentially slow macOS trust inspection outside the poll loop."""
        return {
            "signing": self._cached_signing_status(executable),
            "quarantine": self._cached_quarantine_metadata(executable),
            "inspection_status": "complete",
        }

    def _cached_signing_status(self, executable: str) -> str:
        if executable not in self._signing_cache:
            self._signing_cache[executable] = self._signing_status(executable)
        return self._signing_cache[executable]

    def _cached_quarantine_metadata(self, executable: str) -> dict:
        if executable not in self._quarantine_cache:
            self._quarantine_cache[executable] = self._quarantine_metadata(executable)
        return self._quarantine_cache[executable]

    @staticmethod
    def _ancestry(process: psutil.Process, limit: int = 6) -> list[dict]:
        chain: list[dict] = []
        try:
            parent = process.parent()
            while parent and len(chain) < limit:
                chain.append({"pid": parent.pid, "name": parent.name()})
                parent = parent.parent()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
        return chain

    @staticmethod
    def _signing_status(executable: str) -> str:
        if not executable or not Path(executable).exists():
            return "unavailable"
        try:
            result = subprocess.run(
                ["codesign", "--verify", "--strict", executable],
                capture_output=True,
                timeout=1.5,
                check=False,
            )
            if result.returncode == 0:
                return "valid"
            stderr = result.stderr.decode(errors="ignore").lower()
            return "unsigned" if "not signed at all" in stderr else "untrusted"
        except (OSError, subprocess.TimeoutExpired):
            return "unavailable"

    @staticmethod
    def _quarantine_metadata(executable: str) -> dict:
        """Return parsed provenance flags without retaining the raw xattr value."""
        if not executable or not Path(executable).exists():
            return {"present": False}
        try:
            result = subprocess.run(
                ["xattr", "-p", "com.apple.quarantine", executable],
                capture_output=True,
                timeout=1,
                check=False,
                text=True,
            )
            if result.returncode != 0:
                return {"present": False}
            fields = result.stdout.strip().split(";")
            metadata: dict[str, str | bool] = {"present": True}
            if fields and fields[0]:
                metadata["flags"] = fields[0][:16]
            if len(fields) > 1 and fields[1]:
                try:
                    from datetime import UTC, datetime

                    metadata["timestamp"] = datetime.fromtimestamp(
                        int(fields[1], 16), UTC
                    ).isoformat()
                except ValueError:
                    pass
            if len(fields) > 2 and fields[2]:
                metadata["agent"] = fields[2][:120]
            return metadata
        except (OSError, subprocess.TimeoutExpired):
            return {"present": False}


class NetworkCollector:
    def __init__(self) -> None:
        self.known: set[tuple] = set()
        self.last_error: str | None = None
        self.last_poll: str | None = None
        self.events_observed = 0

    def poll(self) -> list[Event]:
        current: set[tuple] = set()
        events: list[Event] = []
        process_names: dict[int, str] = {}
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            self.last_error = str(exc)
            self.last_poll = datetime.now(UTC).isoformat()
            log.debug("Network collection unavailable: %s", exc)
            return []
        for connection in connections:
            local_address = connection.laddr.ip if connection.laddr else None
            local_port = connection.laddr.port if connection.laddr else None
            remote_address = connection.raddr.ip if connection.raddr else None
            remote_port = connection.raddr.port if connection.raddr else None
            key = (
                connection.pid,
                local_address,
                local_port,
                remote_address,
                remote_port,
                connection.status,
            )
            current.add(key)
            if key in self.known:
                continue
            name = None
            if connection.pid:
                if connection.pid not in process_names:
                    try:
                        process_names[connection.pid] = psutil.Process(connection.pid).name()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        process_names[connection.pid] = "restricted"
                name = process_names[connection.pid]
            event_type = "network_listen" if connection.status == psutil.CONN_LISTEN else "network_connection"
            events.append(
                Event(
                    event_type=event_type,
                    pid=connection.pid,
                    process_name=name,
                    local_address=local_address,
                    local_port=local_port,
                    remote_address=remote_address,
                    remote_port=remote_port,
                    connection_state=connection.status,
                )
            )
        self.known = current
        self.last_error = None
        self.last_poll = datetime.now(UTC).isoformat()
        self.events_observed += len(events)
        return events
