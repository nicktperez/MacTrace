"""Lifecycle and de-duplication for collectors."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from ..config import Settings
from ..models import Event
from .files import FileCollector
from .processes import NetworkCollector, ProcessCollector

log = logging.getLogger(__name__)


class CollectorManager:
    def __init__(
        self, settings: Settings, emit: Callable[[Event], Awaitable[None]]
    ) -> None:
        self.settings = settings
        self.emit = emit
        self.processes = ProcessCollector(settings.command_line_max_chars)
        self.network = NetworkCollector()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.file_collector: FileCollector | None = None
        self.tasks: list[asyncio.Task] = []
        self._recent: dict[tuple, float] = {}
        self._inspection_queue: asyncio.Queue[Event] = asyncio.Queue(
            maxsize=max(1, settings.signing_inspection_queue_size)
        )
        self._inspection_queued: set[str] = set()
        self.started_at: str | None = None

    async def start(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.file_collector = FileCollector(self.settings.watch_paths, self._emit_from_thread)
        self.file_collector.start()
        self.started_at = datetime.now(UTC).isoformat()
        for event in await asyncio.to_thread(self.file_collector.persistence_snapshot):
            await self._emit_deduped(event)
        self.tasks = [
            asyncio.create_task(
                self._poll(self.processes.poll, self.settings.poll_interval, "processes")
            ),
            asyncio.create_task(
                self._poll(self.network.poll, self.settings.network_poll_interval, "network")
            ),
            *[
                asyncio.create_task(self._inspection_worker())
                for _ in range(max(1, self.settings.signing_inspection_workers))
            ],
        ]

    async def stop(self) -> None:
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.file_collector:
            self.file_collector.stop()

    def _emit_from_thread(self, event: Event) -> None:
        if self.loop:
            asyncio.run_coroutine_threadsafe(self._emit_deduped(event), self.loop)

    async def _poll(
        self, poller: Callable[[], list[Event]], interval: float, sensor: str
    ) -> None:
        while True:
            try:
                for event in await asyncio.to_thread(poller):
                    await self._emit_deduped(event)
                    if (
                        event.event_type == "process_start"
                        and event.executable
                        and event.metadata.get("newly_observed_executable")
                    ):
                        await self._queue_inspection(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("%s collector poll failed", sensor)
            await asyncio.sleep(interval)

    def health(self) -> list[dict]:
        sensors: list[dict] = []
        for sensor_id, name, collector in (
            ("processes", "Process activity", self.processes),
            ("network", "Network activity", self.network),
        ):
            sensors.append(
                {
                    "id": sensor_id,
                    "name": name,
                    "status": (
                        "restricted"
                        if collector.last_error
                        else "healthy"
                        if collector.last_poll
                        else "starting"
                    ),
                    "last_poll": collector.last_poll,
                    "events_observed": collector.events_observed,
                    "detail": collector.last_error or "Polling normally",
                    "errors": [collector.last_error] if collector.last_error else [],
                }
            )
        if self.file_collector:
            sensors.append(self.file_collector.health())
        sensors.append(
            {
                "id": "trust",
                "name": "Executable trust",
                "status": "healthy",
                "last_poll": self.started_at,
                "events_observed": None,
                "detail": (
                    f"{self._inspection_queue.qsize()} queued of "
                    f"{self._inspection_queue.maxsize}; "
                    f"{max(1, self.settings.signing_inspection_workers)} worker(s)"
                ),
                "errors": [],
            }
        )
        return sensors

    async def _queue_inspection(self, event: Event) -> None:
        executable = event.executable or ""
        if not executable or executable in self._inspection_queued:
            return
        # Awaiting a bounded queue applies backpressure without running codesign/xattr
        # in the polling thread or allowing unbounded memory growth.
        await self._inspection_queue.put(event)
        self._inspection_queued.add(executable)

    async def _inspection_worker(self) -> None:
        while True:
            candidate = await self._inspection_queue.get()
            executable = candidate.executable or ""
            try:
                metadata = await asyncio.to_thread(
                    self.processes.inspect_executable, executable
                )
                await self._emit_deduped(
                    Event(
                        event_type="executable_trust",
                        pid=candidate.pid,
                        ppid=candidate.ppid,
                        process_name=candidate.process_name,
                        executable=executable,
                        metadata=metadata,
                        synthetic=candidate.synthetic,
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Executable trust inspection failed for %s", executable)
            finally:
                self._inspection_queue.task_done()

    async def _emit_deduped(self, event: Event) -> None:
        key = (
            event.event_type,
            event.pid,
            event.file_path,
            event.action,
            event.local_address,
            event.local_port,
            event.remote_address,
            event.remote_port,
        )
        now = time.monotonic()
        if now - self._recent.get(key, 0) < 1.0:
            return
        self._recent[key] = now
        if len(self._recent) > 5000:
            self._recent = {key: value for key, value in self._recent.items() if now - value < 60}
        await self.emit(event)
