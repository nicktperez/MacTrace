"""Synthetic incident replay for safe demonstrations."""

from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Awaitable, Callable

from .models import Event


def scenario() -> list[Event]:
    """Return a cohesive, sanitized persistence and beaconing scenario."""
    base = datetime.now(UTC) - timedelta(minutes=7)

    def at(seconds: int) -> str:
        return (base + timedelta(seconds=seconds)).isoformat()

    return [
        Event(
            "process_start",
            timestamp=at(0),
            pid=48120,
            ppid=612,
            process_name="Safari",
            executable="/Applications/Safari.app/Contents/MacOS/Safari",
            command_line="/Applications/Safari.app/Contents/MacOS/Safari",
            ancestry=[{"pid": 1, "name": "launchd"}],
            metadata={"signing": "valid", "scenario": "initial download"},
            synthetic=True,
        ),
        Event(
            "file_change",
            timestamp=at(7),
            file_path="/Users/demo/Downloads/InvoiceViewer",
            action="created",
            metadata={"scenario": "downloaded artifact"},
            synthetic=True,
        ),
        Event(
            "process_start",
            timestamp=at(18),
            pid=48201,
            ppid=48120,
            process_name="InvoiceViewer",
            executable="/Users/demo/Downloads/InvoiceViewer",
            command_line="/Users/demo/Downloads/InvoiceViewer --open sample.pdf",
            ancestry=[{"pid": 48120, "name": "Safari"}, {"pid": 1, "name": "launchd"}],
            metadata={"signing": "untrusted", "scenario": "suspicious launch"},
            synthetic=True,
        ),
        Event(
            "process_start",
            timestamp=at(25),
            pid=48208,
            ppid=48201,
            process_name="zsh",
            executable="/bin/zsh",
            command_line="/bin/zsh -c 'python3 -c [LONG_ARGUMENT_REDACTED]'",
            ancestry=[
                {"pid": 48201, "name": "InvoiceViewer"},
                {"pid": 48120, "name": "Safari"},
                {"pid": 1, "name": "launchd"},
            ],
            metadata={"signing": "valid", "scenario": "unusual child shell"},
            synthetic=True,
        ),
        Event(
            "process_start",
            timestamp=at(29),
            pid=48211,
            ppid=48208,
            process_name="python3",
            executable="/usr/bin/python3",
            command_line="/usr/bin/python3 -c 'import base64; base64.b64decode([REDACTED])'",
            ancestry=[
                {"pid": 48208, "name": "zsh"},
                {"pid": 48201, "name": "InvoiceViewer"},
                {"pid": 48120, "name": "Safari"},
            ],
            metadata={"signing": "valid", "scenario": "encoded interpreter"},
            synthetic=True,
        ),
        Event(
            "network_connection",
            timestamp=at(34),
            pid=48211,
            process_name="python3",
            local_address="192.0.2.15",
            local_port=51844,
            remote_address="198.51.100.42",
            remote_port=443,
            connection_state="ESTABLISHED",
            metadata={"scenario": "documentation-range destination"},
            synthetic=True,
        ),
        Event(
            "file_change",
            timestamp=at(46),
            pid=48211,
            process_name="python3",
            file_path="/Users/demo/Library/LaunchAgents/com.acme.sync-helper.plist",
            action="created",
            metadata={"scenario": "persistence"},
            synthetic=True,
        ),
        Event(
            "network_listen",
            timestamp=at(58),
            pid=48211,
            process_name="python3",
            local_address="127.0.0.1",
            local_port=8765,
            connection_state="LISTEN",
            metadata={"scenario": "local control port"},
            synthetic=True,
        ),
        Event(
            "process_stop",
            timestamp=at(102),
            pid=48201,
            process_name="InvoiceViewer",
            executable="/Users/demo/Downloads/InvoiceViewer",
            metadata={"scenario": "launcher exits"},
            synthetic=True,
        ),
    ]


class DemoReplayer:
    def __init__(self, emit: Callable[[Event], Awaitable[None]], speed: float = 0.45) -> None:
        self.emit = emit
        self.speed = speed
        self.task: asyncio.Task | None = None

    async def start(self) -> None:
        self.task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        events = scenario()
        while True:
            for event in events:
                event.id = None
                event.timestamp = datetime.now(UTC).isoformat()
                await self.emit(event)
                await asyncio.sleep(self.speed)
            await asyncio.sleep(18)

    async def stop(self) -> None:
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    if args.reset:
        database = Path("data/demo.db")
        for suffix in ("", "-shm", "-wal"):
            target = Path(str(database) + suffix)
            if target.exists():
                target.unlink()
        print("Demo data reset.")


if __name__ == "__main__":
    main()

