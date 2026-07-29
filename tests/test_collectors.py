import asyncio

import pytest

from mactrace.collectors.manager import CollectorManager
from mactrace.collectors.processes import ProcessCollector
from mactrace.config import Settings
from mactrace.models import Event


class FakeProcess:
    info = {
        "pid": 501,
        "ppid": 1,
        "name": "sample",
        "exe": "/tmp/sample",
        "cmdline": ["/tmp/sample"],
        "create_time": 100.0,
    }

    def parent(self):
        return None


def test_process_poll_does_not_run_trust_inspection(monkeypatch):
    collector = ProcessCollector()
    monkeypatch.setattr(
        "mactrace.collectors.processes.psutil.process_iter",
        lambda _fields: iter([FakeProcess()]),
    )

    def fail_if_called(_executable):
        raise AssertionError("trust inspection blocked the process poll")

    monkeypatch.setattr(collector, "_signing_status", fail_if_called)
    event = collector.poll()[0]
    assert event.metadata["signing"] == "pending"
    assert event.metadata["quarantine"]["status"] == "pending"
    assert event.metadata["newly_observed_executable"] is True


@pytest.mark.asyncio
async def test_bounded_inspection_worker_emits_result():
    emitted = []

    async def emit(event):
        emitted.append(event)

    settings = Settings(
        signing_inspection_workers=1,
        signing_inspection_queue_size=1,
    )
    manager = CollectorManager(settings, emit)
    manager.processes.inspect_executable = lambda _path: {
        "signing": "valid",
        "quarantine": {"present": False},
        "inspection_status": "complete",
    }
    candidate = Event(
        "process_start",
        pid=502,
        process_name="sample",
        executable="/tmp/sample",
        metadata={"newly_observed_executable": True},
    )
    await manager._queue_inspection(candidate)
    worker = asyncio.create_task(manager._inspection_worker())
    await asyncio.wait_for(manager._inspection_queue.join(), timeout=1)
    worker.cancel()
    await asyncio.gather(worker, return_exceptions=True)

    assert manager._inspection_queue.maxsize == 1
    assert emitted[0].event_type == "executable_trust"
    assert emitted[0].metadata["signing"] == "valid"
