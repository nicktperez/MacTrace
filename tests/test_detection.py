from pathlib import Path

from mactrace.detection.engine import DetectionEngine
from mactrace.config import Settings
from mactrace.detection.rules import (
    EarlyNetworkConnection,
    EncodedCommand,
    LaunchAgentChanged,
    LaunchFromWritableLocation,
    UnusualShellParent,
)
from mactrace.models import Event
from mactrace.storage import Storage


def build_engine(tmp_path: Path, rules):
    return DetectionEngine(Storage(tmp_path / "test.db"), rules=rules)


def persist_and_evaluate(engine, event):
    engine.storage.add_event(event)
    return engine.evaluate(event)


def test_downloads_launch_detection(tmp_path):
    engine = build_engine(tmp_path, [LaunchFromWritableLocation()])
    alerts = persist_and_evaluate(
        engine,
        Event(
            "process_start",
            pid=42,
            process_name="sample",
            executable="/Users/me/Downloads/sample",
        ),
    )
    assert alerts[0].rule_id == "MT-PROC-001"
    assert alerts[0].severity == "medium"


def test_launch_agent_detection(tmp_path):
    engine = build_engine(tmp_path, [LaunchAgentChanged()])
    alerts = persist_and_evaluate(
        engine,
        Event(
            "file_change",
            file_path="/Users/me/Library/LaunchAgents/com.example.test.plist",
            action="created",
        ),
    )
    assert alerts[0].rule_id == "MT-PERSIST-001"


def test_encoded_command_detection(tmp_path):
    engine = build_engine(tmp_path, [EncodedCommand()])
    alerts = persist_and_evaluate(
        engine,
        Event(
            "process_start",
            pid=43,
            process_name="python3",
            command_line="python3 -c 'import base64; base64.b64decode(payload)'",
        ),
    )
    assert alerts[0].severity == "high"


def test_unusual_shell_parent(tmp_path):
    engine = build_engine(tmp_path, [UnusualShellParent()])
    alerts = persist_and_evaluate(
        engine,
        Event(
            "process_start",
            pid=44,
            process_name="zsh",
            ancestry=[{"pid": 40, "name": "Preview"}],
        ),
    )
    assert alerts[0].rule_id == "MT-PROC-002"


def test_network_shortly_after_process(tmp_path):
    engine = build_engine(tmp_path, [EarlyNetworkConnection()])
    started = Event("process_start", pid=45, process_name="helper")
    persist_and_evaluate(engine, started)
    connected = Event(
        "network_connection",
        pid=45,
        process_name="helper",
        remote_address="198.51.100.8",
        remote_port=443,
    )
    alerts = persist_and_evaluate(engine, connected)
    assert alerts[0].supporting_event_ids == [started.id, connected.id]


def test_allowlisted_executable_is_not_alerted(tmp_path):
    settings = Settings(allowlisted_executable_prefixes=["/Users/me/Downloads/trusted/"])
    storage = Storage(tmp_path / "test.db")
    engine = DetectionEngine(
        storage,
        rules=[LaunchFromWritableLocation()],
        settings=settings,
    )
    event = Event(
        "process_start",
        pid=90,
        executable="/Users/me/Downloads/trusted/tool",
        process_name="tool",
    )
    storage.add_event(event)
    assert engine.evaluate(event) == []


def test_config_suppressed_rule_is_not_alerted(tmp_path):
    settings = Settings(suppressed_rule_ids={"MT-PROC-001"})
    storage = Storage(tmp_path / "test.db")
    engine = DetectionEngine(
        storage,
        rules=[LaunchFromWritableLocation()],
        settings=settings,
    )
    event = Event(
        "process_start",
        pid=91,
        executable="/Users/me/Downloads/tool",
        process_name="tool",
    )
    storage.add_event(event)
    assert engine.evaluate(event) == []
