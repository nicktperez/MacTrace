from datetime import UTC, datetime, timedelta

from mactrace.models import Alert, Event
from mactrace.storage import Storage


def test_storage_round_trip_and_alert_update(tmp_path):
    store = Storage(tmp_path / "mactrace.db")
    event = Event("process_start", pid=101, process_name="test", ancestry=[{"pid": 1}])
    store.add_event(event)
    alert = Alert(
        rule_id="TEST-1",
        rule_name="Test",
        description="Test alert",
        severity="low",
        explanation="Testing",
        supporting_event_ids=[event.id],
        recommended_steps=["Review"],
        pid=101,
    )
    assert store.add_alert(alert, "unique") is not None
    updated = store.update_alert(alert.id, "resolved", "Expected test")
    assert updated["status"] == "resolved"
    assert updated["analyst_note"] == "Expected test"
    assert store.events_for_pid(101)[0]["ancestry"] == [{"pid": 1}]


def test_alert_fingerprint_deduplicates(tmp_path):
    store = Storage(tmp_path / "mactrace.db")
    alert = Alert("TEST", "Test", "desc", "low", "explain", [], ["review"])
    assert store.add_alert(alert, "same") is not None
    assert store.add_alert(alert, "same") is None


def test_connections_are_aggregated(tmp_path):
    store = Storage(tmp_path / "mactrace.db")
    first = Event(
        "network_connection",
        pid=77,
        process_name="client",
        local_address="127.0.0.1",
        local_port=50000,
        remote_address="198.51.100.10",
        remote_port=443,
        connection_state="ESTABLISHED",
    )
    second = Event(
        "network_connection",
        timestamp=(datetime.now(UTC) + timedelta(seconds=2)).isoformat(),
        pid=77,
        process_name="client",
        local_address="127.0.0.1",
        local_port=50000,
        remote_address="198.51.100.10",
        remote_port=443,
        connection_state="ESTABLISHED",
    )
    store.add_event(first)
    store.add_event(second)
    connection = store.connections()[0]
    assert connection["observation_count"] == 2
    assert connection["first_observed"] == first.timestamp
    assert connection["last_observed"] == second.timestamp


def test_suppression_expires_and_can_be_removed(tmp_path):
    store = Storage(tmp_path / "mactrace.db")
    store.suppress_rule("MT-TEST", 1, "Expected automation")
    assert store.is_rule_suppressed("MT-TEST")
    assert store.active_suppressions()[0]["reason"] == "Expected automation"
    store.remove_suppression("MT-TEST")
    assert not store.is_rule_suppressed("MT-TEST")


def test_retention_removes_old_telemetry(tmp_path):
    store = Storage(tmp_path / "mactrace.db")
    old = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    store.add_event(Event("process_start", timestamp=old, pid=1))
    store.add_event(Event("process_start", pid=2))
    result = store.enforce_retention(retention_days=2, max_database_mb=32)
    assert result["events"] == 1
    assert [event["pid"] for event in store.events()] == [2]
