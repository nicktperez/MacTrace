from datetime import UTC, datetime

from mactrace.assessment import build_assessment
from mactrace.demo import scenario
from mactrace.detection import DetectionEngine
from mactrace.storage import Storage


def test_demo_chain_is_summarized_as_urgent(tmp_path):
    storage = Storage(tmp_path / "assessment.db")
    engine = DetectionEngine(storage)
    for event in scenario():
        storage.add_event(event)
        engine.evaluate(event)

    assessment = build_assessment(storage.alerts(100), storage.events(200))

    assert assessment["status"] == "attention"
    assert assessment["urgent_count"] >= 1
    finding = assessment["findings"][0]
    assert finding["priority"] == "urgent"
    assert finding["confidence"] == "high"
    assert finding["recommendation"] == "Investigate now"
    assert {"persistence", "network", "command"}.issubset(finding["tactics"])
    assert "InvoiceViewer" in finding["headline"]
    assert "python3" in finding["headline"]


def test_resolved_and_benign_alerts_do_not_drive_assessment():
    timestamp = datetime.now(UTC).isoformat()
    alerts = [
        {
            "id": 1,
            "timestamp": timestamp,
            "rule_id": "MT-CMD-001",
            "rule_name": "Encoded command",
            "severity": "high",
            "status": "resolved",
            "supporting_event_ids": [1],
            "recommended_steps": ["Review"],
            "pid": 10,
            "process_name": "python3",
        },
        {
            "id": 2,
            "timestamp": timestamp,
            "rule_id": "MT-NET-002",
            "rule_name": "Early network",
            "severity": "low",
            "status": "benign",
            "supporting_event_ids": [2],
            "recommended_steps": ["Review"],
            "pid": 10,
            "process_name": "python3",
        },
    ]
    assessment = build_assessment(alerts, [])
    assert assessment["status"] == "quiet"
    assert assessment["findings"] == []
