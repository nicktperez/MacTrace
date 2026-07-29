from fastapi.testclient import TestClient

from mactrace.api import create_app
from mactrace.config import Settings
from mactrace.models import Event


def test_health_and_demo_data(tmp_path):
    settings = Settings(mode="demo", database_path=tmp_path / "demo.db")
    with TestClient(create_app(settings)) as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["mode"] == "demo"
        assert client.get("/api/events").json()
        alerts = client.get("/api/alerts").json()
        assert alerts


def test_alert_workflow_and_exports(tmp_path):
    settings = Settings(mode="demo", database_path=tmp_path / "demo.db")
    with TestClient(create_app(settings)) as client:
        alert = client.get("/api/alerts").json()[0]
        response = client.patch(
            f"/api/alerts/{alert['id']}",
            json={"status": "investigating", "analyst_note": "Reviewing the chain"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "investigating"
        assert client.get(f"/api/investigations/{alert['id']}").status_code == 200
        exported = client.get(f"/api/investigations/{alert['id']}/export?format=html")
        assert exported.status_code == 200
        assert "Sanitized local report" in exported.text


def test_websocket_connects(tmp_path):
    settings = Settings(mode="demo", database_path=tmp_path / "demo.db")
    with TestClient(create_app(settings)) as client:
        with client.websocket_connect("/ws") as socket:
            message = socket.receive_json()
            assert message["kind"] == "connected"
            assert message["data"]["mode"] == "demo"


def test_rule_suppression_and_storage_status(tmp_path):
    settings = Settings(mode="demo", database_path=tmp_path / "demo.db")
    with TestClient(create_app(settings)) as client:
        response = client.put(
            "/api/suppressions/MT-PROC-001",
            json={"hours": 2, "reason": "Known test fixture"},
        )
        assert response.status_code == 200
        assert response.json()["rule_id"] == "MT-PROC-001"
        assert client.get("/api/suppressions").json()[0]["reason"] == "Known test fixture"
        storage = client.get("/api/storage").json()
        assert storage["retention_days"] == 30
        assert storage["database_bytes"] > 0
        assert client.delete("/api/suppressions/MT-PROC-001").status_code == 204


def test_process_detail_merges_async_trust_result(tmp_path):
    settings = Settings(mode="demo", database_path=tmp_path / "demo.db")
    with TestClient(create_app(settings)) as client:
        client.app.state.storage.add_event(
            Event(
                "executable_trust",
                pid=48201,
                process_name="InvoiceViewer",
                executable="/Users/demo/Downloads/InvoiceViewer",
                metadata={
                    "signing": "untrusted",
                    "quarantine": {"present": True, "agent": "Safari"},
                    "inspection_status": "complete",
                },
                synthetic=True,
            )
        )
        detail = client.get("/api/processes/48201").json()
        assert detail["process"]["metadata"]["signing"] == "untrusted"
        assert detail["process"]["metadata"]["quarantine"]["agent"] == "Safari"


def test_assessment_endpoint_prioritizes_demo_chain(tmp_path):
    settings = Settings(mode="demo", database_path=tmp_path / "demo.db")
    with TestClient(create_app(settings)) as client:
        assessment = client.get("/api/assessment")
        assert assessment.status_code == 200
        payload = assessment.json()
        assert payload["status"] == "attention"
        assert payload["findings"][0]["recommendation"] == "Investigate now"
        assert payload["method"].startswith("Local rule correlation")


def test_five_operational_surfaces(tmp_path):
    settings = Settings(
        mode="demo",
        database_path=tmp_path / "demo.db",
        baseline_learning_observations=10,
    )
    with TestClient(create_app(settings)) as client:
        sensors = client.get("/api/sensors")
        assert sensors.status_code == 200
        assert {sensor["status"] for sensor in sensors.json()} == {"healthy"}

        baseline = client.get("/api/baseline").json()
        assert baseline["observations"] > 0
        assert "categories" in baseline

        cases = client.get("/api/cases").json()
        assert cases
        detail = client.get(f"/api/cases/{cases[0]['id']}").json()
        assert detail["alerts"]
        assert detail["timeline"]
        updated = client.patch(
            f"/api/cases/{cases[0]['id']}",
            json={"status": "investigating", "analyst_note": "Triaged locally"},
        )
        assert updated.json()["status"] == "investigating"

        executables = client.get("/api/inventory/executables").json()
        persistence = client.get("/api/inventory/persistence").json()
        assert any(item["process_name"] == "InvoiceViewer" for item in executables)
        assert any(item["persistence_type"] == "LaunchAgent" for item in persistence)

        rules = client.get("/api/rules").json()
        target = rules[0]
        changed = client.put(
            f"/api/rules/{target['rule_id']}",
            json={"enabled": False, "severity_override": "low"},
        )
        assert changed.json()["enabled"] is False
        assert changed.json()["severity_override"] == "low"

        created = client.post(
            "/api/allowlists",
            json={
                "kind": "remote_cidr",
                "value": "198.51.100.42",
                "rule_id": None,
            },
        )
        assert created.status_code == 201
        entry = created.json()
        assert entry["value"] == "198.51.100.42/32"
        assert client.delete(f"/api/allowlists/{entry['id']}").status_code == 204
