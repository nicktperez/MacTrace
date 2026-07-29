"""FastAPI application factory and routes."""

from __future__ import annotations

import html
import ipaddress
import json
import logging
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .assessment import build_assessment
from .baseline import BaselineService
from .cases import sync_cases
from .collectors import CollectorManager
from .config import Settings
from .demo import DemoReplayer
from .detection import DetectionEngine
from .models import Alert, Event
from .storage import Storage
from .websocket import WebSocketHub

log = logging.getLogger(__name__)
WEB_DIR = Path(__file__).parent / "web"


class AlertUpdate(BaseModel):
    status: Literal["new", "investigating", "benign", "resolved"]
    analyst_note: str = Field(default="", max_length=4000)


class RuleSuppression(BaseModel):
    hours: int = Field(default=1, ge=1, le=24 * 30)
    reason: str = Field(default="", max_length=500)


class RuleSettingUpdate(BaseModel):
    enabled: bool = True
    severity_override: Literal["low", "medium", "high", "critical"] | None = None


class AllowlistCreate(BaseModel):
    kind: Literal["process_name", "executable_prefix", "remote_cidr"]
    value: str = Field(min_length=1, max_length=500)
    rule_id: str | None = Field(default=None, max_length=80)


class CaseUpdate(BaseModel):
    status: Literal["new", "investigating", "contained", "resolved", "benign"]
    analyst_note: str = Field(default="", max_length=4000)


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings.load()
    storage = Storage(config.database_path)
    baseline = BaselineService(storage, config.baseline_learning_observations)
    hub = WebSocketHub()
    service: CollectorManager | DemoReplayer | None = None
    retention_task: asyncio.Task | None = None
    stats_broadcast_task: asyncio.Task | None = None
    stats_dirty = False

    async def broadcast_latest_stats() -> None:
        nonlocal stats_dirty
        while stats_dirty:
            stats_dirty = False
            await asyncio.sleep(0.75)
            await hub.broadcast({"kind": "stats", "data": storage.stats()})

    def schedule_stats_broadcast() -> None:
        nonlocal stats_broadcast_task, stats_dirty
        stats_dirty = True
        if stats_broadcast_task is None or stats_broadcast_task.done():
            stats_broadcast_task = asyncio.create_task(broadcast_latest_stats())

    async def ingest(event: Event) -> None:
        baseline.assess_and_record(event)
        storage.add_event(event)
        await hub.broadcast({"kind": "event", "data": event.to_dict()})
        for alert in engine.evaluate(event):
            await hub.broadcast({"kind": "alert", "data": alert.to_dict()})
        schedule_stats_broadcast()

    def alert_callback(alert: Alert) -> None:
        # Alerts generated in ingest are broadcast there; callback remains useful to extensions.
        return None

    engine = DetectionEngine(storage, on_alert=alert_callback, settings=config)

    async def retention_loop() -> None:
        while True:
            await asyncio.sleep(max(1, config.retention_check_interval_hours) * 3600)
            result = await asyncio.to_thread(
                storage.enforce_retention,
                config.retention_days,
                config.max_database_mb,
            )
            if result["events"] or result["alerts"] or result["connections"]:
                log.info("Retention pruning completed: %s", result)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal service, retention_task, stats_broadcast_task
        hub.loop = asyncio.get_running_loop()
        await asyncio.to_thread(
            storage.enforce_retention,
            config.retention_days,
            config.max_database_mb,
        )
        if config.mode == "demo":
            if not storage.events(limit=1):
                for event in __import__("mactrace.demo", fromlist=["scenario"]).scenario():
                    await ingest(event)
            service = DemoReplayer(ingest)
        else:
            service = CollectorManager(config, ingest)
        await service.start()
        retention_task = asyncio.create_task(retention_loop())
        yield
        retention_task.cancel()
        if stats_broadcast_task and not stats_broadcast_task.done():
            stats_broadcast_task.cancel()
        await asyncio.gather(
            retention_task,
            *([stats_broadcast_task] if stats_broadcast_task else []),
            return_exceptions=True,
        )
        await service.stop()
        storage.close()

    app = FastAPI(
        title="MacTrace",
        version="0.1.0",
        description="Local-first macOS endpoint activity monitor",
        lifespan=lifespan,
    )
    app.state.settings = config
    app.state.storage = storage
    app.state.ingest = ingest
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/api/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "mode": config.mode,
            "local_only": True,
            "retention_days": config.retention_days,
            "max_database_mb": config.max_database_mb,
        }

    @app.get("/api/stats")
    async def stats() -> dict:
        return storage.stats()

    @app.get("/api/assessment")
    async def assessment() -> dict:
        result = build_assessment(
            storage.alerts(1000),
            storage.events(2000),
            window_hours=config.assessment_window_hours,
        )
        sync_cases(storage, result)
        return result

    @app.get("/api/sensors")
    async def sensors() -> list[dict]:
        if isinstance(service, CollectorManager):
            return service.health()
        count = storage.stats()["total_events"]
        return [
            {
                "id": "demo",
                "name": "Scenario replay",
                "status": "healthy",
                "last_poll": None,
                "events_observed": count,
                "detail": "Synthetic demonstration telemetry",
                "errors": [],
            },
            {
                "id": "local-storage",
                "name": "Local event store",
                "status": "healthy",
                "last_poll": None,
                "events_observed": count,
                "detail": "SQLite is available",
                "errors": [],
            },
        ]

    @app.get("/api/baseline")
    async def baseline_status() -> dict:
        summary = storage.baseline_summary()
        observations = summary["observations"]
        target = config.baseline_learning_observations
        return {
            **summary,
            "learning": observations < target,
            "learning_observations": target,
            "progress": min(100, round(observations / max(1, target) * 100)),
        }

    @app.get("/api/events")
    async def events(
        limit: int = Query(250, ge=1, le=2000), event_type: str | None = None
    ) -> list[dict]:
        return storage.events(limit, event_type)

    @app.get("/api/alerts")
    async def alerts(
        limit: int = Query(250, ge=1, le=2000), status: str | None = None
    ) -> list[dict]:
        return storage.alerts(limit, status)

    @app.get("/api/alerts/{alert_id}")
    async def alert(alert_id: int) -> dict:
        result = storage.get_alert(alert_id)
        if not result:
            raise HTTPException(404, "Alert not found")
        return result

    @app.patch("/api/alerts/{alert_id}")
    async def update_alert(alert_id: int, update: AlertUpdate) -> dict:
        result = storage.update_alert(alert_id, update.status, update.analyst_note)
        if not result:
            raise HTTPException(404, "Alert not found")
        await hub.broadcast({"kind": "alert_update", "data": result})
        return result

    @app.get("/api/processes")
    async def processes() -> list[dict]:
        latest: dict[int, dict] = {}
        for event in storage.events(2000):
            if event["pid"] is not None and event["event_type"] == "process_start":
                latest.setdefault(event["pid"], event)
        return list(latest.values())

    @app.get("/api/processes/{pid}")
    async def process(pid: int) -> dict:
        events_for_pid = storage.events_for_pid(pid)
        if not events_for_pid:
            raise HTTPException(404, "Process not found")
        process_event = next(
            (
                event
                for event in events_for_pid
                if event["event_type"] == "process_start"
            ),
            events_for_pid[0],
        )
        process_event = dict(process_event)
        trust_event = next(
            (
                event
                for event in events_for_pid
                if event["event_type"] == "executable_trust"
                and event["executable"] == process_event["executable"]
            ),
            None,
        )
        if trust_event:
            process_event["metadata"] = {
                **process_event["metadata"],
                **trust_event["metadata"],
            }
        alerts_for_pid = [row for row in storage.alerts(1000) if row["pid"] == pid]
        return {
            "process": process_event,
            "events": events_for_pid,
            "alerts": alerts_for_pid,
        }

    @app.get("/api/network")
    async def network() -> list[dict]:
        return storage.connections(1500)

    @app.get("/api/cases")
    async def cases() -> list[dict]:
        result = build_assessment(
            storage.alerts(1000),
            storage.events(2000),
            window_hours=config.assessment_window_hours,
        )
        return sync_cases(storage, result)

    @app.get("/api/cases/{case_id}")
    async def case(case_id: str) -> dict:
        result = storage.get_case(case_id)
        if not result:
            raise HTTPException(404, "Case not found")
        return result

    @app.patch("/api/cases/{case_id}")
    async def update_case(case_id: str, update: CaseUpdate) -> dict:
        result = storage.update_case(case_id, update.status, update.analyst_note)
        if not result:
            raise HTTPException(404, "Case not found")
        await hub.broadcast({"kind": "case_update", "data": result})
        return result

    @app.get("/api/inventory/executables")
    async def executable_inventory(
        limit: int = Query(1000, ge=1, le=2000),
    ) -> list[dict]:
        return storage.executable_inventory(limit)

    @app.get("/api/inventory/persistence")
    async def persistence_inventory(
        limit: int = Query(1000, ge=1, le=2000),
    ) -> list[dict]:
        return storage.persistence_inventory(limit)

    @app.get("/api/rules")
    async def rules() -> list[dict]:
        result = []
        for rule in engine.rules:
            result.append(
                {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "default_severity": rule.severity,
                    **storage.rule_setting(rule.rule_id),
                }
            )
        return result

    @app.put("/api/rules/{rule_id}")
    async def update_rule(rule_id: str, update: RuleSettingUpdate) -> dict:
        known = {rule.rule_id for rule in engine.rules}
        if rule_id not in known:
            raise HTTPException(404, "Detection rule not found")
        result = storage.update_rule_setting(
            rule_id, update.enabled, update.severity_override
        )
        await hub.broadcast({"kind": "rule_update", "data": result})
        return result

    @app.get("/api/allowlists")
    async def allowlists() -> list[dict]:
        return storage.allowlist_entries()

    @app.post("/api/allowlists", status_code=201)
    async def create_allowlist(entry: AllowlistCreate) -> dict:
        value = entry.value.strip()
        if entry.kind == "remote_cidr":
            try:
                value = str(ipaddress.ip_network(value, strict=False))
            except ValueError as exc:
                raise HTTPException(422, "Invalid network or IP address") from exc
        if entry.rule_id and entry.rule_id not in {
            rule.rule_id for rule in engine.rules
        }:
            raise HTTPException(422, "Unknown detection rule")
        return storage.add_allowlist_entry(entry.kind, value, entry.rule_id)

    @app.delete("/api/allowlists/{entry_id}", status_code=204)
    async def delete_allowlist(entry_id: int) -> None:
        storage.delete_allowlist_entry(entry_id)

    @app.get("/api/suppressions")
    async def suppressions() -> list[dict]:
        return storage.active_suppressions()

    @app.put("/api/suppressions/{rule_id}")
    async def suppress_rule(rule_id: str, suppression: RuleSuppression) -> dict:
        known_rule_ids = {rule.rule_id for rule in engine.rules}
        if rule_id not in known_rule_ids:
            raise HTTPException(404, "Detection rule not found")
        result = storage.suppress_rule(rule_id, suppression.hours, suppression.reason)
        await hub.broadcast({"kind": "suppression_update", "data": result})
        return result

    @app.delete("/api/suppressions/{rule_id}", status_code=204)
    async def unsuppress_rule(rule_id: str) -> None:
        storage.remove_suppression(rule_id)

    @app.get("/api/storage")
    async def storage_status() -> dict:
        return {
            "database_bytes": storage.database_size_bytes(),
            "retention_days": config.retention_days,
            "max_database_mb": config.max_database_mb,
            "active_suppressions": storage.active_suppressions(),
            "allowlist_counts": {
                "executable_prefixes": len(config.allowlisted_executable_prefixes),
                "process_names": len(config.allowlisted_process_names),
                "remote_addresses": len(config.allowlisted_remote_addresses),
            },
        }

    @app.get("/api/investigations/{alert_id}")
    async def investigation(alert_id: int) -> dict:
        selected = storage.get_alert(alert_id)
        if not selected:
            raise HTTPException(404, "Alert not found")
        evidence = [
            storage.event(event_id)
            for event_id in selected["supporting_event_ids"]
            if storage.event(event_id)
        ]
        related = storage.events_for_pid(selected["pid"], 100) if selected["pid"] else []
        by_id = {event["id"]: event for event in [*evidence, *related]}
        return {
            "generated_by": "MacTrace",
            "sanitized": True,
            "mode": config.mode,
            "alert": selected,
            "timeline": sorted(by_id.values(), key=lambda event: event["timestamp"]),
        }

    @app.get("/api/investigations/{alert_id}/export")
    async def export_investigation(
        alert_id: int, format: Literal["json", "html"] = "json"
    ):
        report = await investigation(alert_id)
        if format == "json":
            return JSONResponse(
                report,
                headers={
                    "Content-Disposition": f'attachment; filename="mactrace-{alert_id}.json"'
                },
            )
        body = html.escape(json.dumps(report, indent=2))
        document = (
            "<!doctype html><html><head><meta charset='utf-8'><title>MacTrace report</title>"
            "<style>body{font:15px system-ui;background:#111;color:#eee;padding:2rem}"
            "pre{white-space:pre-wrap;background:#191919;padding:1rem;border-radius:8px}</style>"
            f"</head><body><h1>MacTrace investigation #{alert_id}</h1>"
            "<p>Sanitized local report. Synthetic data is labeled in the payload.</p>"
            f"<pre>{body}</pre></body></html>"
        )
        return HTMLResponse(
            document,
            headers={
                "Content-Disposition": f'attachment; filename="mactrace-{alert_id}.html"'
            },
        )

    @app.websocket("/ws")
    async def websocket_endpoint(socket: WebSocket) -> None:
        await hub.connect(socket)
        try:
            await socket.send_json(
                {"kind": "connected", "data": {"mode": config.mode, "stats": storage.stats()}}
            )
            while True:
                await socket.receive_text()
        except WebSocketDisconnect:
            hub.disconnect(socket)

    return app
