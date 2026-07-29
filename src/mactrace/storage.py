"""Thread-safe SQLite persistence."""

from __future__ import annotations

import json
import ipaddress
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import Alert, Event


class Storage:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._initialize()

    def _initialize(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
                    pid INTEGER, ppid INTEGER, process_name TEXT, executable TEXT,
                    command_line TEXT, ancestry TEXT NOT NULL DEFAULT '[]',
                    local_address TEXT, remote_address TEXT, local_port INTEGER,
                    remote_port INTEGER, connection_state TEXT, file_path TEXT,
                    action TEXT, metadata TEXT NOT NULL DEFAULT '{}',
                    synthetic INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL, rule_id TEXT NOT NULL, rule_name TEXT NOT NULL,
                    description TEXT NOT NULL, severity TEXT NOT NULL,
                    explanation TEXT NOT NULL, supporting_event_ids TEXT NOT NULL,
                    recommended_steps TEXT NOT NULL, process_name TEXT, pid INTEGER,
                    status TEXT NOT NULL DEFAULT 'new', analyst_note TEXT NOT NULL DEFAULT '',
                    synthetic INTEGER NOT NULL DEFAULT 0,
                    fingerprint TEXT UNIQUE
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp DESC);
                CREATE TABLE IF NOT EXISTS connections (
                    fingerprint TEXT PRIMARY KEY,
                    pid INTEGER, process_name TEXT,
                    local_address TEXT, local_port INTEGER,
                    remote_address TEXT, remote_port INTEGER,
                    connection_state TEXT, event_type TEXT NOT NULL,
                    first_observed TEXT NOT NULL, last_observed TEXT NOT NULL,
                    observation_count INTEGER NOT NULL DEFAULT 1,
                    synthetic INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_connections_last
                    ON connections(last_observed DESC);
                CREATE TABLE IF NOT EXISTS rule_suppressions (
                    rule_id TEXT PRIMARY KEY,
                    suppressed_until TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS baselines (
                    kind TEXT NOT NULL, key TEXT NOT NULL,
                    first_observed TEXT NOT NULL, last_observed TEXT NOT NULL,
                    observation_count INTEGER NOT NULL DEFAULT 1,
                    details TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (kind, key)
                );
                CREATE TABLE IF NOT EXISTS executable_inventory (
                    path TEXT PRIMARY KEY, process_name TEXT,
                    first_observed TEXT NOT NULL, last_observed TEXT NOT NULL,
                    launch_count INTEGER NOT NULL DEFAULT 1,
                    signing TEXT NOT NULL DEFAULT 'pending',
                    quarantine TEXT NOT NULL DEFAULT '{}',
                    synthetic INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_executable_last
                    ON executable_inventory(last_observed DESC);
                CREATE TABLE IF NOT EXISTS persistence_inventory (
                    path TEXT PRIMARY KEY, persistence_type TEXT NOT NULL,
                    first_observed TEXT NOT NULL, last_observed TEXT NOT NULL,
                    change_count INTEGER NOT NULL DEFAULT 1,
                    last_action TEXT, process_name TEXT, pid INTEGER,
                    synthetic INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_persistence_last
                    ON persistence_inventory(last_observed DESC);
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL, summary TEXT NOT NULL,
                    priority TEXT NOT NULL, confidence TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new',
                    analyst_note TEXT NOT NULL DEFAULT '',
                    first_observed TEXT NOT NULL, last_observed TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_alerts (
                    case_id TEXT NOT NULL, alert_id INTEGER NOT NULL,
                    PRIMARY KEY (case_id, alert_id),
                    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS rule_settings (
                    rule_id TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    severity_override TEXT
                );
                CREATE TABLE IF NOT EXISTS allowlist_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL, value TEXT NOT NULL,
                    rule_id TEXT, enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                """
            )
        self._backfill_connections()

    def _backfill_connections(self) -> None:
        existing = self._connection.execute(
            "SELECT COUNT(*) FROM connections"
        ).fetchone()[0]
        if existing:
            return
        rows = self._connection.execute(
            """SELECT timestamp,event_type,pid,process_name,local_address,local_port,
                      remote_address,remote_port,connection_state,synthetic
               FROM events
               WHERE event_type IN ('network_connection','network_listen')
               ORDER BY timestamp ASC"""
        )
        with self._connection:
            for row in rows:
                self._upsert_connection(
                    Event(
                        timestamp=row["timestamp"],
                        event_type=row["event_type"],
                        pid=row["pid"],
                        process_name=row["process_name"],
                        local_address=row["local_address"],
                        local_port=row["local_port"],
                        remote_address=row["remote_address"],
                        remote_port=row["remote_port"],
                        connection_state=row["connection_state"],
                        synthetic=bool(row["synthetic"]),
                    )
                )

    def add_event(self, event: Event) -> int:
        data = event.to_dict()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """INSERT INTO events (
                    timestamp,event_type,pid,ppid,process_name,executable,command_line,
                    ancestry,local_address,remote_address,local_port,remote_port,
                    connection_state,file_path,action,metadata,synthetic
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    data["timestamp"], data["event_type"], data["pid"], data["ppid"],
                    data["process_name"], data["executable"], data["command_line"],
                    json.dumps(data["ancestry"]), data["local_address"], data["remote_address"],
                    data["local_port"], data["remote_port"], data["connection_state"],
                    data["file_path"], data["action"], json.dumps(data["metadata"]),
                    int(data["synthetic"]),
                ),
            )
            event.id = int(cursor.lastrowid)
            if event.event_type in {"network_connection", "network_listen"}:
                self._upsert_connection(event)
            self._update_inventories(event)
            return event.id

    def _update_inventories(self, event: Event) -> None:
        if event.event_type == "process_start" and event.executable:
            self._connection.execute(
                """INSERT INTO executable_inventory (
                    path,process_name,first_observed,last_observed,launch_count,
                    signing,quarantine,synthetic
                ) VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(path) DO UPDATE SET
                    process_name=COALESCE(excluded.process_name, executable_inventory.process_name),
                    last_observed=excluded.last_observed,
                    launch_count=executable_inventory.launch_count + 1,
                    synthetic=excluded.synthetic""",
                (
                    event.executable, event.process_name, event.timestamp, event.timestamp, 1,
                    event.metadata.get("signing", "pending"),
                    json.dumps(event.metadata.get("quarantine", {})),
                    int(event.synthetic),
                ),
            )
        elif event.event_type == "executable_trust" and event.executable:
            self._connection.execute(
                """UPDATE executable_inventory
                   SET signing=?, quarantine=?, last_observed=?
                   WHERE path=?""",
                (
                    event.metadata.get("signing", "unavailable"),
                    json.dumps(event.metadata.get("quarantine", {})),
                    event.timestamp,
                    event.executable,
                ),
            )
        persistence_type = self._persistence_type(event.file_path)
        if persistence_type and event.event_type in {"file_change", "persistence_observed"}:
            self._connection.execute(
                """INSERT INTO persistence_inventory (
                    path,persistence_type,first_observed,last_observed,change_count,
                    last_action,process_name,pid,synthetic
                ) VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(path) DO UPDATE SET
                    last_observed=excluded.last_observed,
                    change_count=persistence_inventory.change_count +
                        CASE WHEN excluded.last_action='observed' THEN 0 ELSE 1 END,
                    last_action=excluded.last_action,
                    process_name=COALESCE(excluded.process_name,persistence_inventory.process_name),
                    pid=COALESCE(excluded.pid,persistence_inventory.pid)""",
                (
                    event.file_path, persistence_type, event.timestamp, event.timestamp,
                    0 if event.action == "observed" else 1, event.action,
                    event.process_name, event.pid, int(event.synthetic),
                ),
            )

    @staticmethod
    def _persistence_type(path: str | None) -> str | None:
        lowered = (path or "").lower()
        if "/library/launchagents/" in lowered:
            return "LaunchAgent"
        if "/library/launchdaemons/" in lowered:
            return "LaunchDaemon"
        if lowered.endswith(("/.zshrc", "/.bashrc", "/.bash_profile", "/.profile")):
            return "Shell startup"
        if "/cron" in lowered or lowered.endswith("/crontab"):
            return "Scheduled task"
        return None

    def baseline_get(self, kind: str, key: str) -> dict | None:
        row = self._connection.execute(
            "SELECT * FROM baselines WHERE kind=? AND key=?", (kind, key)
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["details"] = json.loads(result["details"])
        return result

    def baseline_record(
        self, kind: str, key: str, timestamp: str, details: dict | None = None
    ) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT INTO baselines (
                    kind,key,first_observed,last_observed,observation_count,details
                ) VALUES (?,?,?,?,1,?)
                ON CONFLICT(kind,key) DO UPDATE SET
                    last_observed=excluded.last_observed,
                    observation_count=baselines.observation_count + 1,
                    details=excluded.details""",
                (kind, key, timestamp, timestamp, json.dumps(details or {})),
            )

    def baseline_summary(self) -> dict:
        counts = {
            row["kind"]: row["count"]
            for row in self._connection.execute(
                "SELECT kind, COUNT(*) count FROM baselines GROUP BY kind"
            )
        }
        observations = self._connection.execute(
            "SELECT COALESCE(SUM(observation_count),0) FROM baselines"
        ).fetchone()[0]
        return {"categories": counts, "observations": observations}

    def executable_inventory(self, limit: int = 1000) -> list[dict]:
        rows = self._connection.execute(
            "SELECT * FROM executable_inventory ORDER BY last_observed DESC LIMIT ?",
            (min(limit, 2000),),
        )
        result = []
        for row in rows:
            item = dict(row)
            item["quarantine"] = json.loads(item["quarantine"])
            item["synthetic"] = bool(item["synthetic"])
            result.append(item)
        return result

    def persistence_inventory(self, limit: int = 1000) -> list[dict]:
        return [
            {**dict(row), "synthetic": bool(row["synthetic"])}
            for row in self._connection.execute(
                "SELECT * FROM persistence_inventory ORDER BY last_observed DESC LIMIT ?",
                (min(limit, 2000),),
            )
        ]

    def rule_setting(self, rule_id: str) -> dict:
        row = self._connection.execute(
            "SELECT * FROM rule_settings WHERE rule_id=?", (rule_id,)
        ).fetchone()
        return (
            {
                "rule_id": rule_id,
                "enabled": bool(row["enabled"]),
                "severity_override": row["severity_override"],
            }
            if row
            else {"rule_id": rule_id, "enabled": True, "severity_override": None}
        )

    def update_rule_setting(
        self, rule_id: str, enabled: bool, severity_override: str | None
    ) -> dict:
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT INTO rule_settings (rule_id,enabled,severity_override)
                   VALUES (?,?,?)
                   ON CONFLICT(rule_id) DO UPDATE SET
                     enabled=excluded.enabled,
                     severity_override=excluded.severity_override""",
                (rule_id, int(enabled), severity_override),
            )
        return self.rule_setting(rule_id)

    def allowlist_entries(self) -> list[dict]:
        return [
            {**dict(row), "enabled": bool(row["enabled"])}
            for row in self._connection.execute(
                "SELECT * FROM allowlist_entries ORDER BY created_at DESC"
            )
        ]

    def add_allowlist_entry(self, kind: str, value: str, rule_id: str | None) -> dict:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """INSERT INTO allowlist_entries (
                    kind,value,rule_id,enabled,created_at
                ) VALUES (?,?,?,?,?)""",
                (kind, value, rule_id, 1, datetime.now(UTC).isoformat()),
            )
        return next(
            item for item in self.allowlist_entries() if item["id"] == cursor.lastrowid
        )

    def delete_allowlist_entry(self, entry_id: int) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM allowlist_entries WHERE id=?", (entry_id,)
            )

    def event_is_allowlisted(self, event: Event, rule_id: str) -> bool:
        for entry in self.allowlist_entries():
            if not entry["enabled"] or (
                entry["rule_id"] and entry["rule_id"] != rule_id
            ):
                continue
            if entry["kind"] == "process_name" and (
                event.process_name or ""
            ).lower() == entry["value"].lower():
                return True
            if entry["kind"] == "executable_prefix" and (
                event.executable or ""
            ).startswith(entry["value"]):
                return True
            if entry["kind"] == "remote_cidr" and event.remote_address:
                try:
                    if ipaddress.ip_address(event.remote_address) in ipaddress.ip_network(
                        entry["value"], strict=False
                    ):
                        return True
                except ValueError:
                    continue
        return False

    def upsert_case(self, finding: dict) -> dict:
        now = datetime.now(UTC).isoformat()
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT INTO cases (
                    id,title,summary,priority,confidence,status,analyst_note,
                    first_observed,last_observed,updated_at
                ) VALUES (?,?,?,?,?,'new','',?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title, summary=excluded.summary,
                    priority=excluded.priority, confidence=excluded.confidence,
                    first_observed=MIN(cases.first_observed,excluded.first_observed),
                    last_observed=MAX(cases.last_observed,excluded.last_observed),
                    updated_at=excluded.updated_at""",
                (
                    finding["id"], finding["headline"], finding["summary"],
                    finding["priority"], finding["confidence"],
                    finding["first_observed"], finding["last_observed"], now,
                ),
            )
            for alert_id in finding["alert_ids"]:
                self._connection.execute(
                    "INSERT OR IGNORE INTO case_alerts (case_id,alert_id) VALUES (?,?)",
                    (finding["id"], alert_id),
                )
        return self.get_case(finding["id"]) or {}

    def cases(self, limit: int = 250) -> list[dict]:
        rows = self._connection.execute(
            """SELECT c.*, COUNT(ca.alert_id) alert_count
               FROM cases c LEFT JOIN case_alerts ca ON ca.case_id=c.id
               GROUP BY c.id
               ORDER BY
                 CASE c.priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1
                   WHEN 'review' THEN 2 ELSE 3 END,
                 c.last_observed DESC LIMIT ?""",
            (min(limit, 1000),),
        )
        return [dict(row) for row in rows]

    def get_case(self, case_id: str) -> dict | None:
        row = self._connection.execute(
            "SELECT * FROM cases WHERE id=?", (case_id,)
        ).fetchone()
        if not row:
            return None
        result = dict(row)
        alert_ids = [
            item[0]
            for item in self._connection.execute(
                "SELECT alert_id FROM case_alerts WHERE case_id=?", (case_id,)
            )
        ]
        result["alerts"] = [
            alert for alert_id in alert_ids
            if (alert := self.get_alert(alert_id)) is not None
        ]
        event_ids = sorted(
            {
                event_id
                for alert in result["alerts"]
                for event_id in alert["supporting_event_ids"]
            }
        )
        pids = {alert["pid"] for alert in result["alerts"] if alert["pid"] is not None}
        events = [
            event for event_id in event_ids
            if (event := self.event(event_id)) is not None
        ]
        for pid in pids:
            events.extend(self.events_for_pid(pid, 100))
        result["timeline"] = sorted(
            {event["id"]: event for event in events}.values(),
            key=lambda event: event["timestamp"],
        )
        return result

    def update_case(self, case_id: str, status: str, analyst_note: str) -> dict | None:
        with self._lock, self._connection:
            self._connection.execute(
                """UPDATE cases SET status=?,analyst_note=?,updated_at=? WHERE id=?""",
                (status, analyst_note[:4000], datetime.now(UTC).isoformat(), case_id),
            )
        return self.get_case(case_id)

    def _upsert_connection(self, event: Event) -> None:
        import hashlib

        fingerprint = hashlib.sha256(
            (
                f"{event.pid}:{event.local_address}:{event.local_port}:"
                f"{event.remote_address}:{event.remote_port}:{event.event_type}"
            ).encode()
        ).hexdigest()
        self._connection.execute(
            """INSERT INTO connections (
                fingerprint,pid,process_name,local_address,local_port,remote_address,
                remote_port,connection_state,event_type,first_observed,last_observed,
                observation_count,synthetic
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                process_name=COALESCE(excluded.process_name, connections.process_name),
                connection_state=excluded.connection_state,
                last_observed=excluded.last_observed,
                observation_count=connections.observation_count + 1""",
            (
                fingerprint, event.pid, event.process_name, event.local_address,
                event.local_port, event.remote_address, event.remote_port,
                event.connection_state, event.event_type, event.timestamp, event.timestamp,
                1, int(event.synthetic),
            ),
        )

    def add_alert(self, alert: Alert, fingerprint: str) -> int | None:
        data = alert.to_dict()
        try:
            with self._lock, self._connection:
                cursor = self._connection.execute(
                    """INSERT INTO alerts (
                        timestamp,rule_id,rule_name,description,severity,explanation,
                        supporting_event_ids,recommended_steps,process_name,pid,status,
                        analyst_note,synthetic,fingerprint
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        data["timestamp"], data["rule_id"], data["rule_name"],
                        data["description"], data["severity"], data["explanation"],
                        json.dumps(data["supporting_event_ids"]),
                        json.dumps(data["recommended_steps"]), data["process_name"],
                        data["pid"], data["status"], data["analyst_note"],
                        int(data["synthetic"]), fingerprint,
                    ),
                )
                alert.id = int(cursor.lastrowid)
                return alert.id
        except sqlite3.IntegrityError:
            return None

    def events(self, limit: int = 250, event_type: str | None = None) -> list[dict]:
        query = "SELECT * FROM events"
        params: list[Any] = []
        if event_type:
            query += " WHERE event_type = ?"
            params.append(event_type)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(min(limit, 2000))
        return [self._event_row(row) for row in self._connection.execute(query, params)]

    def alerts(self, limit: int = 250, status: str | None = None) -> list[dict]:
        query = "SELECT * FROM alerts"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(min(limit, 2000))
        return [self._alert_row(row) for row in self._connection.execute(query, params)]

    def get_alert(self, alert_id: int) -> dict | None:
        row = self._connection.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return self._alert_row(row) if row else None

    def event(self, event_id: int) -> dict | None:
        row = self._connection.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        return self._event_row(row) if row else None

    def events_for_pid(self, pid: int, limit: int = 100) -> list[dict]:
        rows = self._connection.execute(
            "SELECT * FROM events WHERE pid=? ORDER BY timestamp DESC LIMIT ?", (pid, limit)
        )
        return [self._event_row(row) for row in rows]

    def update_alert(self, alert_id: int, status: str, note: str) -> dict | None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE alerts SET status=?, analyst_note=? WHERE id=?",
                (status, note[:4000], alert_id),
            )
        return self.get_alert(alert_id)

    def connections(self, limit: int = 1000) -> list[dict]:
        rows = self._connection.execute(
            "SELECT * FROM connections ORDER BY last_observed DESC LIMIT ?",
            (min(limit, 2000),),
        )
        result = []
        for row in rows:
            item = dict(row)
            item["synthetic"] = bool(item["synthetic"])
            result.append(item)
        return result

    def suppress_rule(self, rule_id: str, hours: int, reason: str = "") -> dict:
        now = datetime.now(UTC)
        until = now + timedelta(hours=max(1, min(hours, 24 * 30)))
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT INTO rule_suppressions (
                    rule_id,suppressed_until,reason,created_at
                ) VALUES (?,?,?,?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    suppressed_until=excluded.suppressed_until,
                    reason=excluded.reason,
                    created_at=excluded.created_at""",
                (rule_id, until.isoformat(), reason[:500], now.isoformat()),
            )
        return {
            "rule_id": rule_id,
            "suppressed_until": until.isoformat(),
            "reason": reason[:500],
        }

    def remove_suppression(self, rule_id: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM rule_suppressions WHERE rule_id=?", (rule_id,)
            )

    def active_suppressions(self) -> list[dict]:
        now = datetime.now(UTC).isoformat()
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM rule_suppressions WHERE suppressed_until <= ?", (now,)
            )
        return [
            dict(row)
            for row in self._connection.execute(
                "SELECT * FROM rule_suppressions ORDER BY suppressed_until DESC"
            )
        ]

    def is_rule_suppressed(self, rule_id: str) -> bool:
        now = datetime.now(UTC).isoformat()
        row = self._connection.execute(
            """SELECT 1 FROM rule_suppressions
               WHERE rule_id=? AND suppressed_until > ?""",
            (rule_id, now),
        ).fetchone()
        return row is not None

    def enforce_retention(self, retention_days: int, max_database_mb: int) -> dict[str, int]:
        """Prune old telemetry and bound the SQLite file with oldest-first deletion."""
        cutoff = (datetime.now(UTC) - timedelta(days=max(1, retention_days))).isoformat()
        deleted_events = 0
        deleted_alerts = 0
        deleted_connections = 0
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "DELETE FROM events WHERE timestamp < ?", (cutoff,)
            )
            deleted_events += max(cursor.rowcount, 0)
            cursor = self._connection.execute(
                "DELETE FROM alerts WHERE timestamp < ?", (cutoff,)
            )
            deleted_alerts += max(cursor.rowcount, 0)
            cursor = self._connection.execute(
                "DELETE FROM connections WHERE last_observed < ?", (cutoff,)
            )
            deleted_connections += max(cursor.rowcount, 0)

        max_bytes = max(16, max_database_mb) * 1024 * 1024
        # Delete oldest telemetry in bounded batches. WAL bytes are included because they
        # are part of the on-disk footprint users care about.
        while self.database_logical_size_bytes() > max_bytes:
            with self._lock, self._connection:
                cursor = self._connection.execute(
                    """DELETE FROM events WHERE id IN (
                        SELECT id FROM events ORDER BY timestamp ASC LIMIT 1000
                    )"""
                )
                batch = max(cursor.rowcount, 0)
                deleted_events += batch
                if batch == 0:
                    break
        with self._lock:
            self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            if self.database_size_bytes() > max_bytes:
                self._connection.execute("VACUUM")
        return {
            "events": deleted_events,
            "alerts": deleted_alerts,
            "connections": deleted_connections,
            "database_bytes": self.database_size_bytes(),
        }

    def database_size_bytes(self) -> int:
        return sum(
            candidate.stat().st_size
            for candidate in (
                self.path,
                Path(str(self.path) + "-wal"),
                Path(str(self.path) + "-shm"),
            )
            if candidate.exists()
        )

    def database_logical_size_bytes(self) -> int:
        page_count = self._connection.execute("PRAGMA page_count").fetchone()[0]
        free_pages = self._connection.execute("PRAGMA freelist_count").fetchone()[0]
        page_size = self._connection.execute("PRAGMA page_size").fetchone()[0]
        return max(0, page_count - free_pages) * page_size

    def stats(self) -> dict[str, Any]:
        row = self._connection.execute(
            """SELECT
                (SELECT COUNT(*) FROM alerts WHERE date(timestamp)=date('now')) alerts_today,
                (SELECT COUNT(DISTINCT pid) FROM events
                  WHERE event_type='process_start' AND timestamp >= datetime('now','-1 day')) processes,
                (SELECT COUNT(*) FROM events WHERE event_type='network_connection'
                  AND timestamp >= datetime('now','-10 minutes')) connections,
                (SELECT COUNT(*) FROM events) total_events,
                (SELECT COUNT(*) FROM connections) unique_connections"""
        ).fetchone()
        severities = dict(
            self._connection.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
            ).fetchall()
        )
        weights = {"critical": 32, "high": 20, "medium": 9, "low": 3}
        risk = min(100, sum(weights.get(key, 0) * value for key, value in severities.items()))
        return {
            **dict(row),
            "risk_score": risk,
            "severities": severities,
            "database_bytes": self.database_size_bytes(),
        }

    def clear(self) -> None:
        with self._lock, self._connection:
            self._connection.execute("DELETE FROM alerts")
            self._connection.execute("DELETE FROM events")
            self._connection.execute("DELETE FROM connections")
            self._connection.execute("DELETE FROM rule_suppressions")
            self._connection.execute("DELETE FROM baselines")
            self._connection.execute("DELETE FROM executable_inventory")
            self._connection.execute("DELETE FROM persistence_inventory")
            self._connection.execute("DELETE FROM case_alerts")
            self._connection.execute("DELETE FROM cases")
            self._connection.execute("DELETE FROM rule_settings")
            self._connection.execute("DELETE FROM allowlist_entries")

    @staticmethod
    def _event_row(row: sqlite3.Row) -> dict:
        result = dict(row)
        result["ancestry"] = json.loads(result["ancestry"])
        result["metadata"] = json.loads(result["metadata"])
        result["synthetic"] = bool(result["synthetic"])
        return result

    @staticmethod
    def _alert_row(row: sqlite3.Row) -> dict:
        result = dict(row)
        result["supporting_event_ids"] = json.loads(result["supporting_event_ids"])
        result["recommended_steps"] = json.loads(result["recommended_steps"])
        result["synthetic"] = bool(result["synthetic"])
        result.pop("fingerprint", None)
        return result

    def close(self) -> None:
        self._connection.close()
