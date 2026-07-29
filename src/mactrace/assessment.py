"""Explainable local correlation and investigation prioritization."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

SEVERITY_WEIGHT = {"critical": 35, "high": 22, "medium": 12, "low": 5}

RULE_SIGNALS = {
    "MT-PROC-001": ("execution", "ran from a user-writable staging location"),
    "MT-PERSIST-001": ("persistence", "created or changed a LaunchAgent"),
    "MT-CMD-001": ("command", "used an encoded or opaque interpreter command"),
    "MT-NET-001": ("network", "opened a new listening port"),
    "MT-PROC-002": ("execution", "launched a shell from an unusual parent"),
    "MT-TRUST-001": ("trust", "lacked trusted signing evidence"),
    "MT-PROC-003": ("execution", "ran repeatedly in a short interval"),
    "MT-NET-002": ("network", "connected to the network shortly after starting"),
    "MT-BASE-001": ("baseline", "differed from the learned local baseline"),
}

TACTIC_LABELS = {
    "execution": "execution",
    "persistence": "persistence",
    "command": "command concealment",
    "network": "network activity",
    "trust": "software trust",
    "baseline": "behavioral novelty",
}


class _DisjointSet:
    def __init__(self, values: set[int]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: int) -> int:
        root = value
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[value] != value:
            value, self.parent[value] = self.parent[value], root
        return root

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def _join_phrases(values: list[str]) -> str:
    if not values:
        return "showed noteworthy activity"
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return f"{', '.join(values[:-1])}, and {values[-1]}"


def _priority(score: int) -> tuple[str, str]:
    if score >= 70:
        return "urgent", "Investigate now"
    if score >= 40:
        return "high", "Review soon"
    if score >= 20:
        return "review", "Review when convenient"
    return "low", "Monitor unless other context raises concern"


def _score(alerts: list[dict], tactics: set[str], has_chain: bool) -> int:
    score = sum(SEVERITY_WEIGHT.get(alert["severity"], 0) for alert in alerts)
    rule_ids = {alert["rule_id"] for alert in alerts}
    if {"persistence", "command", "network"}.issubset(tactics):
        score += 25
    if {"MT-PROC-001", "MT-TRUST-001"}.issubset(rule_ids):
        score += 12
    if {"MT-PROC-002", "MT-CMD-001"}.issubset(rule_ids):
        score += 15
    if len(rule_ids) >= 3:
        score += 10
    if has_chain:
        score += 8
    return min(100, score)


def _finding(
    group_alerts: list[dict],
    has_chain: bool,
    chain_names: list[str] | None = None,
) -> dict[str, Any]:
    ordered = sorted(
        group_alerts,
        key=lambda alert: (
            -SEVERITY_WEIGHT.get(alert["severity"], 0),
            alert["timestamp"],
        ),
    )
    rule_ids = {alert["rule_id"] for alert in ordered}
    tactics = {
        RULE_SIGNALS[rule_id][0]
        for rule_id in rule_ids
        if rule_id in RULE_SIGNALS
    }
    clauses = [
        RULE_SIGNALS[rule_id][1]
        for rule_id in RULE_SIGNALS
        if rule_id in rule_ids
    ]
    processes = sorted(
        {alert["process_name"] for alert in ordered if alert.get("process_name")}
    )
    pids = sorted({alert["pid"] for alert in ordered if alert.get("pid") is not None})
    score = _score(ordered, tactics, has_chain)
    priority, recommendation = _priority(score)
    subject = " → ".join((chain_names or processes)[:4]) if has_chain and processes else (
        processes[0] if processes else "Endpoint activity"
    )
    tactic_text = _join_phrases([TACTIC_LABELS[tactic] for tactic in sorted(tactics)])
    signal_text = _join_phrases(clauses)
    if len(tactics) >= 3:
        summary = (
            f"{subject} {signal_text}. These related signals span {tactic_text}, "
            "which is less likely to be explained by one routine action."
        )
    else:
        summary = (
            f"{subject} {signal_text}. This may still be legitimate, but the observed "
            "combination is worth attributing."
        )
    confidence = "high" if len(tactics) >= 3 and has_chain else (
        "medium" if len(tactics) >= 2 or len(rule_ids) >= 2 else "low"
    )
    evidence_ids = sorted(
        {
            event_id
            for alert in ordered
            for event_id in alert["supporting_event_ids"]
        }
    )
    steps: list[str] = []
    for alert in ordered:
        for step in alert["recommended_steps"]:
            if step not in steps:
                steps.append(step)
    finding_basis = ":".join(map(str, [*pids, *sorted(rule_ids)]))
    return {
        "id": hashlib.sha256(finding_basis.encode()).hexdigest()[:12],
        "priority": priority,
        "score": score,
        "confidence": confidence,
        "recommendation": recommendation,
        "headline": (
            f"Related activity involving {subject}"
            if len(ordered) > 1
            else ordered[0]["rule_name"]
        ),
        "summary": summary,
        "why": [
            f"{len(rule_ids)} distinct detection rule{'s' if len(rule_ids) != 1 else ''}",
            f"{len(tactics)} behavior categor{'ies' if len(tactics) != 1 else 'y'}",
            "Connected process ancestry" if has_chain else "No connected process chain confirmed",
        ],
        "tactics": sorted(tactics),
        "alert_ids": [alert["id"] for alert in ordered],
        "event_ids": evidence_ids,
        "pids": pids,
        "processes": processes,
        "first_observed": min(alert["timestamp"] for alert in ordered),
        "last_observed": max(alert["timestamp"] for alert in ordered),
        "recommended_steps": steps[:4],
    }


def build_assessment(
    alerts: list[dict],
    events: list[dict],
    *,
    window_hours: int = 24,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Correlate active detections and return a transparent analyst-style briefing."""
    current = now or datetime.now(UTC)
    cutoff = current - timedelta(hours=max(1, window_hours))
    active = [
        alert
        for alert in alerts
        if alert["status"] not in {"benign", "resolved"}
        and datetime.fromisoformat(alert["timestamp"]) >= cutoff
    ]
    if not active:
        return {
            "generated_at": current.isoformat(),
            "window_hours": window_hours,
            "status": "quiet",
            "headline": "No active detections need attention",
            "summary": (
                "MacTrace found no unresolved detection patterns in the assessment window. "
                "Continue monitoring; this does not prove the endpoint is threat-free."
            ),
            "finding_count": 0,
            "urgent_count": 0,
            "findings": [],
            "method": "Local rule correlation; no external AI or telemetry.",
        }

    pids = {alert["pid"] for alert in active if alert.get("pid") is not None}
    groups = _DisjointSet(pids)
    connected_pairs: set[tuple[int, int]] = set()
    for event in events:
        if event["event_type"] != "process_start" or event.get("pid") not in pids:
            continue
        child = event["pid"]
        for ancestor in event.get("ancestry", []):
            parent = ancestor.get("pid")
            if parent in pids:
                groups.union(child, parent)
                connected_pairs.add(tuple(sorted((child, parent))))

    grouped: dict[str, list[dict]] = defaultdict(list)
    for alert in active:
        pid = alert.get("pid")
        key = f"pid:{groups.find(pid)}" if pid is not None else f"alert:{alert['id']}"
        grouped[key].append(alert)

    findings = []
    for group_alerts in grouped.values():
        group_pids = {alert["pid"] for alert in group_alerts if alert.get("pid") is not None}
        has_chain = any(
            left in group_pids and right in group_pids
            for left, right in connected_pairs
        )
        chain_names: list[str] = []
        if has_chain:
            candidates = [
                event
                for event in events
                if event["event_type"] == "process_start" and event.get("pid") in group_pids
            ]
            if candidates:
                deepest = max(
                    candidates,
                    key=lambda event: sum(
                        ancestor.get("pid") in group_pids
                        for ancestor in event.get("ancestry", [])
                    ),
                )
                names_by_pid = {
                    event["pid"]: event.get("process_name")
                    for event in candidates
                    if event.get("process_name")
                }
                chain_pids = [
                    ancestor.get("pid")
                    for ancestor in reversed(deepest.get("ancestry", []))
                    if ancestor.get("pid") in group_pids
                ] + [deepest["pid"]]
                chain_names = [
                    names_by_pid.get(pid)
                    or next(
                        (
                            ancestor.get("name")
                            for ancestor in deepest.get("ancestry", [])
                            if ancestor.get("pid") == pid
                        ),
                        str(pid),
                    )
                    for pid in chain_pids
                ]
        findings.append(_finding(group_alerts, has_chain, chain_names))
    findings.sort(key=lambda finding: (-finding["score"], finding["first_observed"]))

    urgent_count = sum(finding["priority"] == "urgent" for finding in findings)
    high_count = sum(finding["priority"] == "high" for finding in findings)
    if urgent_count:
        headline = (
            f"{urgent_count} activity chain{'s' if urgent_count != 1 else ''} "
            "should be investigated now"
        )
        summary = (
            "Multiple related behaviors reinforce one another. Start with the top finding "
            "and validate its process ancestry, persistence change, and network destination."
        )
        status = "attention"
    elif high_count:
        headline = f"{high_count} finding{'s' if high_count != 1 else ''} need review soon"
        summary = (
            "MacTrace found correlated behavior that is more meaningful together than as "
            "individual alerts. Review the leading finding when practical."
        )
        status = "review"
    else:
        headline = "No urgent activity chains identified"
        summary = (
            "The active detections are currently isolated or lower-confidence. Review them "
            "for attribution, but no combined pattern requires immediate escalation."
        )
        status = "watch"
    return {
        "generated_at": current.isoformat(),
        "window_hours": window_hours,
        "status": status,
        "headline": headline,
        "summary": summary,
        "finding_count": len(findings),
        "urgent_count": urgent_count,
        "findings": findings,
        "method": "Local rule correlation; no external AI or telemetry.",
    }
