"""Persistent case synchronization from explainable assessment findings."""

from __future__ import annotations

from .storage import Storage


def sync_cases(storage: Storage, assessment: dict) -> list[dict]:
    for finding in assessment.get("findings", []):
        storage.upsert_case(finding)
    return storage.cases()
