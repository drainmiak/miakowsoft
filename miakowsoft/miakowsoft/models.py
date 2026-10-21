"""Data models for miakowsoft investigation results."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class SourceResult:
    source: str
    status: str
    count: int = 0
    duration_ms: int = 0
    note: str = ""
    error: str = ""
    records: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Observation:
    indicator: str
    indicator_type: str
    title: str
    source: str
    retrieved_at: str
    source_url: str = ""
    confidence: str = "observation"
    evidence: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationReport:
    application: str
    version: str
    target: str
    target_type: str
    started_at: str
    finished_at: str
    elapsed_ms: int
    sources: list[dict[str, Any]]
    records: list[dict[str, Any]]
    correlations: list[dict[str, Any]]
    summary: dict[str, Any]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
