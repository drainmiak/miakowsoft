"""Export investigation results to JSON, Markdown, CSV and plain text."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from miakowsoft.utils import ensure_dir


class Reporter:
    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or Path.cwd() / "data" / "reports"
        ensure_dir(self.base_dir)

    def _stamp(self, target: str) -> str:
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in target)[:80]
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"{ts}_{safe}"

    def export(self, payload: dict[str, Any], fmt: str = "json") -> Path:
        fmt = (fmt or "json").lower().strip()
        stamp = self._stamp(str(payload.get("target", "target")))
        if fmt == "json":
            path = self.base_dir / f"{stamp}.json"
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            return path
        if fmt in ("md", "markdown"):
            path = self.base_dir / f"{stamp}.md"
            path.write_text(self._to_markdown(payload), encoding="utf-8")
            return path
        if fmt == "txt":
            path = self.base_dir / f"{stamp}.txt"
            path.write_text(self._to_text(payload), encoding="utf-8")
            return path
        if fmt == "csv":
            path = self.base_dir / f"{stamp}.csv"
            self._to_csv(payload, path)
            return path
        raise ValueError(f"Unsupported export format: {fmt}")

    def _to_markdown(self, payload: dict[str, Any]) -> str:
        lines: list[str] = []
        lines.append("miakowsoft report")
        lines.append("")
        lines.append(f"- Target: `{payload.get('target')}`")
        lines.append(f"- Type: {payload.get('target_type')}")
        lines.append(f"- Version: {payload.get('version')}")
        lines.append(f"- Started: {payload.get('started_at')}")
        lines.append(f"- Finished: {payload.get('finished_at')}")
        lines.append(f"- Elapsed: {payload.get('elapsed_ms')} ms")
        lines.append("")
        summary = payload.get("summary") or {}
        lines.append("Summary")
        lines.append("")
        for k, v in summary.items():
            lines.append(f"- {k}: {v}")
        lines.append("")
        lines.append("Sources")
        lines.append("")
        for src in payload.get("sources") or []:
            status = src.get("status")
            detail = src.get("error") or src.get("note") or ""
            lines.append(f"- [{status}] **{src.get('source')}** — {src.get('count')} result(s), {src.get('duration_ms')} ms {detail}")
        lines.append("")
        lines.append("Observations")
        lines.append("")
        for idx, row in enumerate(payload.get("records") or [], 1):
            title = row.get("title") or row.get("indicator") or "item"
            lines.append(f"{idx}. **{title}**")
            lines.append(f"   - Source: {row.get('source')}")
            lines.append(f"   - Retrieved: {row.get('retrieved_at')}")
            if row.get("source_url"):
                lines.append(f"   - URL: {row.get('source_url')}")
            if row.get("evidence"):
                lines.append(f"   - Evidence: {row.get('evidence')}")
            if row.get("confidence"):
                lines.append(f"   - Confidence: {row.get('confidence')}")
            lines.append("")
        corrs = payload.get("correlations") or []
        if corrs:
            lines.append("Correlations (repeated observations)")
            lines.append("")
            lines.append("These are co-occurrences under multiple source labels, not identity proofs.")
            lines.append("")
            for c in corrs:
                lines.append(f"- `{c.get('indicator')}` seen in {c.get('source_count')} sources: {', '.join(c.get('sources') or [])}")
            lines.append("")
        for note in payload.get("notes") or []:
            lines.append(f"> {note}")
        lines.append("")
        return "\n".join(lines)

    def _to_text(self, payload: dict[str, Any]) -> str:
        lines: list[str] = []
        lines.append("miakowsoft report")
        lines.append("=" * 60)
        lines.append(f"Target: {payload.get('target')}  Type: {payload.get('target_type')}")
        lines.append(f"Version: {payload.get('version')}  Elapsed: {payload.get('elapsed_ms')} ms")
        lines.append(f"Started: {payload.get('started_at')}  Finished: {payload.get('finished_at')}")
        lines.append("")
        lines.append("Sources")
        lines.append("-" * 40)
        for src in payload.get("sources") or []:
            detail = src.get("error") or src.get("note") or ""
            lines.append(f"[{src.get('status'):<7}] {src.get('source')}: {src.get('count')} ({src.get('duration_ms')} ms) {detail}")
        lines.append("")
        lines.append("Observations")
        lines.append("-" * 40)
        for idx, row in enumerate(payload.get("records") or [], 1):
            title = row.get("title") or row.get("indicator") or "item"
            lines.append(f"{idx}. {title}")
            lines.append(f"   source={row.get('source')}  at={row.get('retrieved_at')}")
            if row.get("source_url"):
                lines.append(f"   url={row.get('source_url')}")
            if row.get("evidence"):
                lines.append(f"   evidence={row.get('evidence')}")
            lines.append("")
        return "\n".join(lines)

    def _to_csv(self, payload: dict[str, Any], path: Path) -> None:
        fieldnames = [
            "indicator",
            "indicator_type",
            "title",
            "source",
            "retrieved_at",
            "source_url",
            "confidence",
            "evidence",
        ]
        with path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in payload.get("records") or []:
                writer.writerow({k: row.get(k, "") for k in fieldnames})
