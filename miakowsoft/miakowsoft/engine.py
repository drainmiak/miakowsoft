"""Investigation engine with bounded parallelism, caching, pivot and correlation."""

from __future__ import annotations

import os
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from miakowsoft.models import InvestigationReport, utc_now_iso
from miakowsoft.security import InputValidationError, normalize_target
from miakowsoft.sources import COLLECTORS, SOURCE_CATALOG, collectors_for


DOMAIN_LIKE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
IP_LIKE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
EMAIL_LIKE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class miakowsoftEngine:
    def __init__(self, max_workers: int | None = None, max_depth: int | None = None) -> None:
        self.max_workers = max_workers or int(os.getenv("QT_CONCURRENCY", "10"))
        self.max_depth = max_depth if max_depth is not None else int(os.getenv("QT_CHAIN_DEPTH", "0"))
        self.fast_mode = os.getenv("QT_FAST", "0") in ("1", "true", "yes")
        self.skip_sources = set()
        if self.fast_mode:
            self.skip_sources = {"wayback_cdx", "anubis", "bufferover", "otx_passive_dns", "crtsh"}
        self.max_pivot_targets = int(os.getenv("QT_MAX_PIVOT_TARGETS", "18"))
        self._progress: Callable[[str], None] | None = None

    def set_progress(self, callback: Callable[[str], None] | None) -> None:
        self._progress = callback

    def _emit(self, message: str) -> None:
        if self._progress:
            self._progress(message)

    def source_catalog(self) -> list[dict[str, Any]]:
        catalog = []
        for entry in SOURCE_CATALOG:
            item = dict(entry)
            item["status"] = "ready"
            item["missing_configuration"] = []
            catalog.append(item)
        return catalog

    def investigate(self, target: str, target_type: str, depth: int | None = None) -> dict[str, Any]:
        depth = self.max_depth if depth is None else max(0, min(depth, 2))
        started = time.perf_counter()
        started_at = utc_now_iso()

        all_source_results: list[dict[str, Any]] = []
        all_records: list[dict[str, Any]] = []
        seen_targets: set[tuple[str, str]] = set()
        frontier: list[tuple[str, str, int]] = [(target, target_type, 0)]
        pivot_log: list[dict[str, Any]] = []

        while frontier:
            current, ctype, level = frontier.pop(0)
            key = (ctype, current.lower())
            if key in seen_targets:
                continue
            seen_targets.add(key)

            self._emit(f"Depth {level}: {ctype}:{current} ({len(collectors_for(ctype))} sources)")
            batch_sources, batch_records = self._run_collectors(current, ctype)
            all_source_results.extend(batch_sources)
            all_records.extend(batch_records)

            if level >= depth:
                continue

            new_targets = self._extract_pivot_targets(batch_records, current, ctype)
            added = 0
            for nt, ntype in new_targets:
                nkey = (ntype, nt.lower())
                if nkey in seen_targets:
                    continue
                if added >= self.max_pivot_targets:
                    break
                try:
                    norm, detected = normalize_target(nt, ntype)
                except InputValidationError:
                    continue
                frontier.append((norm, detected, level + 1))
                pivot_log.append(
                    {
                        "from": current,
                        "from_type": ctype,
                        "to": norm,
                        "to_type": detected,
                        "depth": level + 1,
                        "basis": "Extracted from prior observation fields",
                    }
                )
                added += 1
            if added:
                self._emit(f"Pivot queued {added} target(s) at depth {level + 1}")

        all_source_results.sort(key=lambda r: (r.get("source", ""), r.get("status", "")))
        all_records = self._dedupe_records(all_records)
        correlations = self._correlate(all_records)
        entities = self._entity_summary(all_records, correlations)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        finished_at = utc_now_iso()

        summary = {
            "sources_ok": sum(1 for s in all_source_results if s.get("status") == "ok"),
            "sources_empty": sum(1 for s in all_source_results if s.get("status") == "empty"),
            "sources_error": sum(1 for s in all_source_results if s.get("status") == "error"),
            "sources_skipped": sum(1 for s in all_source_results if s.get("status") == "skipped"),
            "total_records": len(all_records),
            "unique_indicators": len({(r.get("indicator") or "").lower() for r in all_records if r.get("indicator")}),
            "correlations": len(correlations),
            "entities": len(entities),
            "targets_investigated": len(seen_targets),
            "pivot_steps": len(pivot_log),
            "max_depth": depth,
        }

        notes = [
            "A username or email match is an observation, not identity confirmation.",
            "Geolocation and ASN data describe network infrastructure, not a person's residence.",
            "Empty results mean no public match was returned in this run, not proof of absence.",
            "Pivot targets are derived automatically from prior observations within depth limits.",
            "Entity summary groups indicators by type; multi-source does not equal identity proof.",
        ]

        report = InvestigationReport(
            application="miakowsoft",
            version="1.1.0",
            target=target,
            target_type=target_type,
            started_at=started_at,
            finished_at=finished_at,
            elapsed_ms=elapsed_ms,
            sources=all_source_results,
            records=all_records,
            correlations=correlations,
            summary=summary,
            notes=notes,
        )
        payload = report.to_dict()
        payload["pivots"] = pivot_log
        payload["entities"] = entities
        return payload

    def _run_collectors(self, target: str, target_type: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        names = [n for n in collectors_for(target_type) if n not in self.skip_sources]
        source_results: list[dict[str, Any]] = []
        all_records: list[dict[str, Any]] = []

        def run_one(name: str) -> dict[str, Any]:
            collector = COLLECTORS[name]
            result = collector(target, target_type)
            return result.to_dict()

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(run_one, n): n for n in names}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    payload = fut.result()
                except Exception as exc:
                    payload = {
                        "source": name,
                        "status": "error",
                        "count": 0,
                        "duration_ms": 0,
                        "error": str(exc),
                        "records": [],
                    }
                source_results.append(payload)
                recs = payload.get("records") or []
                all_records.extend(recs)
                self._emit(f"[{payload.get('status')}] {name}: {payload.get('count', 0)} result(s)")

        return source_results, all_records

    def _extract_pivot_targets(
        self, records: list[dict[str, Any]], origin: str, origin_type: str
    ) -> list[tuple[str, str]]:
        scored: dict[tuple[str, str], int] = {}
        origin_l = origin.lower()
        parent = origin_l if origin_type == "domain" else ""

        def score_add(value: str, t: str, weight: int) -> None:
            v = value.strip().lower().rstrip(".")
            if not v or v == origin_l:
                return
            if t == "domain" and not DOMAIN_LIKE.match(v):
                return
            if t == "ip" and not IP_LIKE.match(v):
                return
            if t == "email" and not EMAIL_LIKE.match(v):
                return
            if t == "username" and len(v) < 2:
                return
            key = (v, t)
            bonus = 0
            if t == "domain" and parent and (v.endswith("." + parent) or v == parent):
                bonus += 8
            if t == "ip":
                bonus += 3
            if t == "email":
                bonus += 2
            scored[key] = max(scored.get(key, 0), weight + bonus)

        for rec in records:
            conf = rec.get("confidence") or ""
            base = 5 if conf == "direct" else 3
            ind = (rec.get("indicator") or "").strip()
            itype = rec.get("indicator_type") or ""
            if itype in ("subdomain", "domain") and ind:
                score_add(ind, "domain", base + 4)
            if itype == "ip" and ind:
                score_add(ind, "ip", base + 3)
            if itype == "email" and ind:
                score_add(ind, "email", base + 2)
            if itype == "username" and ind:
                score_add(ind, "username", base)

            for key in ("ip", "value", "host", "exchange", "blog", "preferred_username", "login"):
                val = rec.get(key)
                if not isinstance(val, str):
                    continue
                val = val.strip()
                if IP_LIKE.match(val):
                    score_add(val, "ip", base + 2)
                elif DOMAIN_LIKE.match(val.lower().rstrip(".")):
                    score_add(val, "domain", base + 1)
                elif EMAIL_LIKE.match(val):
                    score_add(val, "email", base)
                elif key in ("preferred_username", "login") and len(val) >= 2:
                    score_add(val, "username", base)

            ns = rec.get("nameservers")
            if isinstance(ns, list):
                for item in ns:
                    if isinstance(item, str):
                        score_add(item, "domain", base)

        ranked = sorted(scored.items(), key=lambda kv: (-kv[1], kv[0][1], kv[0][0]))
        return [(val, typ) for (val, typ), _w in ranked[: self.max_pivot_targets]]

    def _dedupe_records(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str]] = set()
        out: list[dict[str, Any]] = []
        for rec in records:
            key = (
                (rec.get("indicator") or "").lower(),
                rec.get("source") or "",
                (rec.get("title") or "")[:160],
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(rec)
        return out

    def _entity_summary(
        self, records: list[dict[str, Any]], correlations: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        by_ind: dict[str, dict[str, Any]] = {}
        corr_map = {c["indicator"]: c for c in correlations}
        for rec in records:
            ind = (rec.get("indicator") or "").strip()
            if not ind:
                continue
            key = ind.lower()
            ent = by_ind.get(key)
            if not ent:
                ent = {
                    "indicator": ind,
                    "indicator_type": rec.get("indicator_type") or "unknown",
                    "sources": set(),
                    "titles": [],
                    "source_urls": [],
                    "confidence_labels": set(),
                    "multi_source": False,
                    "not_identity_proof": True,
                }
                by_ind[key] = ent
            ent["sources"].add(rec.get("source") or "")
            title = rec.get("title")
            if title and title not in ent["titles"] and len(ent["titles"]) < 5:
                ent["titles"].append(title)
            url = rec.get("source_url")
            if url and url not in ent["source_urls"] and len(ent["source_urls"]) < 5:
                ent["source_urls"].append(url)
            if rec.get("confidence"):
                ent["confidence_labels"].add(rec["confidence"])

        entities: list[dict[str, Any]] = []
        for key, ent in by_ind.items():
            sources = sorted(s for s in ent["sources"] if s)
            corr = corr_map.get(key)
            entities.append(
                {
                    "indicator": ent["indicator"],
                    "indicator_type": ent["indicator_type"],
                    "source_count": len(sources),
                    "sources": sources,
                    "titles": ent["titles"],
                    "source_urls": ent["source_urls"],
                    "confidence_labels": sorted(ent["confidence_labels"]),
                    "multi_source": len(sources) >= 2,
                    "correlation": corr is not None,
                    "not_identity_proof": True,
                }
            )
        entities.sort(key=lambda e: (-e["source_count"], e["indicator_type"], e["indicator"]))
        return entities

    def _correlate(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_indicator: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for rec in records:
            ind = (rec.get("indicator") or "").strip().lower()
            if ind:
                by_indicator[ind].append(rec)

        correlations: list[dict[str, Any]] = []
        for ind, group in by_indicator.items():
            sources = sorted({r.get("source", "") for r in group if r.get("source")})
            types = sorted({r.get("indicator_type", "") for r in group if r.get("indicator_type")})
            if len(sources) < 2:
                continue
            correlations.append(
                {
                    "indicator": ind,
                    "indicator_type": group[0].get("indicator_type"),
                    "source_count": len(sources),
                    "observation_count": len(group),
                    "types": types,
                    "sources": sources,
                    "basis": "Same indicator observed under multiple independent source labels",
                    "confidence": "repeated_observation",
                    "not_identity_proof": True,
                    "first_seen": min((r.get("retrieved_at") or "") for r in group),
                    "last_seen": max((r.get("retrieved_at") or "") for r in group),
                }
            )
        correlations.sort(key=lambda c: (-c["source_count"], -c["observation_count"], c["indicator"]))
        return correlations
