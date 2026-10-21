"""Terminal presentation for miakowsoft."""

from __future__ import annotations

import os
import shutil
import sys
from typing import Any


def color_enabled() -> bool:
    if os.getenv("NO_COLOR") or os.getenv("QT_NO_COLOR"):
        return False
    return sys.stdout.isatty()


class Palette:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _c(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def primary(self, text: str) -> str:
        return self._c("36", text)

    def gold(self, text: str) -> str:
        return self._c("33", text)

    def muted(self, text: str) -> str:
        return self._c("90", text)

    def ok(self, text: str) -> str:
        return self._c("32", text)

    def warn(self, text: str) -> str:
        return self._c("33", text)

    def err(self, text: str) -> str:
        return self._c("31", text)

    def bold(self, text: str) -> str:
        return self._c("1", text)


class TerminalUI:
    def __init__(self) -> None:
        self.p = Palette(color_enabled())
        self.width = min(shutil.get_terminal_size((80, 24)).columns, 96)


    def banner(self) -> None:
        line = "─" * min(self.width, 56)
        art = r"""
                                                                                        ▄▄                       ▄▄
  ▄▄▄▄▄   ▄▄▄    ▄██▄▄   ▄▄▄▄▄▄    ▄▄▄▄   ▄▄▄    ▄▄▄▄▄▄      ▄▄  ▄    ▄▄           ▄▄▄▄███     ▄▄▄▄▄▄      ▄▄▄▄▄███ ▄▄▄▄▄▄▄▄▄▄▄▄▄
▄█▓▓█▀█▄▄██▀█▄▄  ▀█▓▀▀ ▄█▓▓▀▀▓█▄▄  ██▓█   ████ ▄█▓▓▀▀▓█▄▄  ▄█▓█  █▄▄  ▓█▄▄       ▄███▀▀███   ▄█▓▓▀▀▓█▄▄  ▄█▓▓▀▀▀███ ░▒▀██▓▓▀▀▀███
█▓▒▀▀ ░██▀▀ ░▒▄▄       █▓▒█   ▓▒▄▄ █▓▒█  ▄▓▒██ █▓▒█   ░▒▄▄ █▓▒█  ▒▒▄▄  ░▒▄▄      ▀██▄▄▄▄▓▄▄  █▓▒█   ░▒▄▄ █▓▒█ ▄▄ ▀▀    █▓▒█    ▀▀
▓▒██  ▒▓▓█  ▒░▓█    ▄▄ ▓▒░░▒▓▓██▓█ ▓▒░░▒▓▓█▀▀  ▓▒▌▌   ░░▓█ ▓▒░█  ▒░▓█  ░░▓█        ▀▀▀▀▀▓▓▓█ ▓▒▌▌   ░░▓█ ▓▒░▒▓██       ▓▒░█
▒░██  ░▒▓█  ░▒▓█  ▄███ ▒░██   ▓▒▓█ ▒░██  ▓▓▄▄  ▒░██   ▓▒▓█ ▒░██  ░▒▓█  ▓▒▓█              ░▒█ ▒░██   ▓▒▓█ ▒░██ ▀▀       ▒░██
░███  ░░██  ░░██  ██▐▌ ░███  ▐▒▒█  ░███  ░▒▒▌▌ ░██▀▄▄▄░░█  ░██▀▄▀░▒▒▄▄░▒▓█       ░▄    ▄░░▄▀ ░██▀▄▄▄░░█  ░███          ░███
████  ░▒▓█  ░▒▓█  ▐██   ▀██  █░▒█  ▓▓██  ░░▒█   ▀█████▄▀    ▀████▄▀▀▒▒▓▀▀        ██████░▄▀    ▀█████▄▀   ▀███          ▀███
                                                                                 █▄▀                       ▀             ▀
"""
        print()
        print(self.p.primary(line))
        print(f"\033[1;35m{art}\033[0m")
        print(self.p.muted("  v1.0 miakowsoft"))
        print(self.p.primary(line))
        print()


    def menu(self) -> None:
        items = [
            ("1", "domain", "DNS, RDAP, CT, archives, reputation"),
            ("2", "ip", "Geolocation, ASN, BGP, OTX"),
            ("3", "email", "Syntax, MX, Gravatar, GitHub search"),
            ("4", "username", "GitHub, GitLab, HN, archives, search"),
            ("5", "phone", "Local normalization"),
            ("6", "search", "Web mentions via DuckDuckGo and HN"),
            ("7", "list-sources", "Show registered public sources"),
            ("0", "exit", "Quit"),
        ]
        print(self.p.bold("Select target type"))
        for key, name, desc in items:
            print(f"  {self.p.primary('[' + key + ']')}  {self.p.bold(name):<14}  {self.p.muted(desc)}")
        print()

    def status(self, message: str) -> None:
        print(self.p.muted(message))

    def progress(self, message: str) -> None:
        print(self.p.primary("  · " + message))

    def print_payload(self, payload: dict[str, Any]) -> None:
        print()
        print(self.p.bold(f"Target: {payload.get('target')}  |  Type: {payload.get('target_type')}"))
        print(self.p.muted(f"Elapsed: {payload.get('elapsed_ms')} ms  |  Records: {len(payload.get('records') or [])}"))
        print("─" * min(self.width, 72))
        for source in payload.get("sources") or []:
            status = source.get("status", "")
            duration = f"{source.get('duration_ms', 0)} ms"
            detail = ""
            if source.get("error"):
                detail = " — " + source["error"]
            elif source.get("note"):
                detail = " — " + source["note"]
            color = self.p.ok if status == "ok" else self.p.warn if status in ("empty", "skipped") else self.p.err
            print(f"{color('[' + status + ']')} {source.get('source')}: {source.get('count')} result(s), {duration}{detail}")
        print()
        print(self.p.bold("Findings"))
        print("─" * min(self.width, 72))
        records = payload.get("records") or []
        if not records:
            print(self.p.muted("  No public observations returned."))
        for index, row in enumerate(records, 1):
            title = (
                row.get("title")
                or row.get("domain")
                or row.get("ip")
                or row.get("username")
                or row.get("indicator")
                or "Observation"
            )
            print(f"{index:>3}. {title}")
            if row.get("source"):
                print(f"     Source: {row['source']}")
            if row.get("source_url"):
                url = row["source_url"]
                if len(url) > self.width - 12:
                    url = url[: self.width - 15] + "..."
                print(f"     URL: {url}")
            if row.get("evidence"):
                print(f"     Evidence: {row['evidence']}")
            if row.get("confidence"):
                print(f"     Confidence: {row['confidence']}")
            if row.get("retrieved_at"):
                print(f"     Retrieved: {row['retrieved_at']}")
        corrs = payload.get("correlations") or []
        if corrs:
            print()
            print(self.p.bold("Correlations (repeated observations, not identity proof)"))
            print("─" * min(self.width, 72))
            for c in corrs[:30]:
                print(f"  · {c.get('indicator')}  sources={', '.join(c.get('sources') or [])}")
        entities = payload.get("entities") or []
        multi = [e for e in entities if e.get("multi_source")]
        if multi:
            print()
            print(self.p.bold("Entities with multi-source support"))
            print("─" * min(self.width, 72))
            for e in multi[:20]:
                print(
                    f"  · [{e.get('indicator_type')}] {e.get('indicator')}  "
                    f"sources={e.get('source_count')} ({', '.join(e.get('sources') or [])})"
                )
        pivots = payload.get("pivots") or []
        if pivots:
            print()
            print(self.p.bold("Pivot chain"))
            print("─" * min(self.width, 72))
            for p in pivots[:25]:
                print(f"  · {p.get('from')} -> {p.get('to')} ({p.get('to_type')}) depth={p.get('depth')}")
        summary = payload.get("summary") or {}
        if summary.get("targets_investigated"):
            print(self.p.muted(
                f"  targets={summary.get('targets_investigated')} pivots={summary.get('pivot_steps')} "
                f"entities={summary.get('entities')} depth={summary.get('max_depth')}"
            ))
        for note in payload.get("notes") or []:
            print(self.p.muted("  note: " + note))
        print()

    def print_catalog(self, catalog: list[dict[str, Any]]) -> None:
        print()
        print(self.p.bold("miakowsoft — source registry"))
        print("─" * min(self.width, 72))
        for source in catalog:
            status = source.get("status", "ready")
            cats = ", ".join(source.get("categories") or [])
            print(f"[{status}] {source.get('name')} [{cats}]")
            print(f"  {source.get('description')}")
            if source.get("documentation_url"):
                print(f"  Docs: {source.get('documentation_url')}")
        print()
