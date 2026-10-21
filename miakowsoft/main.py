"""miakowsoft entry point. Run with: python main.py"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from miakowsoft import __version__
from miakowsoft.engine import miakowsoftEngine
from miakowsoft.reporting import Reporter
from miakowsoft.security import InputValidationError, normalize_target
from miakowsoft.ui import TerminalUI

REPORTS_DIR = ROOT / "reports"


def load_env_file(path: Path | None = None) -> None:
    file_path = path or ROOT / ".env"
    if not file_path.is_file():
        return
    try:
        for raw in file_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or "=" not in line:
                continue
            if line.startswith(" ") or line.startswith("\t"):
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key.replace("_", "").isalnum():
                os.environ.setdefault(key, value)
    except OSError:
        pass


def save_reports(payload: dict, formats: list[str], ui: TerminalUI | None = None) -> list[Path]:
    reporter = Reporter(REPORTS_DIR)
    saved: list[Path] = []
    for fmt in formats:
        path = reporter.export(payload, "md" if fmt == "markdown" else fmt)
        saved.append(path.resolve())
    if ui:
        for path in saved:
            ui.status(ui.p.ok(f"Saved: {path}"))
    else:
        for path in saved:
            print(f"Saved: {path}")
    print(f"Reports folder: {REPORTS_DIR.resolve()}")
    return saved


def interactive_loop(engine: miakowsoftEngine, ui: TerminalUI) -> None:
    type_map = {
        "1": "domain",
        "2": "ip",
        "3": "email",
        "4": "username",
        "5": "phone",
        "6": "search",
    }
    while True:
        ui.menu()
        try:
            choice = input(ui.p.primary("miakowsoft > ")).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nmiakowsoft closed.")
            return
        if choice in ("0", "exit", "quit", "q"):
            print("miakowsoft closed.")
            return
        if choice == "7" or choice == "list-sources":
            ui.print_catalog(engine.source_catalog())
            continue
        target_type = type_map.get(choice)
        if not target_type:
            print(ui.p.err("Unknown option."))
            continue
        try:
            raw = input(f"Target ({target_type}): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nmiakowsoft closed.")
            return
        if not raw:
            continue
        try:
            target, detected = normalize_target(raw, target_type)
        except InputValidationError as exc:
            print(ui.p.err(str(exc)))
            continue
        engine.set_progress(ui.progress)
        try:
            payload = engine.investigate(target, detected)
        except KeyboardInterrupt:
            print(ui.p.warn("\nInvestigation cancelled."))
            continue
        finally:
            engine.set_progress(None)
        ui.print_payload(payload)
        save_reports(payload, ["json"], ui)
        try:
            extra = input("Extra export? [md/txt/csv/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            continue
        if extra in ("md", "txt", "csv", "markdown"):
            save_reports(payload, [extra], ui)


def main() -> int:
    load_env_file()
    parser = argparse.ArgumentParser(description="miakowsoft — modular public-source OSINT.")
    parser.add_argument("--version", action="version", version=f"miakowsoft {__version__}")
    parser.add_argument("--target", help="Investigation target")
    parser.add_argument("--type", dest="target_type", default="auto", help="domain|ip|email|phone|username|search|auto")
    parser.add_argument("--export", choices=["json", "md", "txt", "csv", "markdown"], help="Extra export format (JSON always saved)")
    parser.add_argument("--depth", type=int, default=0, help="Pivot depth 0-2 (default 0 for speed)")
    parser.add_argument("--fast", action="store_true", help="Skip slow sources (wayback, anubis, bufferover, crtsh, otx_passive_dns)")
    parser.add_argument("--list-sources", action="store_true", help="List registered sources")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--reports-dir", help="Override reports directory path")
    args = parser.parse_args()

    global REPORTS_DIR
    if args.reports_dir:
        REPORTS_DIR = Path(args.reports_dir).expanduser().resolve()

    if args.no_color:
        os.environ["QT_NO_COLOR"] = "1"
    if args.fast:
        os.environ["QT_FAST"] = "1"

    ui = TerminalUI()
    engine = miakowsoftEngine()

    if args.list_sources:
        ui.banner()
        ui.print_catalog(engine.source_catalog())
        return 0

    if args.target:
        try:
            target, detected = normalize_target(args.target, args.target_type)
        except InputValidationError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        ui.banner()
        engine.set_progress(ui.progress)
        try:
            depth = max(0, min(int(args.depth), 2))
            payload = engine.investigate(target, detected, depth=depth)
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 130
        finally:
            engine.set_progress(None)
        ui.print_payload(payload)
        formats = ["json"]
        if args.export and args.export != "json":
            formats.append(args.export)
        save_reports(payload, formats, ui)
        return 0

    ui.banner()
    print(ui.p.muted(f"Reports will be saved to: {REPORTS_DIR.resolve()}"))
    interactive_loop(engine, ui)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nmiakowsoft closed.")
        raise SystemExit(130)
