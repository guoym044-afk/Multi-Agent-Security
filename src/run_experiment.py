#!/usr/bin/env python3
"""Generate deterministic multi-agent security experiment logs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agents import generate_logs


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES_PATH = ROOT / "data" / "attack_cases.json"
DEFAULT_BENIGN_CASES_PATH = ROOT / "data" / "benign_cases.json"
DEFAULT_OUTPUT_PATH = ROOT / "data" / "b_demo_full_logs.json"
DEFAULT_SAMPLE_LOG_PATH = ROOT / "data" / "sample_logs.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate deterministic logs from attack and benign case libraries."
    )
    parser.add_argument(
        "--cases",
        type=Path,
        default=DEFAULT_CASES_PATH,
        help="Attack case JSON file. Defaults to data/attack_cases.json.",
    )
    parser.add_argument(
        "--benign-cases",
        type=Path,
        default=DEFAULT_BENIGN_CASES_PATH,
        help="Benign control case JSON file. Defaults to data/benign_cases.json.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="Output JSON log path. Defaults to data/b_demo_full_logs.json.",
    )
    parser.add_argument(
        "--sample-logs",
        type=Path,
        default=DEFAULT_SAMPLE_LOG_PATH,
        help="Evaluator-compatible copy. Defaults to data/sample_logs.json.",
    )
    return parser.parse_args()


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


def load_cases(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Case file not found: {path}")
    with path.open("r", encoding="utf-8") as file:
        cases = json.load(file)
    if not isinstance(cases, list):
        raise ValueError("Expected a JSON list of cases.")
    return cases


def write_logs(logs: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(logs, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    args = parse_args()
    try:
        attack_cases = load_cases(args.cases)
        benign_cases = load_cases(args.benign_cases)
        logs = generate_logs(attack_cases, benign_cases)
        write_logs(logs, args.output)
        if args.sample_logs != args.output:
            write_logs(logs, args.sample_logs)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Error: {exc}") from exc

    print(f"Loaded attack cases: {len(attack_cases)}")
    print(f"Loaded benign cases: {len(benign_cases)}")
    print(f"Generated experiment logs: {len(logs)}")
    print(f"Wrote log file: {display_path(args.output)}")
    if args.sample_logs != args.output:
        print(f"Wrote evaluator-compatible logs: {display_path(args.sample_logs)}")


if __name__ == "__main__":
    main()
