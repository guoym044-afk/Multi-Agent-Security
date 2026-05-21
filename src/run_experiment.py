"""Run the B-role multi-agent safety demo and export structured logs."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Iterable, List

from agents import DefenseMode, MultiAgentDemo, default_attack_cases


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
RESULTS_DIR = PROJECT_ROOT / "results"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Multi-agent security demo for role B.")
    parser.add_argument(
        "--mode",
        choices=["no_defense", "simple_defense", "keyword_filter", "safety_agent", "permission_control", "all"],
        default="all",
        help="Defense mode to run. simple_defense is an alias of keyword_filter.",
    )
    parser.add_argument(
        "--output",
        default=str(DATA_DIR / "b_demo_full_logs.json"),
        help="Path for detailed B demo JSON logs.",
    )
    parser.add_argument(
        "--sample-logs",
        default=str(DATA_DIR / "sample_logs.json"),
        help="Path for evaluator-compatible compact logs.",
    )
    parser.add_argument(
        "--metrics",
        default=str(RESULTS_DIR / "b_demo_metrics.csv"),
        help="Path for a compact CSV metrics table.",
    )
    return parser.parse_args()


def selected_modes(mode: str) -> List[DefenseMode]:
    if mode == "all":
        return ["no_defense", "keyword_filter", "safety_agent", "permission_control"]
    return [mode]  # type: ignore[list-item]


def run_modes(modes: Iterable[DefenseMode]) -> List[dict]:
    results: List[dict] = []
    for mode in modes:
        demo = MultiAgentDemo(mode)
        for case in default_attack_cases():
            results.append(demo.run_case(case))
    return results


def flatten_logs(results: Iterable[dict]) -> List[dict]:
    logs: List[dict] = []
    for result in results:
        logs.extend(result["logs"])
    return logs


def build_metrics(results: Iterable[dict]) -> List[dict]:
    by_mode: dict[str, dict[str, int]] = {}
    for result in results:
        mode = result["mode"]
        stats = by_mode.setdefault(
            mode,
            {"cases": 0, "attack_success": 0, "blocked_messages": 0, "messages": 0},
        )
        stats["cases"] += 1
        stats["attack_success"] += int(result["attack_success"])
        stats["messages"] += len(result["logs"])
        stats["blocked_messages"] += sum(1 for item in result["logs"] if item["blocked"])

    rows = []
    for mode, stats in by_mode.items():
        rows.append(
            {
                "mode": mode,
                "cases": stats["cases"],
                "attack_success_rate": round(stats["attack_success"] / stats["cases"], 3),
                "defense_block_rate": round(stats["blocked_messages"] / stats["messages"], 3),
                "blocked_messages": stats["blocked_messages"],
                "messages": stats["messages"],
            }
        )
    return rows


def build_evaluation_logs(results: Iterable[dict]) -> List[dict]:
    logs = []
    for result in results:
        final_output = result["final_output"]
        logs.append(
            {
                "case_id": result["case_id"],
                "category": result["category"],
                "mode": result["mode"],
                "blocked": any(item["blocked"] for item in result["logs"]),
                "attack_success": result["attack_success"],
                "privacy_leak": result["secret"] in final_output,
                "task_completed": bool(final_output.strip()),
                "false_positive": False,
            }
        )
    return logs


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    args = parse_args()
    modes = selected_modes(args.mode)
    results = run_modes(modes)
    logs = flatten_logs(results)
    metrics = build_metrics(results)
    evaluation_logs = build_evaluation_logs(results)

    write_json(
        Path(args.output),
        {
            "description": "B 模块多智能体 Demo 结构化日志，包含无防御和多种轻量防御模式。",
            "cases": [case.__dict__ for case in default_attack_cases()],
            "runs": results,
            "logs": logs,
        },
    )
    write_json(Path(args.sample_logs), evaluation_logs)
    write_csv(Path(args.metrics), metrics)

    print("Multi-agent security demo finished.")
    print(f"Cases: {len(default_attack_cases())}; runs: {len(results)}; log entries: {len(logs)}")
    for row in metrics:
        print(
            f"- {row['mode']}: attack_success_rate={row['attack_success_rate']}, "
            f"defense_block_rate={row['defense_block_rate']}"
        )
    print(f"Detailed JSON logs: {Path(args.output)}")
    print(f"Evaluator-compatible logs: {Path(args.sample_logs)}")
    print(f"Metrics: {Path(args.metrics)}")


if __name__ == "__main__":
    main()
