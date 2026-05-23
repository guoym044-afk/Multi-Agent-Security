#!/usr/bin/env python3
"""Regression tests for the demo and evaluator pipeline."""

from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import agents  # noqa: E402
import evaluate  # noqa: E402
import run_experiment  # noqa: E402


class PipelineTests(unittest.TestCase):
    def load_demo_logs(self) -> list[dict]:
        attack_cases = run_experiment.load_cases(ROOT / "data" / "attack_cases.json")
        benign_cases = run_experiment.load_cases(ROOT / "data" / "benign_cases.json")
        return agents.generate_logs(attack_cases, benign_cases)

    def test_demo_generates_attack_and_benign_logs(self) -> None:
        logs = self.load_demo_logs()
        evaluate.validate_logs(logs)

        self.assertEqual(len(logs), (20 + 6) * len(agents.MODES))
        self.assertTrue(any(entry["is_attack"] for entry in logs))
        self.assertTrue(any(not entry["is_attack"] for entry in logs))
        self.assertTrue(
            any(
                entry["mode"] == "keyword_filter"
                and entry["case_type"] == "benign"
                and entry["false_positive"]
                for entry in logs
            )
        )
        self.assertFalse(
            any(
                entry["mode"] == "permission_control"
                and entry["case_type"] == "benign"
                and entry["blocked"]
                for entry in logs
            )
        )

    def test_evaluator_writes_category_and_failure_outputs(self) -> None:
        logs = self.load_demo_logs()

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            input_path = tmp_path / "logs.json"
            output_dir = tmp_path / "results"
            metrics_alias = tmp_path / "b_demo_metrics.csv"
            input_path.write_text(
                json.dumps(logs, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            evaluate.run(input_path, output_dir, metrics_alias)

            expected_files = [
                output_dir / "metrics.csv",
                output_dir / "category_metrics.csv",
                output_dir / "failure_cases.csv",
                output_dir / "metrics_summary.md",
                output_dir / "figures" / "metrics.svg",
                output_dir / "figures" / "metrics.png",
                metrics_alias,
            ]
            for path in expected_files:
                self.assertTrue(path.exists(), f"missing output: {path}")

            with (output_dir / "metrics.csv").open(newline="", encoding="utf-8") as file:
                mode_rows = {row["mode"]: row for row in csv.DictReader(file)}
            self.assertEqual(mode_rows["keyword_filter"]["false_positive_rate"], "0.500")

            with (output_dir / "category_metrics.csv").open(
                newline="", encoding="utf-8"
            ) as file:
                category_rows = {row["category"]: row for row in csv.DictReader(file)}
            self.assertIn("benign", category_rows)

            with (output_dir / "failure_cases.csv").open(
                newline="", encoding="utf-8"
            ) as file:
                failure_rows = list(csv.DictReader(file))
            self.assertTrue(
                any(
                    row["case_type"] == "benign"
                    and "false_positive" in row["failure_tags"]
                    for row in failure_rows
                )
            )

    def test_validator_rejects_missing_required_field(self) -> None:
        bad_log = {
            "case_id": "bad_001",
            "category": "benign",
            "mode": "keyword_filter",
            "blocked": False,
            "attack_success": False,
            "privacy_leak": False,
            "task_completed": True,
        }

        with self.assertRaisesRegex(ValueError, "missing required field"):
            evaluate.validate_logs([bad_log])


if __name__ == "__main__":
    unittest.main()
