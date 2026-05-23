#!/usr/bin/env python3
"""Evaluate multi-agent safety experiment logs.

The evaluator is dependency-free. It validates JSON logs, computes metrics by
defense mode and attack category, writes CSV/Markdown artifacts, and creates a
simple chart for presentation use.
"""

from __future__ import annotations

import argparse
import binascii
import csv
import json
import struct
import zlib
from collections import defaultdict
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG_PATH = ROOT / "data" / "sample_logs.json"
DEFAULT_OUTPUT_DIR = ROOT / "results"

MODE_ORDER = [
    "no_defense",
    "keyword_filter",
    "safety_agent",
    "permission_control",
]

CATEGORY_ORDER = [
    "benign",
    "privacy_leakage",
    "prompt_injection",
    "misinformation",
    "review_bypass",
    "collusion",
]

MODE_LABELS = {
    "no_defense": "No defense",
    "keyword_filter": "Keyword filter",
    "safety_agent": "Safety agent",
    "permission_control": "Permission control",
}

METRIC_FIELDS = [
    ("attack_success_rate", "attack_success", "Attack success"),
    ("privacy_leak_rate", "privacy_leak", "Privacy leak"),
    ("task_completion_rate", "task_completed", "Task completion"),
    ("defense_block_rate", "blocked", "Defense block"),
    ("false_positive_rate", "false_positive", "False positive"),
]

REQUIRED_FIELDS = {
    "case_id": str,
    "category": str,
    "mode": str,
    "blocked": bool,
    "attack_success": bool,
    "privacy_leak": bool,
    "task_completed": bool,
    "false_positive": bool,
}

CASE_TYPE_FIELDS = {
    "is_attack": bool,
}

COLORS = {
    "attack_success_rate": "#d95f02",
    "privacy_leak_rate": "#7570b3",
    "task_completion_rate": "#1b9e77",
    "defense_block_rate": "#e7298a",
    "false_positive_rate": "#66a61e",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate multi-agent safety logs and generate result artifacts."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help="JSON log file to evaluate. Defaults to data/sample_logs.json.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for CSV, Markdown, SVG, and PNG outputs. Defaults to results/.",
    )
    parser.add_argument(
        "--metrics-alias",
        type=Path,
        default=None,
        help=(
            "Optional extra copy of the mode metrics CSV, resolved from the "
            "repository root when relative."
        ),
    )
    return parser.parse_args()


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


def load_logs(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    with path.open("r", encoding="utf-8") as file:
        logs = json.load(file)
    if not isinstance(logs, list):
        raise ValueError("Expected a JSON list of log entries.")
    return logs


def validate_logs(logs: list[dict[str, Any]]) -> None:
    for index, entry in enumerate(logs, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"Log entry #{index} must be a JSON object.")

        missing = sorted(field for field in REQUIRED_FIELDS if field not in entry)
        if missing:
            case_label = entry.get("case_id", f"entry #{index}")
            raise ValueError(
                f"{case_label} is missing required field(s): {', '.join(missing)}"
            )

        for field, expected_type in REQUIRED_FIELDS.items():
            value = entry[field]
            if not isinstance(value, expected_type):
                case_label = entry.get("case_id", f"entry #{index}")
                expected_name = expected_type.__name__
                actual_name = type(value).__name__
                raise ValueError(
                    f"{case_label}.{field} must be {expected_name}, got {actual_name}."
                )

        for field, expected_type in CASE_TYPE_FIELDS.items():
            if field not in entry:
                continue
            value = entry[field]
            if not isinstance(value, expected_type):
                case_label = entry.get("case_id", f"entry #{index}")
                expected_name = expected_type.__name__
                actual_name = type(value).__name__
                raise ValueError(
                    f"{case_label}.{field} must be {expected_name}, got {actual_name}."
                )


def metric_entries(
    entries: list[dict[str, Any]], metric_name: str
) -> list[dict[str, Any]]:
    has_case_type = any("is_attack" in entry for entry in entries)
    if not has_case_type:
        return entries

    if metric_name in {"attack_success_rate", "privacy_leak_rate"}:
        return [entry for entry in entries if entry.get("is_attack", True)]
    if metric_name == "false_positive_rate":
        return [entry for entry in entries if entry.get("is_attack") is False]
    return entries


def compute_grouped_metrics(
    logs: list[dict[str, Any]], group_field: str, preferred_order: Optional[list[str]] = None
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in logs:
        grouped[entry[group_field]].append(entry)

    ordered_groups: list[str] = []
    if preferred_order:
        ordered_groups.extend(group for group in preferred_order if group in grouped)
    ordered_groups.extend(sorted(set(grouped) - set(ordered_groups)))

    rows: list[dict[str, Any]] = []
    for group in ordered_groups:
        entries = grouped[group]
        total = len(entries)
        if total == 0:
            continue

        row: dict[str, Any] = {group_field: group, "total_cases": total}
        for metric_name, source_field, _label in METRIC_FIELDS:
            denominator_entries = metric_entries(entries, metric_name)
            denominator = len(denominator_entries)
            positives = sum(1 for entry in denominator_entries if entry[source_field])
            row[metric_name] = positives / denominator if denominator else 0.0
        rows.append(row)

    return rows


def failure_tags(entry: dict[str, Any]) -> list[str]:
    tags = []
    if entry["attack_success"]:
        tags.append("attack_success")
    if entry["privacy_leak"]:
        tags.append("privacy_leak")
    if entry["false_positive"]:
        tags.append("false_positive")
    if not entry["task_completed"]:
        tags.append("task_not_completed")
    return tags


def find_failure_cases(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failures = []
    for entry in logs:
        tags = failure_tags(entry)
        if tags:
            output = dict(entry)
            output["failure_tags"] = ",".join(tags)
            failures.append(output)
    return failures


def write_metrics_csv(rows: list[dict[str, Any]], path: Path, group_field: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [group_field, "total_cases"] + [item[0] for item in METRIC_FIELDS]
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            output = dict(row)
            for metric_name, _source_field, _label in METRIC_FIELDS:
                output[metric_name] = f"{row[metric_name]:.3f}"
            writer.writerow(output)


def write_failure_cases_csv(failures: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "mode",
        "category",
        "case_id",
        "case_type",
        "failure_tags",
        "blocked",
        "task_completed",
        "blocked_reason",
    ]
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        for failure in failures:
            writer.writerow(failure)


def pct(value: float) -> str:
    return f"{value * 100:.0f}%"


def label_for(group_field: str, value: str) -> str:
    if group_field == "mode":
        return MODE_LABELS.get(value, value)
    return value


def append_metrics_table(
    lines: list[str],
    title: str,
    rows: list[dict[str, Any]],
    group_field: str,
    first_column_label: str,
) -> None:
    lines.extend(
        [
            f"## {title}",
            "",
            f"| {first_column_label} | Cases | Attack Success | Privacy Leak | Task Completion | Defense Block | False Positive |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    label_for(group_field, row[group_field]),
                    str(row["total_cases"]),
                    pct(row["attack_success_rate"]),
                    pct(row["privacy_leak_rate"]),
                    pct(row["task_completion_rate"]),
                    pct(row["defense_block_rate"]),
                    pct(row["false_positive_rate"]),
                ]
            )
            + " |"
        )
    lines.append("")


def write_summary(
    mode_rows: list[dict[str, Any]],
    category_rows: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    source_path: Path,
    output_dir: Path,
) -> None:
    failure_csv = output_dir / "failure_cases.csv"
    lines = [
        "# Evaluation Summary",
        "",
        f"Source log: `{display_path(source_path)}`",
        "",
    ]

    append_metrics_table(lines, "Defense Mode Metrics", mode_rows, "mode", "Mode")
    append_metrics_table(lines, "Case Category Metrics", category_rows, "category", "Category")

    lines.extend(["## Failure Cases", ""])
    if failures:
        lines.append(
            "| Mode | Category | Case | Failure Tags | Blocked | Task Completed |"
        )
        lines.append("|---|---|---|---|---:|---:|")
        for failure in failures[:20]:
            lines.append(
                "| "
                + " | ".join(
                    [
                        label_for("mode", failure["mode"]),
                        failure["category"],
                        failure["case_id"],
                        failure["failure_tags"],
                        str(failure["blocked"]),
                        str(failure["task_completed"]),
                    ]
                )
                + " |"
            )
        if len(failures) > 20:
            remaining = len(failures) - 20
            lines.append("")
            lines.append(
                f"{remaining} additional failure case(s) are available in `{display_path(failure_csv)}`."
            )
    else:
        lines.append("No attack successes, privacy leaks, false positives, or task failures were found.")

    lines.extend(
        [
            "",
            "## Presentation Takeaways",
            "",
            "- Compare defense modes first, then use the category breakdown to explain which attack types remain difficult.",
            "- Use benign control cases to make false positives explicit instead of inferring them only from attack runs.",
            "- Use the failure-case table to show concrete examples that bypassed a defense or harmed task completion.",
            "- Treat simulated logs and demo-generated logs separately when presenting results.",
        ]
    )

    summary_path = output_dir / "metrics_summary.md"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_svg_chart(rows: list[dict[str, Any]], path: Path) -> None:
    width = 1180
    height = 680
    margin_left = 82
    margin_right = 28
    margin_top = 82
    margin_bottom = 140
    plot_width = width - margin_left - margin_right
    plot_height = height - margin_top - margin_bottom
    group_width = plot_width / max(len(rows), 1)
    bar_gap = 4
    bar_width = (group_width * 0.72) / len(METRIC_FIELDS)

    elements = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        '<text x="82" y="42" font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#202124">Multi-Agent Safety Evaluation</text>',
        '<text x="82" y="68" font-family="Arial, sans-serif" font-size="14" fill="#5f6368">Metrics by defense mode</text>',
    ]

    for tick in range(0, 101, 20):
        y = margin_top + plot_height - (tick / 100) * plot_height
        elements.append(
            f'<line x1="{margin_left}" y1="{y:.1f}" x2="{width - margin_right}" y2="{y:.1f}" stroke="#e8eaed" stroke-width="1"/>'
        )
        elements.append(
            f'<text x="{margin_left - 12}" y="{y + 5:.1f}" font-family="Arial, sans-serif" font-size="12" text-anchor="end" fill="#5f6368">{tick}%</text>'
        )

    elements.append(
        f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + plot_height}" stroke="#3c4043" stroke-width="1.2"/>'
    )
    elements.append(
        f'<line x1="{margin_left}" y1="{margin_top + plot_height}" x2="{width - margin_right}" y2="{margin_top + plot_height}" stroke="#3c4043" stroke-width="1.2"/>'
    )

    for mode_index, row in enumerate(rows):
        group_x = margin_left + mode_index * group_width + group_width * 0.14
        for metric_index, (metric_name, _source_field, _label) in enumerate(METRIC_FIELDS):
            value = row[metric_name]
            bar_h = value * plot_height
            x = group_x + metric_index * (bar_width + bar_gap)
            y = margin_top + plot_height - bar_h
            elements.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" height="{bar_h:.1f}" rx="2" fill="{COLORS[metric_name]}"/>'
            )
            elements.append(
                f'<text x="{x + bar_width / 2:.1f}" y="{y - 5:.1f}" font-family="Arial, sans-serif" font-size="10" text-anchor="middle" fill="#3c4043">{pct(value)}</text>'
            )

        label_x = margin_left + mode_index * group_width + group_width / 2
        elements.append(
            f'<text x="{label_x:.1f}" y="{margin_top + plot_height + 28}" font-family="Arial, sans-serif" font-size="13" text-anchor="middle" fill="#202124">{MODE_LABELS.get(row["mode"], row["mode"])}</text>'
        )

    legend_x = margin_left
    legend_y = height - 74
    for index, (metric_name, _source_field, label) in enumerate(METRIC_FIELDS):
        x = legend_x + index * 205
        elements.append(
            f'<rect x="{x}" y="{legend_y}" width="14" height="14" rx="2" fill="{COLORS[metric_name]}"/>'
        )
        elements.append(
            f'<text x="{x + 20}" y="{legend_y + 12}" font-family="Arial, sans-serif" font-size="13" fill="#3c4043">{label}</text>'
        )

    elements.append("</svg>")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(elements) + "\n", encoding="utf-8")


def hex_to_rgb(color: str) -> tuple[int, int, int]:
    color = color.lstrip("#")
    return tuple(int(color[i : i + 2], 16) for i in (0, 2, 4))


def write_png(rows: list[dict[str, Any]], path: Path) -> None:
    width = 1180
    height = 680
    pixels = bytearray([255, 255, 255] * width * height)

    def set_pixel(x: int, y: int, rgb: tuple[int, int, int]) -> None:
        if 0 <= x < width and 0 <= y < height:
            offset = (y * width + x) * 3
            pixels[offset : offset + 3] = bytes(rgb)

    def rect(x: int, y: int, w: int, h: int, rgb: tuple[int, int, int]) -> None:
        for yy in range(max(y, 0), min(y + h, height)):
            row_start = (yy * width + max(x, 0)) * 3
            row_end = (yy * width + min(x + w, width)) * 3
            pixels[row_start:row_end] = bytes(rgb) * max(0, min(x + w, width) - max(x, 0))

    def hline(x1: int, x2: int, y: int, rgb: tuple[int, int, int]) -> None:
        for x in range(x1, x2 + 1):
            set_pixel(x, y, rgb)

    def vline(x: int, y1: int, y2: int, rgb: tuple[int, int, int]) -> None:
        for y in range(y1, y2 + 1):
            set_pixel(x, y, rgb)

    margin_left = 82
    margin_right = 28
    margin_top = 82
    margin_bottom = 140
    plot_width = width - margin_left - margin_right
    plot_height = height - margin_top - margin_bottom
    group_width = plot_width / max(len(rows), 1)
    bar_gap = 4
    bar_width = int((group_width * 0.72) / len(METRIC_FIELDS))

    grid = (232, 234, 237)
    axis = (60, 64, 67)
    for tick in range(0, 101, 20):
        y = int(margin_top + plot_height - (tick / 100) * plot_height)
        hline(margin_left, width - margin_right, y, grid)
    vline(margin_left, margin_top, margin_top + plot_height, axis)
    hline(margin_left, width - margin_right, margin_top + plot_height, axis)

    for mode_index, row in enumerate(rows):
        group_x = margin_left + mode_index * group_width + group_width * 0.14
        for metric_index, (metric_name, _source_field, _label) in enumerate(METRIC_FIELDS):
            value = row[metric_name]
            bar_h = int(value * plot_height)
            x = int(group_x + metric_index * (bar_width + bar_gap))
            y = margin_top + plot_height - bar_h
            rect(x, int(y), bar_width, bar_h, hex_to_rgb(COLORS[metric_name]))

    raw_rows = []
    for y in range(height):
        start = y * width * 3
        raw_rows.append(b"\x00" + bytes(pixels[start : start + width * 3]))
    raw = b"".join(raw_rows)

    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + chunk_type
            + data
            + struct.pack(">I", binascii.crc32(chunk_type + data) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, level=9))
    png += chunk(b"IEND", b"")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)


def run(input_path: Path, output_dir: Path, metrics_alias: Optional[Path] = None) -> None:
    logs = load_logs(input_path)
    validate_logs(logs)

    mode_rows = compute_grouped_metrics(logs, "mode", MODE_ORDER)
    category_rows = compute_grouped_metrics(logs, "category", CATEGORY_ORDER)
    failures = find_failure_cases(logs)

    metrics_path = output_dir / "metrics.csv"
    category_metrics_path = output_dir / "category_metrics.csv"
    failure_cases_path = output_dir / "failure_cases.csv"
    svg_path = output_dir / "figures" / "metrics.svg"
    png_path = output_dir / "figures" / "metrics.png"

    write_metrics_csv(mode_rows, metrics_path, "mode")
    if metrics_alias:
        alias_path = metrics_alias if metrics_alias.is_absolute() else ROOT / metrics_alias
        write_metrics_csv(mode_rows, alias_path, "mode")
    write_metrics_csv(category_rows, category_metrics_path, "category")
    write_failure_cases_csv(failures, failure_cases_path)
    write_summary(mode_rows, category_rows, failures, input_path, output_dir)
    write_svg_chart(mode_rows, svg_path)
    write_png(mode_rows, png_path)

    print(f"Loaded and validated logs: {len(logs)}")
    print(f"Wrote mode metrics: {display_path(metrics_path)}")
    if metrics_alias:
        print(f"Wrote mode metrics alias: {display_path(alias_path)}")
    print(f"Wrote category metrics: {display_path(category_metrics_path)}")
    print(f"Wrote failure cases: {display_path(failure_cases_path)}")
    print(f"Wrote summary: {display_path(output_dir / 'metrics_summary.md')}")
    print(f"Wrote chart SVG: {display_path(svg_path)}")
    print(f"Wrote chart PNG: {display_path(png_path)}")


def main() -> None:
    args = parse_args()
    try:
        run(args.input, args.output_dir, args.metrics_alias)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Error: {exc}") from exc


if __name__ == "__main__":
    main()
