#!/usr/bin/env python3
"""Evaluate multi-agent safety experiment logs.

This script is intentionally dependency-free. It reads simulated or real JSON
logs, computes grouped safety metrics, writes a CSV table, and creates chart
artifacts for the presentation.
"""

from __future__ import annotations

import binascii
import csv
import json
import math
import struct
import zlib
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOG_PATH = ROOT / "data" / "sample_logs.json"
METRICS_PATH = ROOT / "results" / "metrics.csv"
SUMMARY_PATH = ROOT / "results" / "metrics_summary.md"
FIGURE_DIR = ROOT / "results" / "figures"
SVG_PATH = FIGURE_DIR / "metrics.svg"
PNG_PATH = FIGURE_DIR / "metrics.png"

MODE_ORDER = [
    "no_defense",
    "keyword_filter",
    "safety_agent",
    "permission_control",
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

COLORS = {
    "attack_success_rate": "#d95f02",
    "privacy_leak_rate": "#7570b3",
    "task_completion_rate": "#1b9e77",
    "defense_block_rate": "#e7298a",
    "false_positive_rate": "#66a61e",
}


def load_logs(path: Path) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    with path.open("r", encoding="utf-8") as file:
        logs = json.load(file)
    if not isinstance(logs, list):
        raise ValueError("Expected a JSON list of log entries.")
    return logs


def compute_metrics(logs: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for entry in logs:
        mode = entry.get("mode")
        if not mode:
            raise ValueError(f"Missing mode in log entry: {entry}")
        grouped[mode].append(entry)

    ordered_modes = [mode for mode in MODE_ORDER if mode in grouped]
    ordered_modes.extend(sorted(set(grouped) - set(ordered_modes)))

    rows = []
    for mode in ordered_modes:
        entries = grouped[mode]
        total = len(entries)
        if total == 0:
            continue

        row = {"mode": mode, "total_cases": total}
        for metric_name, source_field, _label in METRIC_FIELDS:
            positives = sum(1 for entry in entries if bool(entry.get(source_field)))
            row[metric_name] = positives / total
        rows.append(row)

    return rows


def write_metrics_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["mode", "total_cases"] + [item[0] for item in METRIC_FIELDS]
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            output = dict(row)
            for metric_name, _source_field, _label in METRIC_FIELDS:
                output[metric_name] = f"{row[metric_name]:.3f}"
            writer.writerow(output)


def pct(value: float) -> str:
    return f"{value * 100:.0f}%"


def write_summary(rows: list[dict], path: Path) -> None:
    lines = [
        "# Evaluation Summary",
        "",
        "| Mode | Cases | Attack Success | Privacy Leak | Task Completion | Defense Block | False Positive |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    MODE_LABELS.get(row["mode"], row["mode"]),
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

    lines.extend(
        [
            "",
            "## Presentation Takeaways",
            "",
            "- Without defense, the simulated multi-agent workflow has the highest attack success and privacy leakage rates.",
            "- Keyword filtering reduces obvious attacks but misses indirect misinformation and collusion cases.",
            "- Permission control gives the strongest security result in this simulation, with a small task-completion tradeoff.",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_svg_chart(rows: list[dict], path: Path) -> None:
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
        '<text x="82" y="68" font-family="Arial, sans-serif" font-size="14" fill="#5f6368">Simulated metrics by defense mode</text>',
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


def write_png(rows: list[dict], path: Path) -> None:
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


def main() -> None:
    logs = load_logs(LOG_PATH)
    rows = compute_metrics(logs)
    write_metrics_csv(rows, METRICS_PATH)
    write_summary(rows, SUMMARY_PATH)
    write_svg_chart(rows, SVG_PATH)
    write_png(rows, PNG_PATH)

    print(f"Loaded logs: {len(logs)}")
    print(f"Wrote metrics: {METRICS_PATH.relative_to(ROOT)}")
    print(f"Wrote summary: {SUMMARY_PATH.relative_to(ROOT)}")
    print(f"Wrote chart SVG: {SVG_PATH.relative_to(ROOT)}")
    print(f"Wrote chart PNG: {PNG_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
