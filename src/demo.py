#!/usr/bin/env python3
"""Backward-compatible entrypoint for the B demo pipeline.

The project-facing files now use the screenshot naming:
`agents.py` contains the agent logic and `run_experiment.py` generates logs.
This module remains so older commands such as `python3 src/demo.py` keep working.
"""

from __future__ import annotations

from agents import MODES, generate_logs, run_case, task_completed
from run_experiment import load_cases, main, write_logs


__all__ = [
    "MODES",
    "generate_logs",
    "load_cases",
    "main",
    "run_case",
    "task_completed",
    "write_logs",
]


if __name__ == "__main__":
    main()
