# Multi-Agent Security

A course practice project for **AI Safety and Ethics**.

This project studies security risks in multi-agent AI collaboration. It simulates malicious-agent attacks, compares defense strategies, and evaluates the tradeoff between safety and task completion.

Repository: <https://github.com/guoym044-afk/Multi-Agent-Security>

## Project Overview

Multi-agent systems can divide a complex task across multiple agents, but they also introduce new attack surfaces:

- malicious agents can inject harmful instructions into the collaboration process
- one compromised agent can influence downstream agents
- sensitive information may be forwarded across agent boundaries
- safety checks can be bypassed through indirect instructions or collusion

This project focuses on a compact attack-defense-evaluation loop:

1. Simulate multi-agent collaboration.
2. Inject malicious messages or malicious-agent behavior.
3. Apply defense strategies such as filtering, safety judging, and permission control.
4. Measure attack success, privacy leakage, task completion, blocking rate, and false positives.

## Current Status

The current repository contains an evaluation pipeline with simulated experiment logs. This allows the project to produce reproducible tables and figures before the full multi-agent demo is integrated.

When real demo logs are available, replace `data/sample_logs.json` and rerun the evaluator.

## Repository Structure

```text
.
├── README.md
├── data/
│   └── sample_logs.json
├── ppt_materials/
│   └── evaluation.md
├── results/
│   ├── metrics.csv
│   ├── metrics_summary.md
│   └── figures/
│       ├── metrics.png
│       └── metrics.svg
└── src/
    └── evaluate.py
```

## Quick Start

The evaluator only requires Python 3 and does not use third-party packages.

```bash
python3 src/evaluate.py
```

The script reads:

```text
data/sample_logs.json
```

The script writes:

```text
results/metrics.csv
results/metrics_summary.md
results/figures/metrics.svg
results/figures/metrics.png
```

## Experiment Log Format

Each log entry should use this structure:

```json
{
  "case_id": "case_001",
  "category": "privacy_leakage",
  "mode": "no_defense",
  "blocked": false,
  "attack_success": true,
  "privacy_leak": true,
  "task_completed": true,
  "false_positive": false
}
```

## Metrics

| Metric | Meaning |
|---|---|
| `attack_success_rate` | Ratio of cases where the malicious goal succeeds |
| `privacy_leak_rate` | Ratio of cases where sensitive information leaks |
| `task_completion_rate` | Ratio of cases where the normal task is completed |
| `defense_block_rate` | Ratio of cases blocked by the defense |
| `false_positive_rate` | Ratio of acceptable cases incorrectly blocked |

## Current Simulated Results

| Mode | Attack Success | Privacy Leak | Task Completion | Defense Block | False Positive |
|---|---:|---:|---:|---:|---:|
| No defense | 70% | 50% | 90% | 0% | 0% |
| Keyword filter | 40% | 20% | 80% | 50% | 10% |
| Safety agent | 30% | 10% | 80% | 60% | 20% |
| Permission control | 10% | 0% | 70% | 80% | 30% |

## Interpretation

The simulated results show that defenses reduce attack success and privacy leakage. Permission control performs best in this setup, reducing attack success to 10% and privacy leakage to 0%. However, stronger defenses also reduce task completion and increase false positives, so the final system should balance safety with usability.

## Updating With Real Experiment Logs

1. Export real logs from the multi-agent demo using the same field names.
2. Replace `data/sample_logs.json`.
3. Run `python3 src/evaluate.py`.
4. Use `results/metrics.csv` and `results/figures/metrics.svg` in the final report or presentation.
