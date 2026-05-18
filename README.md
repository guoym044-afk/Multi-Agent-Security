# Multi-Agent Security

Course practice project for **AI Safety and Ethics**.

Project topic: **Evaluating malicious-agent attacks and defenses in multi-agent collaboration**.

GitHub repository: <https://github.com/guoym044-afk/Multi-Agent-Security>

## Project Goal

This project builds a small multi-agent workflow to show how malicious agents or malicious messages can affect collaboration. The planned evaluation compares different defense settings and reports whether attacks succeed, whether privacy leaks occur, and whether the normal task can still be completed.

The project focuses on a complete attack-defense-evaluation loop:

1. Multi-agent collaboration flow
2. Attack case design
3. Defense mechanisms
4. Metric calculation
5. Result table and chart for the final presentation

## Role E Scope

This repository snapshot contains the independent deliverables for **Role E: evaluation, visualization, and GitHub organization**.

Role E does not need to wait for the real outputs from other roles. The current version uses simulated logs in `data/sample_logs.json`. When real logs from the demo are ready, replace that file and rerun the evaluator.

## Repository Structure

```text
.
├── README.md
├── data/
│   └── sample_logs.json
├── docs/
├── ppt_materials/
│   └── E_evaluation.md
├── results/
│   ├── metrics.csv
│   ├── metrics_summary.md
│   └── figures/
│       ├── metrics.png
│       └── metrics.svg
├── src/
│   └── evaluate.py
└── 多智能体安全项目分工.md
```

## How To Run Evaluation

Use Python 3. No third-party packages are required.

```bash
python3 src/evaluate.py
```

The script reads:

```text
data/sample_logs.json
```

It writes:

```text
results/metrics.csv
results/metrics_summary.md
results/figures/metrics.svg
results/figures/metrics.png
```

## Log Format

Each log entry should include these fields:

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
| `task_completion_rate` | Ratio of cases where the normal task is still completed |
| `defense_block_rate` | Ratio of cases blocked by the defense |
| `false_positive_rate` | Ratio of benign or acceptable cases blocked incorrectly |

## Current Simulated Result

| Mode | Attack Success | Privacy Leak | Task Completion | Defense Block | False Positive |
|---|---:|---:|---:|---:|---:|
| No defense | 70% | 50% | 90% | 0% | 0% |
| Keyword filter | 40% | 20% | 80% | 50% | 10% |
| Safety agent | 30% | 10% | 80% | 60% | 20% |
| Permission control | 10% | 0% | 70% | 80% | 30% |

## How To Replace With Real Logs

1. Ask Role B to export demo logs using the same field names.
2. Replace `data/sample_logs.json` with the real logs.
3. Run `python3 src/evaluate.py`.
4. Use `results/metrics.csv` and `results/figures/metrics.svg` in the final presentation.

## Presentation Notes

The current simulated results support three points:

1. The no-defense baseline has high attack success and privacy leakage rates.
2. Adding defenses reduces both attack success and privacy leakage.
3. Stronger defenses improve security but may slightly reduce task completion or increase false positives.
