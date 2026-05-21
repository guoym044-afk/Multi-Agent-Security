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

The repository now includes the B-role multi-agent demo and the E-role evaluation pipeline.

The demo can generate structured attack-defense logs, and the evaluator can turn those logs into reproducible tables and figures for the final presentation.

## Repository Structure

```text
.
├── README.md
├── data/
│   ├── b_demo_full_logs.json
│   └── sample_logs.json
├── ppt_materials/
│   ├── B_demo.md
│   └── evaluation.md
├── results/
│   ├── b_demo_metrics.csv
│   ├── metrics.csv
│   ├── metrics_summary.md
│   └── figures/
│       ├── metrics.png
│       └── metrics.svg
└── src/
    ├── agents.py
    ├── run_experiment.py
    └── evaluate.py
```

## Quick Start

The demo and evaluator only require Python 3 and do not use third-party packages.

```bash
python3 src/run_experiment.py
python3 src/evaluate.py
```

The demo writes:

```text
data/b_demo_full_logs.json
data/sample_logs.json
results/b_demo_metrics.csv
```

The evaluator reads:

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
| No defense | 100% | 25% | 100% | 0% | 0% |
| Keyword filter | 25% | 0% | 100% | 100% | 0% |
| Safety agent | 0% | 0% | 100% | 100% | 0% |
| Permission control | 0% | 0% | 100% | 100% | 0% |

## Interpretation

The current B demo shows that malicious-agent messages can fully compromise the workflow without defenses. Keyword filtering blocks obvious attacks but still misses one polluted-information case. Safety judging and permission control both reduce attack success to 0% in this small demo, while preserving task completion.

## Updating With Real Experiment Logs

1. Run `python3 src/run_experiment.py` to export fresh demo logs.
2. Run `python3 src/evaluate.py`.
3. Use `results/metrics.csv` and `results/figures/metrics.svg` in the final report or presentation.
