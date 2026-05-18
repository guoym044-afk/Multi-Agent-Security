# Evaluation Materials

## Evaluation Goal

This module converts multi-agent safety experiment logs into quantitative results for the final presentation. The current repository uses simulated logs so that the evaluation workflow can run before the full demo system is integrated. After real experiment logs are available, replace `data/sample_logs.json` and rerun the evaluator.

## Metrics

| Metric | Meaning | Interpretation |
|---|---|---|
| Attack success rate | Ratio of cases where the malicious goal succeeds | Lower is safer |
| Privacy leak rate | Ratio of cases where sensitive information leaks | Lower is safer |
| Task completion rate | Ratio of cases where the normal task is completed | Higher is better |
| Defense block rate | Ratio of cases blocked by defense mechanisms | Measures defense strength |
| False positive rate | Ratio of acceptable cases incorrectly blocked | Lower is better |

## Experiment Modes

| Mode | Description |
|---|---|
| `no_defense` | Baseline without any defense |
| `keyword_filter` | Blocks obvious malicious instructions with keyword rules |
| `safety_agent` | Uses an additional safety judge to inspect messages |
| `permission_control` | Restricts which agents can access or forward sensitive information |

## Current Simulated Results

| Mode | Attack Success | Privacy Leak | Task Completion | Defense Block | False Positive |
|---|---:|---:|---:|---:|---:|
| No defense | 70% | 50% | 90% | 0% | 0% |
| Keyword filter | 40% | 20% | 80% | 50% | 10% |
| Safety agent | 30% | 10% | 80% | 60% | 20% |
| Permission control | 10% | 0% | 70% | 80% | 30% |

Related files:

- `results/metrics.csv`
- `results/metrics_summary.md`
- `results/figures/metrics.svg`
- `results/figures/metrics.png`

## Presentation Takeaways

1. Without defense, the simulated multi-agent workflow has high attack success and privacy leakage rates.
2. Message-level defenses reduce both attack success and privacy leakage, showing that communication review is useful in multi-agent systems.
3. Permission control gives the strongest security result in this simulation, but it also reduces task completion and increases false positives, showing a security-usability tradeoff.

## Reproduce Results

```bash
python3 src/evaluate.py
```

The command regenerates:

```text
results/metrics.csv
results/metrics_summary.md
results/figures/metrics.svg
results/figures/metrics.png
```
