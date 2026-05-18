# Evaluation Summary

| Mode | Cases | Attack Success | Privacy Leak | Task Completion | Defense Block | False Positive |
|---|---:|---:|---:|---:|---:|---:|
| No defense | 10 | 70% | 50% | 90% | 0% | 0% |
| Keyword filter | 10 | 40% | 20% | 80% | 50% | 10% |
| Safety agent | 10 | 30% | 10% | 80% | 60% | 20% |
| Permission control | 10 | 10% | 0% | 70% | 80% | 30% |

## Presentation Takeaways

- Without defense, the simulated multi-agent workflow has the highest attack success and privacy leakage rates.
- Keyword filtering reduces obvious attacks but misses indirect misinformation and collusion cases.
- Permission control gives the strongest security result in this simulation, with a small task-completion tradeoff.
