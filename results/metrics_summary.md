# Evaluation Summary

| Mode | Cases | Attack Success | Privacy Leak | Task Completion | Defense Block | False Positive |
|---|---:|---:|---:|---:|---:|---:|
| No defense | 4 | 100% | 25% | 100% | 0% | 0% |
| Keyword filter | 4 | 25% | 0% | 100% | 100% | 0% |
| Safety agent | 4 | 0% | 0% | 100% | 100% | 0% |
| Permission control | 4 | 0% | 0% | 100% | 100% | 0% |

## Presentation Takeaways

- Without defense, the simulated multi-agent workflow has the highest attack success and privacy leakage rates.
- Keyword filtering reduces obvious attacks but misses indirect misinformation and collusion cases.
- Permission control gives the strongest security result in this simulation, with a small task-completion tradeoff.
