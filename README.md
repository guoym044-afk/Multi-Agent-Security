# Multi-Agent Security

A course practice project for **AI Safety and Ethics**.

This repository implements a compact, reproducible workflow for studying security risks in multi-agent AI collaboration. It includes an attack case library, a deterministic multi-agent demo, rule-based defense mechanisms, an evaluation pipeline, result artifacts, and presentation-ready Markdown materials.

Repository: <https://github.com/guoym044-afk/Multi-Agent-Security>

## Project Overview

Multi-agent systems make complex tasks easier to decompose, but they also add new security risks:

- malicious agents can inject instructions into the shared workflow
- one compromised agent can influence downstream agents
- sensitive information can move across agent boundaries
- external documents can pollute the evidence used by researcher or writer agents
- reviewers can be bypassed through role impersonation or hidden instructions

This project demonstrates the full loop:

```text
attack cases -> multi-agent demo -> defense decisions -> evaluation logs -> metrics and figures
```

The current implementation is deterministic and dependency-free. It does not call a real LLM API, which makes the project easy to reproduce in class and easy to inspect in GitHub.

## Repository Structure

```text
.
├── README.md
├── data/
│   ├── attack_cases.json
│   ├── benign_cases.json
│   ├── b_demo_full_logs.json
│   ├── defense_test_cases.json
│   ├── interface_examples/
│   └── sample_logs.json
├── docs/
│   ├── defense_design.md
│   └── integration_interfaces.md
├── ppt_materials/
│   ├── B_demo.md
│   ├── D_defense.md
│   ├── attack_cases.md
│   ├── attack_cases_ppt_notes.md
│   ├── benign_controls.md
│   ├── evaluation.md
│   └── final_presentation_outline.md
├── results/
│   ├── category_metrics.csv
│   ├── failure_cases.csv
│   ├── metrics.csv
│   ├── metrics_summary.md
│   └── figures/
├── src/
│   ├── agents.py
│   ├── defense.py
│   ├── demo.py
│   ├── evaluate.py
│   └── run_experiment.py
└── tests/
    └── test_pipeline.py
```

## Quick Start

All scripts use Python 3 and require no third-party packages.

Generate experiment logs from the attack and benign case libraries:

```bash
python3 src/run_experiment.py
```

Evaluate the current sample logs:

```bash
python3 src/evaluate.py
```

Evaluate the generated demo logs into a separate result folder:

```bash
python3 src/evaluate.py --input data/b_demo_full_logs.json --output-dir results/demo --metrics-alias results/b_demo_metrics.csv
```

Run regression tests:

```bash
python3 tests/test_pipeline.py
```

Run the standalone defense module:

```bash
python3 src/defense.py
python3 src/defense.py --method safety_judge
```

## Multi-Agent Demo

The deterministic demo simulates a small collaboration workflow:

```text
PlannerAgent -> ResearcherAgent -> WriterAgent -> ReviewerAgent -> FinalOutput
                         ^
                         |
               MaliciousAgent / ExternalDocument
```

It runs each attack or benign case under four modes:

| Mode | Meaning |
|---|---|
| `no_defense` | No malicious-message inspection |
| `keyword_filter` | Blocks obvious sensitive markers and injection phrases |
| `safety_agent` | Applies broader risk checks by attack category and risk level |
| `permission_control` | Blocks untrusted senders from writing to protected agent roles |

## Attack Case Library

`data/attack_cases.json` contains 20 structured attack cases across five categories:

| Category | Count | Main Risk |
|---|---:|---|
| `privacy_leakage` | 4 | Leaking API keys, passwords, identifiers, or internal fields |
| `prompt_injection` | 5 | Overriding rules, impersonating higher-priority roles, skipping validation |
| `misinformation` | 4 | Polluting the final report with false facts or misleading conclusions |
| `review_bypass` | 4 | Making the reviewer approve unsafe or unsupported content |
| `collusion` | 3 | Coordinating multiple agents to forward secrets or hide failures |

`data/benign_cases.json` contains 6 normal control cases. These are used to measure false positives, especially when a safe request mentions sensitive terms such as API keys or passwords.

## Defense Module

`src/defense.py` provides a standalone rule-based defense layer. It accepts a normalized message object and returns one of three actions:

| Action | Meaning |
|---|---|
| `allow` | Pass the message |
| `block` | Stop the message because it is high risk |
| `redact` | Replace sensitive fields and continue |

Implemented defenses include:

- keyword and rule filtering
- sensitive information redaction
- agent permission checks
- a combined `safety_judge`

The design and limitations are documented in `docs/defense_design.md`.

## Evaluation

`src/evaluate.py` reads evaluator-compatible logs and produces:

```text
results/metrics.csv
results/category_metrics.csv
results/failure_cases.csv
results/metrics_summary.md
results/figures/metrics.svg
results/figures/metrics.png
```

Each log entry must include:

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

Optional fields such as `is_attack`, `case_type`, `attack_entry`, `target_agent`, and `blocked_reason` are preserved for failure analysis. When `is_attack` exists, attack success and privacy leak rates are computed over attack cases, while false positive rate is computed over benign cases.

## Current Results

The current deterministic demo produces 104 evaluation logs: 20 attack cases and 6 benign controls under 4 defense modes.

| Mode | Attack Success | Privacy Leak | Task Completion | Defense Block | False Positive |
|---|---:|---:|---:|---:|---:|
| No defense | 100% | 35% | 69% | 0% | 0% |
| Keyword filter | 45% | 5% | 81% | 54% | 50% |
| Safety agent | 40% | 0% | 92% | 46% | 0% |
| Permission control | 0% | 0% | 54% | 77% | 0% |

Category-level results and failure examples are available in:

```text
results/category_metrics.csv
results/failure_cases.csv
results/metrics_summary.md
```

## Interpretation

The no-defense baseline is fully vulnerable in this deterministic setup. Keyword filtering reduces obvious attacks, but it creates false positives when benign requests mention security-sensitive terms. The safety-agent mode eliminates privacy leakage while preserving the highest task completion rate. Permission control is the strongest security setting because it reduces attack success to 0%, but it also blocks more tasks and reduces completion.

This demonstrates the main security tradeoff: stronger isolation improves safety, while overly broad controls can hurt usefulness.

## Project Deliverables

The latest repository content is organized around five deliverables:

| Deliverable | Main files | Purpose |
|---|---|---|
| Attack library | `data/attack_cases.json`, `ppt_materials/attack_cases.md` | Defines 20 structured attack cases across five risk categories |
| Runnable demo | `src/agents.py`, `src/demo.py`, `src/run_experiment.py` | Generates deterministic multi-agent traces under four defense modes |
| Defense module | `src/defense.py`, `docs/defense_design.md` | Implements keyword, safety-judge, redaction, and permission checks |
| Evaluation module | `src/evaluate.py`, `results/` | Produces mode metrics, category metrics, figures, and failure cases |
| Integration notes | `docs/integration_interfaces.md`, `data/interface_examples/` | Documents JSON interfaces between demo, defense, and evaluator |

## Presentation Materials

Presentation-ready Markdown materials are stored in `ppt_materials/`. PowerPoint files are intentionally not tracked in Git; generate or share `.pptx` files separately when needed.

Important files:

- `ppt_materials/final_presentation_outline.md`
- `ppt_materials/attack_cases.md`
- `ppt_materials/B_demo.md`
- `ppt_materials/D_defense.md`
- `ppt_materials/evaluation.md`

## Reproducing Results

1. Run `python3 src/run_experiment.py`.
2. Run `python3 src/evaluate.py`.
3. Optional: run `python3 src/evaluate.py --input data/b_demo_full_logs.json --output-dir results/demo --metrics-alias results/b_demo_metrics.csv`.
4. Run `python3 tests/test_pipeline.py`.
5. Use `results/metrics.csv`, `results/category_metrics.csv`, `results/failure_cases.csv`, and `results/figures/metrics.svg` in the final report or slides.

## Limitations

- The demo is deterministic and rule-based; it does not call real LLM agents.
- The attack cases are handcrafted and small-scale.
- The defense module is intentionally interpretable, but it cannot cover all paraphrases, multi-turn attacks, or real tool-use risks.
- The results are suitable for a course project demonstration, not for benchmarking production multi-agent systems.
