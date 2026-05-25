# 多智能体安全

[English](./README.md) | [中文](./README.zh-CN.md)

**人工智能安全与伦理**课程实践项目。

本仓库实现了一个紧凑、可复现的多智能体安全实验流程，用于研究多智能体协作中的安全风险。项目包含攻击用例库、确定性多智能体 demo、规则型防御模块、自动化评估流水线、实验结果产物，以及可直接用于汇报的 Markdown 材料。

仓库地址：<https://github.com/guoym044-afk/Multi-Agent-Security>

## 项目概述

多智能体系统可以把复杂任务拆分给多个角色协作完成，但也会带来新的安全风险：

- 恶意 Agent 可以向共享工作流注入指令
- 一个被污染的 Agent 会影响下游 Agent
- 敏感信息可能跨 Agent 边界传播
- 外部文档可能污染 Researcher 或 Writer 使用的证据
- Reviewer 可能被角色冒充、隐藏指令或审查绕过攻击影响

本项目展示了完整实验闭环：

```text
攻击用例 -> 多智能体 demo -> 防御决策 -> 评估日志 -> 指标与图表
```

当前实现是确定性的，并且不依赖第三方包；它不会调用真实 LLM API，因此适合课堂现场复现，也方便在 GitHub 上检查代码和数据。

## 仓库结构

```text
.
├── README.md
├── README.zh-CN.md
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

## 快速开始

所有脚本使用 Python 3，不需要安装第三方依赖。

从攻击用例库和正常控制样例生成实验日志：

```bash
python3 src/run_experiment.py
```

评估当前 sample logs：

```bash
python3 src/evaluate.py
```

把生成的 demo 日志评估到单独结果目录：

```bash
python3 src/evaluate.py --input data/b_demo_full_logs.json --output-dir results/demo --metrics-alias results/b_demo_metrics.csv
```

运行回归测试：

```bash
python3 tests/test_pipeline.py
```

运行独立防御模块：

```bash
python3 src/defense.py
python3 src/defense.py --method safety_judge
```

## 多智能体 Demo

确定性 demo 模拟了一个小型协作工作流：

```text
PlannerAgent -> ResearcherAgent -> WriterAgent -> ReviewerAgent -> FinalOutput
                         ^
                         |
               MaliciousAgent / ExternalDocument
```

每条攻击或正常样例都会在四种模式下运行：

| 模式 | 含义 |
|---|---|
| `no_defense` | 不进行恶意消息检查 |
| `keyword_filter` | 拦截明显的敏感标记和提示注入短语 |
| `safety_agent` | 基于攻击类别和风险等级进行更宽泛的风险判断 |
| `permission_control` | 阻止不可信发送者写入受保护 Agent 角色 |

## 攻击用例库

`data/attack_cases.json` 包含 20 条结构化攻击用例，覆盖五类风险：

| 类别 | 数量 | 主要风险 |
|---|---:|---|
| `privacy_leakage` | 4 | 泄露 API Key、密码、标识符或内部字段 |
| `prompt_injection` | 5 | 覆盖规则、冒充高优先级角色、跳过验证 |
| `misinformation` | 4 | 用虚假事实或误导性结论污染最终报告 |
| `review_bypass` | 4 | 诱导 Reviewer 通过不安全或缺乏依据的内容 |
| `collusion` | 3 | 多个 Agent 配合转发敏感信息或隐藏失败 |

`data/benign_cases.json` 包含 6 条正常控制样例，用于衡量误拦截率，尤其是安全请求本身提到 API keys 或 passwords 等敏感词时的误伤问题。

## 防御模块

`src/defense.py` 提供独立的规则型防御层。它接收标准化 message 对象，并返回三类动作之一：

| 动作 | 含义 |
|---|---|
| `allow` | 放行消息 |
| `block` | 因高风险阻断消息 |
| `redact` | 脱敏敏感字段后继续 |

已实现的防御包括：

- 关键词和规则过滤
- 敏感信息脱敏
- Agent 权限检查
- 组合型 `safety_judge`

设计细节和限制见 `docs/defense_design.md`。

## 评估

`src/evaluate.py` 读取 evaluator 兼容日志，并生成：

```text
results/metrics.csv
results/category_metrics.csv
results/failure_cases.csv
results/metrics_summary.md
results/figures/metrics.svg
results/figures/metrics.png
```

每条日志至少包含：

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

可选字段包括 `is_attack`、`case_type`、`attack_entry`、`target_agent` 和 `blocked_reason`，这些字段会保留用于失败案例分析。当 `is_attack` 存在时，攻击成功率和隐私泄露率只在攻击样例上计算，误拦截率只在正常样例上计算。

## 当前结果

当前确定性 demo 产生 104 条评估日志：20 条攻击用例和 6 条正常控制样例，在 4 种防御模式下运行。

| 模式 | 攻击成功率 | 隐私泄露率 | 任务完成率 | 防御拦截率 | 误拦截率 |
|---|---:|---:|---:|---:|---:|
| No defense | 100% | 35% | 69% | 0% | 0% |
| Keyword filter | 45% | 5% | 81% | 54% | 50% |
| Safety agent | 40% | 0% | 92% | 46% | 0% |
| Permission control | 0% | 0% | 54% | 77% | 0% |

分类结果和失败案例可见：

```text
results/category_metrics.csv
results/failure_cases.csv
results/metrics_summary.md
```

## 结果解读

在当前确定性设置下，`no_defense` 基线完全暴露。`keyword_filter` 能降低明显攻击，但当正常请求提到安全敏感词时，会产生较高误拦截。`safety_agent` 在消除隐私泄露的同时保持最高任务完成率。`permission_control` 的安全性最强，因为它把攻击成功率降到 0%，但也会阻断更多任务并降低完成率。

这体现了项目的核心安全取舍：更强的隔离能提升安全性，但过宽的控制也会损害可用性。

## 项目交付物

当前仓库围绕五类交付物组织：

| 交付物 | 主要文件 | 用途 |
|---|---|---|
| 攻击用例库 | `data/attack_cases.json`, `ppt_materials/attack_cases.md` | 定义 20 条结构化攻击用例，覆盖五类风险 |
| 可运行 demo | `src/agents.py`, `src/demo.py`, `src/run_experiment.py` | 在四种防御模式下生成确定性多智能体 trace |
| 防御模块 | `src/defense.py`, `docs/defense_design.md` | 实现关键词、safety judge、脱敏和权限检查 |
| 评估模块 | `src/evaluate.py`, `results/` | 生成模式指标、类别指标、图表和失败案例 |
| 集成说明 | `docs/integration_interfaces.md`, `data/interface_examples/` | 说明 demo、防御模块和 evaluator 之间的 JSON 接口 |

## 汇报材料

可直接用于汇报的 Markdown 材料存放在 `ppt_materials/`。PowerPoint 文件不会被 Git 跟踪；需要时请单独生成或分享 `.pptx` 文件。

重要文件：

- `ppt_materials/final_presentation_outline.md`
- `ppt_materials/attack_cases.md`
- `ppt_materials/B_demo.md`
- `ppt_materials/D_defense.md`
- `ppt_materials/evaluation.md`

## 复现实验结果

1. 运行 `python3 src/run_experiment.py`。
2. 运行 `python3 src/evaluate.py`。
3. 可选：运行 `python3 src/evaluate.py --input data/b_demo_full_logs.json --output-dir results/demo --metrics-alias results/b_demo_metrics.csv`。
4. 运行 `python3 tests/test_pipeline.py`。
5. 在最终报告或幻灯片中使用 `results/metrics.csv`、`results/category_metrics.csv`、`results/failure_cases.csv` 和 `results/figures/metrics.svg`。

## 局限性

- demo 是确定性、规则型实现，不调用真实 LLM Agent。
- 攻击用例是人工构造的小规模样例。
- 防御模块强调可解释性，但无法覆盖所有改写、长程多轮攻击或真实工具调用风险。
- 结果适合作为课程项目演示，不应作为生产级多智能体系统 benchmark。
