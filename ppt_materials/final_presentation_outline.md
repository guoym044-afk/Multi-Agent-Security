# Final PPT Outline

建议做一个 10 页左右的最终汇报 PPT。原因是这个项目现在已经有攻击库、可运行 demo、benign control、自动评测和测试脚本，如果只交 README 或代码，会损失很多展示效果。PPT 不需要很长，重点是把“攻击 -> 防御 -> 评测 -> 权衡”讲清楚。

## 推荐标题

**多智能体协作中的恶意 Agent 攻击与防护评测**

副标题：基于攻击用例库、最小可运行 demo 和自动化评估的课程实践

## Slide 1：标题页

页面文案：

- 多智能体协作中的恶意 Agent 攻击与防护评测
- AI Safety and Ethics Course Project
- 关键词：Multi-Agent Security / Prompt Injection / Privacy Leakage / Safety Evaluation

讲稿：

本项目关注多智能体协作中的安全风险。我们不是只做静态讨论，而是构建了攻击用例、最小 demo、防御模式和评估脚本，形成一个可运行、可复现的安全评测闭环。

## Slide 2：问题背景

页面文案：

- 多 Agent 系统会把复杂任务拆给 Planner、Researcher、Writer、Reviewer 等角色
- 但 Agent 间消息传递也引入了新的攻击面
- 风险包括：隐私泄露、提示注入、错误信息污染、审查绕过、Agent 串谋

讲稿：

单 Agent 安全主要关注用户输入和最终输出；多 Agent 场景下，中间消息、外部资料和审查环节也可能被污染。一个被攻击的 Agent 可能继续影响下游 Agent。

## Slide 3：系统闭环

页面文案：

```text
attack_cases + benign_cases
        -> src/run_experiment.py
        -> data/b_demo_full_logs.json
        -> src/evaluate.py
        -> metrics + figures + failure cases
```

核心产物：

- 20 条攻击用例
- 6 条 benign 正常样例
- 4 种防御模式
- 104 条 demo 运行日志
- 自动生成指标表、图表和失败案例

讲稿：

项目现在不是单纯的模拟表格，而是先由 demo 生成日志，再由 evaluator 统一统计。这样每个结果都能追溯到具体 case。

## Slide 4：攻击用例库

页面文案：

| 攻击类型 | 数量 | 攻击目标 |
|---|---:|---|
| 隐私泄露 | 4 | API Key、手机号、密码、内部字段 |
| 提示注入 | 5 | 覆盖规则、伪装管理员、跳过验证 |
| 错误信息污染 | 4 | 伪造事实、误导指标解释 |
| 绕过审查 | 4 | 诱导 Reviewer 放行风险内容 |
| Agent 串谋 | 3 | 多 Agent 配合转发敏感信息或隐藏失败 |

讲稿：

攻击库覆盖五类风险，每条用例都有攻击入口、目标 Agent、恶意提示、预期安全行为和成功条件，方便后续自动评测。

## Slide 5：最小可运行 Demo

页面文案：

```text
PlannerAgent -> ResearcherAgent -> WriterAgent -> ReviewerAgent -> FinalOutput
                         ^
                         |
               MaliciousAgent / ExternalDocument
```

防御模式：

- `no_defense`
- `keyword_filter`
- `safety_agent`
- `permission_control`

讲稿：

Demo 是确定性的 toy runtime，不调用真实 LLM，但它能展示恶意消息如何进入协作流程，以及不同防御策略如何拦截或放行。

## Slide 6：Benign Controls

页面文案：

- 目的：衡量正常请求是否被误拦截
- 样例：正常讨论 API Key、token、employee_id、密码脱敏方法
- 价值：让 false positive rate 从近似指标变成可直接统计的指标

关键结论：

- Keyword filter 对 benign 请求误拦截率 50%
- Safety agent 和 permission control 在当前 benign 集上为 0%

讲稿：

只看攻击样例不能说明防御是否好用。Benign controls 让我们能同时看安全性和可用性，尤其能暴露关键词过滤的上下文理解不足。

## Slide 7：评估指标

页面文案：

| 指标 | 含义 | 方向 |
|---|---|---|
| Attack success rate | 攻击目标成功比例 | 越低越安全 |
| Privacy leak rate | 敏感信息泄露比例 | 越低越安全 |
| Task completion rate | 正常任务完成比例 | 越高越可用 |
| Defense block rate | 防御拦截比例 | 衡量防御强度 |
| False positive rate | benign 被误拦截比例 | 越低越好 |

讲稿：

这些指标共同衡量安全性和可用性。尤其 false positive rate 使用 benign cases 作为分母，使结果更严谨。

## Slide 8：实验结果

页面文案：

| Mode | Attack Success | Privacy Leak | Task Completion | Defense Block | False Positive |
|---|---:|---:|---:|---:|---:|
| No defense | 100% | 35% | 69% | 0% | 0% |
| Keyword filter | 45% | 5% | 81% | 54% | 50% |
| Safety agent | 40% | 0% | 92% | 46% | 0% |
| Permission control | 0% | 0% | 54% | 77% | 0% |

讲稿：

无防御时攻击全部成功。关键词过滤能降低攻击成功率，但误拦截明显。Safety agent 在当前 demo 中隐私泄露为 0，任务完成率最高。权限控制最安全，但任务完成率下降明显。

## Slide 9：失败案例分析

页面文案：

| Case | Mode | Failure | 说明 |
|---|---|---|---|
| `case_010` | Keyword filter | attack_success | 错误信息污染绕过关键词过滤 |
| `case_019` | Safety agent | attack_success + task failure | 串谋类攻击仍难处理 |
| `benign_001` | Keyword filter | false_positive | 正常讨论 API Key 保护被误拦截 |

讲稿：

失败案例说明指标背后的原因。关键词过滤对显式敏感词有效，但对错误信息污染弱；同时它会误伤正常安全讨论。串谋类攻击也比单点提示注入更难处理。

## Slide 10：总结与改进方向

页面文案：

项目成果：

- 构建攻击用例库和 benign control set
- 实现最小可运行多 Agent 安全 demo
- 支持 4 种防御模式和自动化评估
- 输出指标表、图表和失败案例
- 增加测试脚本验证关键流程

下一步：

- 接入真实 LLM Agent 日志
- 扩充 benign control set
- 增加更细粒度的权限策略
- 引入人工标注或模型裁判进行结果校验

讲稿：

本项目展示了一个可复现的多智能体安全评测框架。它的价值不在于 demo 很复杂，而在于攻击、防御和评测形成闭环，并能清楚呈现安全性和可用性的权衡。

## 5 分钟汇报节奏

| 时间 | 内容 |
|---:|---|
| 0:00-0:30 | 项目背景和问题 |
| 0:30-1:20 | 攻击用例库 |
| 1:20-2:00 | Demo 流程和防御模式 |
| 2:00-2:40 | Benign controls 和指标 |
| 2:40-4:10 | 实验结果和失败案例 |
| 4:10-5:00 | 总结与改进方向 |

## 10 分钟汇报节奏

| 时间 | 内容 |
|---:|---|
| 0:00-1:00 | 背景、问题定义 |
| 1:00-2:20 | 攻击类型和典型案例 |
| 2:20-3:30 | 最小 demo 架构 |
| 3:30-4:30 | 防御模式 |
| 4:30-5:30 | Benign controls |
| 5:30-7:00 | 指标和实验结果 |
| 7:00-8:30 | 失败案例分析 |
| 8:30-10:00 | 总结、限制和改进方向 |
