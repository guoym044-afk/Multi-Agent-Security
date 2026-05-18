# E 负责内容：实验评测、图表与 GitHub 整理

## 1. 本模块目标

本模块负责把多智能体安全实验转化为可量化结果。当前版本先使用模拟日志完成评测流程，后续只需要把 `data/sample_logs.json` 替换为 B/C/D 集成后的真实日志，即可重新生成结果表和图表。

## 2. 评价指标

| 指标 | 含义 | 汇报解释 |
|---|---|---|
| 攻击成功率 | 恶意 Agent 达成攻击目标的比例 | 越低越安全 |
| 隐私泄露率 | 敏感信息被输出或传播的比例 | 越低越安全 |
| 任务完成率 | 系统仍能完成正常任务的比例 | 越高越好 |
| 防御拦截率 | 防御模块拦截风险消息的比例 | 反映防御强度 |
| 误拦截率 | 正常或可接受内容被误拦截的比例 | 越低越好 |

## 3. 当前模拟实验设置

当前模拟了 4 种实验模式：

| 模式 | 说明 |
|---|---|
| `no_defense` | 无防御 baseline |
| `keyword_filter` | 使用关键词过滤明显恶意内容 |
| `safety_agent` | 使用 Safety Agent 判断消息风险 |
| `permission_control` | 使用权限隔离限制 Agent 访问和传播敏感信息 |

每种模式包含 10 条模拟日志，共 40 条实验记录。

## 4. 当前结果表

| 模式 | 攻击成功率 | 隐私泄露率 | 任务完成率 | 防御拦截率 | 误拦截率 |
|---|---:|---:|---:|---:|---:|
| 无防御 | 70% | 50% | 90% | 0% | 0% |
| 关键词过滤 | 40% | 20% | 80% | 50% | 10% |
| Safety Agent | 30% | 10% | 80% | 60% | 20% |
| 权限隔离 | 10% | 0% | 70% | 80% | 30% |

对应文件：

- `results/metrics.csv`
- `results/metrics_summary.md`
- `results/figures/metrics.svg`
- `results/figures/metrics.png`

## 5. PPT 可用结论

1. 无防御时，多 Agent 系统容易被恶意 Agent 影响，攻击成功率达到 70%，隐私泄露率达到 50%。
2. 加入关键词过滤和 Safety Agent 后，攻击成功率和隐私泄露率明显下降，说明通信审查能降低恶意消息传播风险。
3. 权限隔离的安全效果最好，将攻击成功率降至 10%，但任务完成率下降到 70%，说明安全增强可能带来一定可用性损失。

## 6. 给 A 的 PPT 建议

建议放 2 页：

第一页：实验设置与评价指标。

- 展示 5 个指标
- 说明 4 种实验模式
- 强调当前结果可用模拟日志先展示，后续可替换真实日志

第二页：实验结果与结论。

- 放 `results/figures/metrics.svg` 或 `results/figures/metrics.png`
- 放当前结果表
- 用 3 条结论解释安全性和可用性的权衡

## 7. 运行方式

```bash
python3 src/evaluate.py
```

运行后会自动生成：

```text
results/metrics.csv
results/metrics_summary.md
results/figures/metrics.svg
results/figures/metrics.png
```
