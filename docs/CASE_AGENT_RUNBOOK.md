# 主控 Case Agent

`src/threat2detect/pipeline/controller.py` 是新的有状态入口，原 `src/threat2detect/pipeline/legacy.py` 固定流水线保持兼容。实现位于 `src/threat2detect/pipeline/controller.py`。
结构为一个主控调用现有工具：报告理解/ATT&CK、规则召回、Sigma 条件分析局部 Agent、日志检查和执行、可选规则生成修订工作流。
主控不会把每个模块改造成独立子 Agent，也不会自动部署规则。

## 运行主链路

已有标准化 OTRF 日志时，从项目根目录执行：

```powershell
python -m src.threat2detect --handoff data/annotations/aa25_266a_gold_draft.json --events artifacts/runs/otrf_lsass_normalized.json --output-dir artifacts/runs/case-agent-demo --max-behaviors 1 --candidates-per-mapping 1 --max-search-rounds 1
```

默认 `--controller model`，由本机 Ollama `qwen3:4b` 在当前允许的动作中选择并给理由。
输出目录必须为空；默认只处理前三条行为，未选中的行为明确列出，不能当成全篇已完成。
没有标准化日志时可省略 `--events`，结果会记录未执行原因，不自动替换成其他场景的日志。

无需模型的流程检查：

```powershell
python -m src.threat2detect --handoff data/annotations/aa25_266a_gold_draft.json --events artifacts/runs/otrf_lsass_normalized.json --output-dir artifacts/runs/case-agent-offline-demo --controller policy --skip-coverage --max-behaviors 1 --candidates-per-mapping 1
```

`policy` 是确定性动作策略，不冒充模型决策。只有同时跳过条件分析且不启用生成时才完全不调用模型。
跳过条件分析仍可独立执行样例测试，但报告做法适用性保留未知。

新报告入口：

```powershell
python -m src.threat2detect --report data/reports/cisa-aa25-266a-input.txt --case-id AA25-266A --title "CISA IR case" --source-url "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-266a" --events artifacts/runs/otrf_lsass_normalized.json --output-dir artifacts/runs/case-agent-report-demo --include-draft
```

只接受事先去掉官方标签/参考表的正文；不把 `*-reference.json` 送入模型。
报告工具仍使用当前 A 原型并保留 draft。没有 `--include-draft` 时，未确认行为/映射停止并排队复核；打开它只允许分析草稿，不会提升审核状态。
组员 A/B 可在固定接口后替换相应工具实现。

## 动作与停止条件

| 动作 | 作用与约束 |
|---|---|
| `analyze_report` | 无交接包时调用 A 原型，校验原文定位、输入哈希和目录 ID |
| `read_context` | 读取目标引文及周围上下文，保留事实强度 |
| `search_rules` | 使用优化后的技术标签召回、平台/类别过滤和 IDF 重排；后续轮次扩大候选数量，稳定候选 ID 防止已分析项重复 |
| `assess_candidate` | 调用现有 Sigma 局部工具 Agent，判断报告做法，保持 draft |
| `check_telemetry` | 核对日志源、事件类型与字段，缺失时记录未验证 |
| `test_rule` | 校验候选 YAML 哈希并实际执行，事件引用和结果独立保存 |
| `generate_rule` | 仅有用户配置的生成计划且满足开关/触发条件时允许 |
| `request_review` | 保存人审事项并结束该行为的自动处理；不发送外部消息，不自动确认 |
| `finish` | 仅当所有选中行为已结束自动处理时开放，保留未选中/未验证范围 |

检查字段使用规则字段并集，属于保守检查：若缺失的是 OR 替代分支字段，也可能停止执行并交人工，不宣称所有字段都逻辑必需。
系统只有 `hit/miss` 等指定日志结果，不把样例命中解释为检测到 CISA 原事件。
模型给出的动作理由属于未核验文本，不是证据。实测中模型仍会把“待审适用”说成“已确认”或把结束自动处理说成“案例解决”；规范结果以工具记录、draft、人审队列及 workflow_status 为准。

`search_rules` 直接调用 `src/threat2detect/sigma/retrieval.py`。每次检索的排名、IDF 分数、召回理由和平台排除项都会写入 `state.json`、`trace.jsonl` 和最终 `case_result.items`。AA25-266A 的 4 条人工规则回归中 Recall@5 为 0.75、Recall@10 为 1.00、MRR 为 0.5875；样本很小，不能当作总体准确率。

## 可选规则生成

默认关闭。用户准备生成计划，再用 `--enable-generation --generation-plan PATH` 开启。
计划是 JSON 数组，每项包含：

```json
{
  "behavior_id": "AA25-266A-P020",
  "trigger": "explicit_request",
  "request_path": "artifacts/runs/rule-generation-case-fixture/request.json",
  "events_paths": ["artifacts/runs/rule-generation-case-fixture/events.json"],
  "evaluation_refs_path": "artifacts/runs/rule-generation-case-fixture/evaluation_refs.json",
  "evaluation_events_paths": ["artifacts/runs/rule-generation-case-fixture/evaluation_events.json"]
}
```

- `explicit_request`：用户明确给定独立检测目标，允许在报告行为仍为 draft 时调用；不得把人工目标当作报告事实。
- `coverage_gap`：必须已经完成配置的检索轮次，存在候选且所有候选均分析为 `does_not_match`。空召回、`insufficient_detail`、缺日志都不满足此门槛。这仍是模型提出的局部缺口假设，不是已证实真实缺口。
- 每个行为最多一个计划；计划目标必须处于本轮行为选择范围，路径只能指向项目内。
- 请求给出行为、字段、日志源和检测目标，ATT&CK ID 不足以单独触发生成。
- 输出保存在 `generated-NNN/`，与既有规则候选、覆盖判断和样例执行分开，不自动宣称缺口已解决。

可复现的 BITS 分支演示：

```powershell
python tools/prepare_rule_generation_demo.py artifacts/runs/rule-generation-case-fixture --scenario bits --case-agent-demo
python -m src.threat2detect --handoff artifacts/runs/rule-generation-case-fixture/handoff.json --events artifacts/runs/rule-generation-case-fixture/events.json --output-dir artifacts/runs/case-agent-generation-demo --controller policy --skip-coverage --enable-generation --generation-plan artifacts/runs/rule-generation-case-fixture/generation_plan.json --max-behaviors 1
```

示例关联报告的 BITS 下载行为，但 `/transfer` 是人工选择的窄目标，报告没有明确该参数。原行为仍 draft，开发背景候选不代表已证实良性，最终边界测试为合成数据。

## 预算与产物

预算参数为 `--max-steps`、`--max-model-calls`、`--max-seconds`、`--max-behaviors`、`--max-search-rounds`、`--candidates-per-mapping`、`--sigma-max-steps`、`--generation-attempts`。
主控、A 原型、Sigma 局部 Agent 和规则生成共享模型调用计数，失败调用也计数；生成修订不会吞掉主控预算耗尽信号。
时间预算在调用之间检查，不强制中断正在进行的调用。两次非法主控决策后停止；工具失败后不盲重试，转入人审。

- `state.json`：每步检查点、状态、计数和错误；目前用于查看，不支持断点恢复。
- `trace.jsonl`：每步可选动作、选择理由、实际工具和返回结果。
- `handoff.json`、`candidates.json`、`coverage.json`、`events.json`、`rule_tests.json`：沿用现有契约。
- `specialist-NNN.json`：Sigma 局部分析轨迹。
- `case_result.json`：规范汇总、未处理项、人审队列、可选生成结果引用。
- `incomplete_result.json`：A 阶段未能产生有效交接包时的失败说明。

`completed_with_review` 只表示选中流程结束，仍有人审；`partial_with_review` 还存在未选中行为；`budget_exhausted` / `controller_error` 返回非零退出码并保留部分结果。

## 本机实测

2026-11-22，qwen3:4b 模型主控在一个已确认 whoami 行为上完成 7 步、9 次共享模型调用：读取上下文→召回→核对日志→Sigma 分析→执行→人审→结束。
召回的是带特权进程限制的 whoami 规则：模型适用性判断为 draft，OTRF 两条样本实际 miss，二者独立保留。模型条件判断仍可能错误，需人工复核，不能把这次运行当作推理准确率评估。
BITS 显式生成分支完成 4 步、1 次生成模型调用，开发样例及最终合成边界样例符合预期，原行为未被自动确认。
运行产物在本地 `artifacts/runs/case-agent-model-v2/`、`artifacts/runs/case-agent-generation-v1/`，均被 Git 忽略。
