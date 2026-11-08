# 三段流水线：固定接口串联

从项目根目录运行。统一入口是 `pipeline.py`，依次产生 `case_handoff`、`rule_candidates`、`coverage_assessments`、`normalized_events`、`rule_tests`、`case_result`。每段生成后按 `docs/INTERFACE_CONTRACT.md` 校验，汇总保留候选 ID、行为 ID、数据集 ID 和命中事件 ID。

## 使用已复核案例演示

先按 `docs/OFFLINE_SIGMA_RUNBOOK.md` 生成一次 `artifacts/runs/otrf_lsass_normalized.json`，然后运行：

```powershell
python pipeline.py --handoff data/annotations/aa25_266a_gold_draft.json --events artifacts/runs/otrf_lsass_normalized.json --output-dir artifacts/runs/pipeline-demo --limit 1 --max-coverage 1 --max-rules 1
```

需要本机 Ollama 的 `qwen3:4b`。`--limit` 限制每条映射召回的候选数；`--max-coverage` 限制模型条件对照数；`--max-rules` 限制离线执行数。未处理的候选在 `case_result.items` 中保留 `null`，不能读成未覆盖或规则未命中。`--skip-coverage` 可在无 Ollama 时检查数据接口，输出会明确记载条件对照未做。

要让 Sigma 分析阶段采用工具决策循环，追加 `--agent-coverage --agent-max-steps 5`；具体动作、轨迹和护栏见 [Sigma Agent 运行说明](SIGMA_AGENT_RUNBOOK.md)。

## 接入 A 阶段

新报告先人工准备去掉官方 ATT&CK 答案的 UTF-8 文本。流水线可直接调用原型 Agent：

```powershell
python pipeline.py --report data/reports/cisa-aa25-266a-input.txt --case-id AA25-266A --title "CISA Shares Lessons Learned" --source-url "https://www.cisa.gov/sites/default/files/2025-09/AA25-266A_advisory_cisa_shares_lessons_learned_from_ir_engagement.pdf" --events artifacts/runs/otrf_lsass_normalized.json --output-dir artifacts/runs/pipeline-agent --limit 1 --max-coverage 1 --max-rules 1
```

已有 `agent_poc.py` 预测时，追加 `--prediction <预测文件>` 可免去重新调用模型。适配器校验报告与 ATT&CK 目录哈希、原文引句位置及技术 ID，再把嵌套的实验输出拆为契约中的 `behaviors[]` 和 `mappings[]`。Agent 结果始终为 `draft`，可进入下游演示，不能伪装成人工确认。现有 A 原型每个行为只给一条 ATT&CK 映射；要支持一对多，需改进 A 的输出。

## 结果含义

`coverage.json` 是规则 YAML 与报告描述做法的纸面对照，属于模型草稿；若模型声称完全匹配却列出缺失或未知条件，程序会保守改为 `insufficient_detail` 并保留 `model_decision`。`rule_tests.json` 是选中规则在指定 OTRF 静态事件上的实际运行。二者由候选规则 ID 关联，但 OTRF 与 CISA 报告不是同一事件。`case_result.json` 分列这两个状态，并附有各层 JSON 路径供人工追溯。

首个端到端样例中，模型最初将 `whoami` 规则判为 `matches_procedure`，同时承认必需的用户字段未知；经过校验应为 `insufficient_detail`。该规则在 OTRF 样本中评估了 77 条兼容事件，结果为 `miss`。这两个结论的证据来源不同，不应合并成一个“检测成功/失败”判断。
