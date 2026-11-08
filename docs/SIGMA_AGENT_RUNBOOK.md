# Sigma 条件分析 Agent：首版

`sigma_agent.py` 只判断**报告描述的具体做法**与一条 Sigma 规则是否相符，不执行规则，也不把报告与 OTRF 当作同一次事件。它接受现有 `case_handoff` 与 `rule_candidates`，输出同一个 `coverage_assessments` 契约，因此可以与旧的单次判断器对照。

## 运行

从项目根目录运行，先确保本机 Ollama 已启动且有 `qwen3:4b`：

```powershell
python sigma_agent.py data/annotations/aa25_266a_gold_draft.json data/annotations/aa25_266a_rule_candidates.json artifacts/runs/sigma-agent/coverage-r003.json --candidate-id AA25-266A-R003 --max-steps 5
python validate_contract.py artifacts/runs/sigma-agent/coverage-r003.json --handoff data/annotations/aa25_266a_gold_draft.json --candidates data/annotations/aa25_266a_rule_candidates.json
```

输出旁边的 `coverage-r003_trace.jsonl` 记录每一步工具选择、工具返回、模型提出的判断和校验反馈。Agent 可选择 `inspect_rule`、`read_context`、`check_fields`、`finish`；同一工具不可重复调用。`inspect_rule` 必须在结束前调用。达到 `--max-steps` 后仍没有合格结论，就输出 `insufficient_detail` 和停止原因，而不编造确定判断。

统一流水线可加 `--agent-coverage --agent-max-steps 5`。例如：

```powershell
python pipeline.py --handoff data/annotations/aa25_266a_gold_draft.json --events artifacts/runs/otrf_lsass_normalized.json --output-dir artifacts/runs/pipeline-agent-demo --limit 1 --max-coverage 1 --max-rules 1 --agent-coverage --agent-max-steps 5
```

`--limit`、`--max-coverage`、`--max-rules` 是演示预算；未处理的候选在 `case_result` 中保持 `null`。Agent 判断始终为 `review_status: draft`。只用 `--include-draft` 才会独立分析 A 阶段的未审核预测；统一流水线会在输入含草稿时显式传入该选项。

## 当前校验与边界

首轮用已复核的 R001、R003 检查。R001 的 `whoami` 分支得到 `matches_procedure`。R003 含 `ParentImage` 排除条件；报告目标引句没有父进程值，初判被退回后得到 `insufficient_detail`，与人工行的结论一致。校验器保守检查 `ParentImage` 的否定过滤条件，并阻止“列出未知/缺失条件却声称完全匹配”。这只是一项具体护栏，不代表能正确解析所有 Sigma 语法或代替人工审核。

下一轮调优应在已确认的四条判定样本和更多盲测样本上逐项比较：最终结论、必需字段解释、工具调用次数、无效工具调用、反馈后是否正确修正。不要把人工答案放进 Agent 输入；人工判定表只用于跑完后的评估。
