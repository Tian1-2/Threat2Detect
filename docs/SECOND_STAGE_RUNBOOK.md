# 第二部分：Sigma 检索与条件对照的独立运行

在项目根目录运行；先安装 `python -m pip install -r requirements-poc.txt`，并确保 `data/sigma` 子模块已初始化，Ollama 已启动且有 `qwen3:4b`。输入 `data/annotations/aa25_266a_gold_draft.json` 虽保留旧文件名，其现有四条行为及映射均为 `confirmed`。

## 1. 规则召回（不需要模型）

```powershell
python sigma_retrieval.py data/annotations/aa25_266a_gold_draft.json artifacts/runs/aa25_266a_rule_candidates_poc.json --limit 10
python validate_contract.py artifacts/runs/aa25_266a_rule_candidates_poc.json --handoff data/annotations/aa25_266a_gold_draft.json
```

输出 `kind: rule_candidates`。候选来自 SigmaHQ 中带对应 `attack.tXXXX` 标签的规则，排序使用行为文字与 YAML 的词重叠。它是**召回**，不代表规则适用；Linux/Windows 日志源、父进程条件和过滤项须在下一步检查。黄金候选清单 `data/annotations/aa25_266a_rule_candidates.json` 用于核对有没有召回已知规则，不参与检索算法。

## 2. 条件对照（需要 Ollama）

先用 4 条人工挑选的规则进行受控演示：

```powershell
python sigma_coverage.py data/annotations/aa25_266a_gold_draft.json data/annotations/aa25_266a_rule_candidates.json artifacts/runs/aa25_266a_coverage_poc.json --max-items 4
python validate_contract.py artifacts/runs/aa25_266a_coverage_poc.json --handoff data/annotations/aa25_266a_gold_draft.json --candidates data/annotations/aa25_266a_rule_candidates.json
```

成功后可把第二个参数换成上一步的检索输出；大量候选会产生多次模型调用，先用 `--max-items` 限制规模。输出 `kind: coverage_assessments`，每条 `review_status: draft`。与 `data/annotations/coverage_gold_template.json` 比对时，按 `candidate_id` 连接，不能把人工答案放进模型输入。

`matches_procedure` 只表示报告描述的做法符合规则条件；实际规则运行与命中要由后续日志模块负责。任何未支持的 Sigma 语法、缺失字段或规则库更新都应记入 `DEVELOPMENT_LOG.md`，不要自动当作规则 `miss`。
