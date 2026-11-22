# 第二部分：Sigma 检索与条件对照的独立运行

在项目根目录运行；先安装 `python -m pip install -r config/requirements.txt`，并确保 `data/sigma` 子模块已初始化，Ollama 已启动且有 `qwen3:4b`。输入 `data/annotations/aa25_266a_gold_draft.json` 虽保留旧文件名，其现有四条行为及映射均为 `confirmed`。

## 1. 规则召回（不需要模型）

```powershell
python -m src.threat2detect.sigma.retrieval data/annotations/aa25_266a_gold_draft.json artifacts/runs/aa25_266a_rule_candidates_poc.json --limit 10
python -m src.threat2detect.contracts artifacts/runs/aa25_266a_rule_candidates_poc.json --handoff data/annotations/aa25_266a_gold_draft.json
```

输出 `kind: rule_candidates`。候选先按精确 `attack.tXXXX` 标签召回，再执行平台和事件类别过滤、IDF 加权词项排序、规则状态加权和选择器条件降权。`candidate_id` 由 `mapping_id` 与规则 ID 前缀组成，重新排序不会破坏覆盖分析和执行结果引用。它是**召回**，不代表规则适用；父进程、参数和过滤项仍须在下一步检查。

检索回归与对比：

```powershell
python -m src.threat2detect.sigma.retrieval data/annotations/aa25_266a_gold_draft.json artifacts/runs/sigma_retrieval_optimized.json --limit 10
python tools/evaluate_sigma_retrieval.py data/annotations/aa25_266a_gold_draft.json data/annotations/aa25_266a_rule_candidates.json artifacts/runs/sigma_retrieval_baseline.json artifacts/runs/sigma_retrieval_optimized.json artifacts/runs/sigma_retrieval_comparison.json
```

AA25-266A 的 4 条人工规则上，Recall@5 从 0.25 提升到 0.75，MRR 从 0.3385 提升到 0.5875，Top-10 错误平台候选从 7 降到 0。黄金候选只覆盖 4 条规则，不能据此计算 precision 或总体准确率。

## 2. 条件对照（需要 Ollama）

先用 4 条人工挑选的规则进行受控演示：

```powershell
python -m src.threat2detect.sigma.coverage data/annotations/aa25_266a_gold_draft.json data/annotations/aa25_266a_rule_candidates.json artifacts/runs/aa25_266a_coverage_poc.json --max-items 4
python -m src.threat2detect.contracts artifacts/runs/aa25_266a_coverage_poc.json --handoff data/annotations/aa25_266a_gold_draft.json --candidates data/annotations/aa25_266a_rule_candidates.json
```

成功后可把第二个参数换成上一步的检索输出；大量候选会产生多次模型调用，先用 `--max-items` 限制规模。输出 `kind: coverage_assessments`，每条 `review_status: draft`。与 `data/annotations/coverage_gold_template.json` 比对时，按 `candidate_id` 连接，不能把人工答案放进模型输入。

`matches_procedure` 只表示报告描述的做法符合规则条件；实际规则运行与命中要由后续日志模块负责。任何未支持的 Sigma 语法、缺失字段或规则库更新都应记入 `docs/DEVELOPMENT_LOG.md`，不要自动当作规则 `miss`。
