# 成员 B：Sigma 检索与规则条件分析

## 任务边界

你的输入是已确认的报告行为与 ATT&CK 映射；输出是**候选 Sigma 规则**和**规则条件对该具体行为的适用性判断**。本地日志标准化、Sigma 实际运行和最终报告由组长集成负责。你可以用已复核的 OTRF 事件样本检查自己是否读对 YAML 条件，但不能用该数据集的命中证明 CISA 事件被检测到。

先读[接口契约](INTERFACE_CONTRACT.md)的阶段 4–5 和 A→B 交接点，再读[判定方法](REVIEW_PROTOCOL.md)的成员 B 部分。固定规则库为 `data/sigma`，commit `05d1031f537e830b76da53bae2400c5814c89165`。所有命令从项目根目录运行。

## 输入与起步样本

| 文件 | 用法 |
|---|---|
| `data/annotations/aa25_266a_gold_draft.json` | 其中 4 条 `behaviors[]` 和 4 条 `mappings[]` 已是 `confirmed`；文件名沿用早期名称。只使用已确认行。 |
| `data/attack/enterprise-attack-20.0.json` | 固定技术目录；ID 与名称校验。 |
| `data/annotations/aa25_266a_rule_candidates.json` | 4 条人工挑选的真实规则候选，示范 `candidate_id`、Sigma `rule_id`、路径、SHA-256 和召回理由。 |
| `data/annotations/coverage_gold_template.json` | 报告 × 规则条件对照示范，四行均已由组长复核为 `confirmed`；C002 的结论仅针对报告列出的命令，若后续取得完整命令行需重新判断。 |
| `data/annotations/otrf_lsass_event_judgement_reviewed.md` | 6 组已复核的真实事件 × 规则**人工条件推演**；用于练字段和 YAML 布尔条件，不是 Sigma 引擎执行结果。 |

`candidate_id` 是项目内每组“行为 × 规则候选”的编号；SigmaHQ 的真实规则编号在 `rule_id`，文件在 `rule_path`。同一规则用于多个行为时可以有多个 `candidate_id`。

## 工作顺序与交付

1. **召回。** 对每条已确认的 `behavior_id + technique_id`，先用 `attack.tXXXX` tag、标题和 YAML 条件检索候选。tag 只说明值得检查；同 tag 的规则可能要求完全不同的参数或进程关系。保存规则 `id`、项目根目录相对路径、SHA-256、`status`、`logsource` 和召回理由。输出符合 `kind: rule_candidates` 的 JSON。找不到时保留空列表，不宣称“无覆盖”。
2. **逐条件对照。** 阅读完整 `detection`、`condition` 和所有过滤器，列出规则真正要求的字段。判断报告是否明确支持、明确不符，还是没有决定性信息。`Image` 与 `OriginalFileName` 等 OR 分支不能误写成 AND；`contains|all`、`windash` 和过滤项也要按实际语义处理。输出 `kind: coverage_assessments` 的 JSON，逐项引用 `candidate_id` 与 `behavior_id`。
3. **保留未知的边界。** 威胁报告没有原始日志是案例级测试限制，无须在每一行重复。只有缺少 `ParentImage`、参数、用户等**会改变该条规则结论**的信息才写入 `unknown_conditions`。`matches_procedure` 表示做法在条件上适用，不表示已运行或命中。`does_not_match` 要指出具体冲突条件；拿不准就用 `insufficient_detail`，并写出还需哪个字段。
4. **用 OTRF 样本练匹配。** 先人工复现已复核样本 E01–E06 的逻辑，再考虑自动化解析。事件在 JSONL 的行号和 YAML 规则路径均已给出。背景候选并非已证实良性；攻击相关事件上的规则 `miss` 也不意味着事件良性。真正的 `rule_tests.status` 需执行器运行、保存事件 ID 与引擎版本，由组长负责集成。
5. **提交争议。** 给组长发具体 `behavior_id`、`candidate_id`、YAML 条件、原文引句、你的判断和不确定点。新增行在组长复核前保持 `review_status: draft`。不要读取 CISA `*-reference.json` 来反推行为映射，也不要把当前四条示范规则硬编码为唯一候选。

最小交付是：可复现的规则检索函数、候选 JSON、逐条件覆盖 JSON、所用 Sigma commit/规则哈希，以及一份错误与争议清单。成员 A 的实验输出格式尚未等同正式 `case_handoff`；集成时请按接口契约接收 `behaviors[]` 与 `mappings[]`，不要直接解析 `agent_poc.py` 的嵌套实验 JSON。

## 校验

首次运行：`python -m pip install -r requirements-poc.txt`。下面的路径以你的实际输出文件替换：

```powershell
python validate_contract.py rules_output.json --handoff data/annotations/aa25_266a_gold_draft.json
python validate_contract.py coverage_output.json --handoff data/annotations/aa25_266a_gold_draft.json --candidates rules_output.json
```

验证器检查结构和引用，不替代人工核对 YAML 的语义。遇到不支持的 Sigma 修饰符或布尔写法，应记录具体规则和语法，不要把“无法执行”写成 `miss`。
