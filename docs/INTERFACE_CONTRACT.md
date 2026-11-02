# Threat2Detect 模块数据契约 v1.0

2026-11-01 冻结。**本文是并行开发时字段名与状态值的唯一准绳**；`docs/PROJECT_HANDOFF.md` 介绍职责和流程，`docs/REVIEW_PROTOCOL.md` 说明人工怎么判。所有模块交换 UTF-8 JSON。增字段可以，改本表字段含义、枚举或 ID 规则须由组长统一改版本并通知全组。

## 共同约定

- 每个文件有 `schema_version: "1.0"`、`kind` 和所属的 `case_id` 或 `scenario_id`。`case_id` 用 CISA 产品号，如 `AA25-266A`。
- **官方报告级映射**只放在 `data/reports/*-reference.json`，仅供评估和争议复核。`case_handoff` 不携带官方 ID 或官方版本；人工黄金行的理由必须由去答案正文和 ATT&CK 技术定义独立推导。
- `behavior_id` 是一个输入包内的稳定主键。人工黄金行使用 `AA25-266A-G001`，Agent 预测可使用 `AA25-266A-P001`。A/B、日志和报告都通过这个键引用行为。
- 一个行为可有 **0、1 或多条** `Mapping`；每条只写一个 `technique_id`。因此 PowerShell 下载工具可同时有执行与工具传入映射，但每个 ID 需各自给理由。无足够证据时不造 ID，行为仍保留。
- 同一技术可以对应多条行为。GeoServer 1 的 `ipconfig` 与 SQL Server 的 `ipconfig /all` 主机、命令参数和证据位置不同，应有独立 `behavior_id`，都可映射 T1016；报告级统计可按技术 ID 去重，但展示和规则条件对照必须保留各条行为。仅在同一主机、同一动作和同一证据指向同一次执行时才考虑合并重复提取。
- `evidence.quote` 必须逐字对应 `report.input_path` 的 `[char_start,char_end)`，结束位置不包含在内。PDF 页码是辅助定位；清洗前原文和无答案输入不能混用字符位置。
- `fact_status` 只取 `observed`（报告明确观察到）、`attempted`（尝试）、`inferred`（作者推断）、`unclear`。`review_status` 只取 `draft`、`confirmed`、`disputed`、`insufficient_evidence`；供组员 B 调优的黄金行必须为 `confirmed`。
- `origin` 只取 `cisa_inline`、`cisa_table`、`team_review`、`agent_proposal`。人工黄金行统一使用 `team_review`；官方标签来源不得进入预测或标注阶段的交接包。
- 字段未知用 `null` 或显式状态，不能用空字符串伪装已知。`[]` 表示确认当前没有条目；尚未检查用 `not_assessed` 或 `null`。规则适用性、日志运行结果和误报估计分开存储。
- 所有输出包含实际使用的输入文件哈希/目录版本。**文件路径是项目根目录相对路径**，方便各组员电脑使用；外部来源另记 URL。

## 模块边界

| 阶段 / 负责人 | 输入 | 输出 `kind` 与必须字段 | 停止/失败状态 |
|---|---|---|---|
| 0. 案例准备 / 组长 | CISA PDF、固定 ATT&CK 目录 | `case_handoff` 初始包：`report{case_id,title,source_url,input_path,input_sha256,annotation_basis}`；人工/Agent 行加入 `behaviors`、`mappings` | 清洗残留 ID 或哈希不符即拒绝 |
| 1. 行为提取 / A | `report.input_path` 全部攻击相关正文 | 更新 `case_handoff.behaviors[]`：`behavior_id,evidence{quote,char_start,char_end,pdf_page},action,object,fact_status,confidence,origin,review_status` | 引句无法定位时不入库，写 `warnings` |
| 2. ATT&CK 映射 / A | `behaviors[]`、固定目录 | 更新 `case_handoff.mappings[]`：`mapping_id,behavior_id,technique_id,technique_name,rationale,confidence,origin,review_status,retrieved_candidate_ids`；包内 `attack_catalog{version,sha256,path}` | 候选未召回与模型选错分开记录；ID 不在目录则拒绝 |
| 3. 可观测性 / A 或组长 | 行为、映射、当前数据清单 | 更新 `case_handoff.telemetry[]`：`behavior_id,required_sources[{product,category,event_ids,fields,reason}],available_dataset_ids,assessment,reason` | `assessment` 为 `testable` / `partial` / `unavailable` / `not_assessed` |
| 4. Sigma 召回 / B | **确认**的行为+映射、SigmaHQ commit | `rule_candidates`：`items[{candidate_id,behavior_id,technique_id,rule_id,rule_path,rule_sha256,title,tags,logsource,status,required_fields,retrieval_reason}]`，包内 `ruleset_commit` | 未找到规则时 `items:[]`，不等于“无覆盖” |
| 5. 规则条件对照 / B | 行为原文、候选规则完整 YAML | `coverage_assessments`：`items[{coverage_id,candidate_id,behavior_id,decision,supporting_conditions,missing_conditions,unknown_conditions,explanation,review_status}]` | `decision` 为 `matches_procedure` / `partially_matches` / `does_not_match` / `insufficient_detail` |
| 6. 日志标准化 / C 或组长 | OTRF JSON、数据集说明 | `normalized_events`：`dataset_id,source_path,parse_error_count,items[{event_uid,event_code,channel,host,timestamp_raw,fields,raw_ref}]` | 解析失败数必须保留，不能静默丢弃 |
| 7. 本地规则运行 / 组长 | 候选规则 YAML、标准化日志 | `rule_tests`：`items[{candidate_id,dataset_id,status,matched_event_uids,events_evaluated,events_skipped,unsupported_features,reason,engine_version}]` | `status` 为 `hit` / `miss` / `not_tested` / `incompatible_logsource` / `unsupported_rule` |
| 8. 汇总 / 组长 | 上述所有包 | 人可读报告及 `case_result`：行为、映射、规则适用、实际命中、未验证范围分栏引用原记录 ID | 缺一层证据就保留未知，不升级成“已检测” |

### A → B 的固定交接点

B 只依赖 `case_handoff` 的 `report`、`behaviors`、`mappings` 和 `attack_catalog`；需要日志需求时再读 `telemetry`。开发时用 `origin: team_review` 且 `review_status: confirmed` 的黄金行；集成时换成 `origin: agent_proposal` 的同结构结果。B 不依赖 A 的提示词、模型调用方式或原始输出格式。CISA 官方原标及 `*-reference.json` 永远不进入 Agent 的预测输入或成员 A 的盲标输入。

**注意：**当前 `agent_poc.py` 是实验输出，`mapping` 嵌在行为里且每行为单 ID。成员 A 负责把它转换成上面的 `behaviors[]` 与 `mappings[]`，并支持一对多；B 不应直接解析实验 JSON。

### B 的两个结论不可合并

`coverage_assessments.decision` 只判断规则 YAML 的条件与报告**具体做法**是否相符；`rule_tests.status` 只陈述规则在**指定静态日志样本**上是否命中。报告与 OTRF 场景来源不同，结果必须保留各自的 `behavior_id`、`dataset_id` 和事件 ID。

## 组长的独立规则生成模块

这个模块**不依赖** `rule_candidates` 或 B 的覆盖结论。输入 `rule_generation_request`：`scenario_id,behavior,attack_ids,logsource,available_fields,positive_event_refs,negative_event_refs,executor_supported_features,detection_goal`。可以由组长手工填写 LSASS/Dumpert 场景作为开发样例。

`positive_event_refs[]` 与 `negative_event_refs[]` 的每项为 `{dataset_id,event_uid,provenance}`；`provenance` 取 `public_attack` / `public_benign` / `local_capture` / `synthetic`，不能把自造事件冒充独立公开数据。

输出 `rule_generation_result`：`scenario_id,candidate_yaml_path,candidate_yaml_sha256,parse_status,required_fields,positive_tests[],negative_tests[],limitations`。`parse_status` 为 `valid` / `invalid` / `unsupported_syntax`；每个测试项为 `{dataset_id,tested_event_uids,matched_event_uids,status,reason}`，`status` 取 `hit` / `miss` / `not_tested` / `unsupported_rule`。若生成失败，YAML 路径/哈希为 `null`，原因写入 `limitations`。只有主流程需要使用新规则时，才追加 SigmaHQ 重复检查和真实缺口核对。

## 人工填写顺序

1. `data/annotations/aa25_266a_gold_draft.json` 中已有 4 条组长确认的行为及映射，是小规模审核样本，不代表全篇已标完。新增行仍需从去答案报告正文独立分析，确认后再把 `review_status` 改为 `confirmed`；别从 Agent 预测中反推答案。
2. SigmaHQ 已固定 commit。`data/annotations/aa25_266a_rule_candidates.json` 是真实候选规则清单；`data/annotations/coverage_gold_template.json` 已填 4 条示范判断，均已由组长复核为 `confirmed`，可供 B 调优。B 以后可扩大规则集并把争议结论交回组长。
3. A、B 分别拿确认行调优，各自保存版本、输入哈希和错误清单；组长审核新争议，不逐行代替他们跑实验。

示例文件用 `python validate_contract.py <文件路径>` 校验结构、引用与报告引句位置。后续跨模块交付时带上游文件，例如：

首次在其他成员电脑运行前安装 `python -m pip install -r requirements-poc.txt`。

```powershell
python validate_contract.py rules_output.json --handoff data/annotations/aa25_266a_gold_draft.json
python validate_contract.py coverage_output.json --handoff data/annotations/aa25_266a_gold_draft.json --candidates rules_output.json
python validate_contract.py rule_tests_output.json --candidates rules_output.json --events normalized_events.json
```

验证器会检查行为/技术连接、候选规则引用及命中事件 ID；它不能代替安全语义复核。草稿黄金行的 `review_status` 必须由组长确认后才能作为 B 的调优答案。
