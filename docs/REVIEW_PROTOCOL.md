# CISA 案例的判定表与下一轮人工标注

本文件给成员 A（报告→ATT&CK）和成员 B（ATT&CK→Sigma）使用。**CISA 自带映射表是报告级参考答案**；它告诉我们报告涉及哪些技术，但不总能说明一个命令应如何划分行为、它的证据在哪一句、或某条 Sigma 规则是否覆盖。以下两个表补足这些层次，不把团队判断冒充 CISA 原标。

## 1. 成员 A：行为级核对表

组长先从 **AA25-266A 开发案例**确定约 10–20 个代表性行为级答案，覆盖正确、漏报、错报、尝试和推测；成员 A 据此调优并提交新增争议行供组长裁决。暂不人工标注所有报告，也不打开封存测试案例 AA24-193A。位置以 `data/reports/cisa-aa25-266a-extracted.txt` 的行号或 PDF 页码为准；把正文连续上下文一起读，不能只看命令名。正式交接字段见 `docs/INTERFACE_CONTRACT.md`。

| 字段 | 记录什么 |
|---|---|
| `behavior_id` | 稳定编号；同一个动作的多个命令/路径合并为一项 |
| `evidence.quote / char_start / char_end / pdf_page` | 在无答案输入中逐字可定位的引句与位置；PDF 页码辅助核对，不能凭常识补事实 |
| `action / object` | 攻击者**对什么做了什么**；工具名与目的写在同一项 |
| `fact_status` | `observed` / `attempted` / `inferred`；证据不足用 `unclear` |
| `mappings[].technique_id / origin` | 每个接受的 v20 技术单独一条映射；独立人工标注使用 `team_review`。CISA 报告级 ID 仅存于独立 `*-reference.json`，盲标完成后才对照 |
| `mappings[].rationale` | 为何选这个技术、为何没有细分；多技术各写各的理由 |
| `review_status` / `reviewer` | `draft` / `confirmed` / `disputed` / `insufficient_evidence`，以及复核人；争议行不强行写成确定答案 |

`agent_result` 与 `error_type` 是调优时的**评估记录**，不属于给 B 的黄金交接包。成员 A 可另记 `correct`、`missed_behavior`、`wrong_technique`、`unsupported_inference`、`over_split`、`candidate_not_retrieved`、`needs_review`，并引用对应的 Agent 输出 ID。

### 四条起步核对行

这些是**核对任务，不是自动生成的黄金答案**。原始报告的命令列表与上下文见提取文本约第 267–290 行；fscan 和 Stowaway 见约第 259–317 行。以下 ID 在 CISA 官方映射表中均存在。

| 行 | 报告中的动作 | CISA 参考 ID | 下一轮重点核对 |
|---|---|---|---|
| A01 | SQL Server 上执行 `whoami`，识别当前用户 | `T1033` | Agent 有没有保留 SQL Server 上下文？ |
| A02 | SQL Server 上执行 `ipconfig /all`，查看网络配置 | `T1016` | 是否误选 `T1049`（网络连接发现）？ |
| A03 | SQL Server 上执行 `tasklist`，列出进程 | `T1057` | 是否误选 PowerShell 或泛化的命令解释器技术？ |
| A04 | 使用 Stowaway 转发 C2 流量访问内网资源 | `T1090` | 是否误把工具名映成 Windows 服务、远程访问工具？ |

另加两种**否定或限定**样例：报告中 RingQ 仅由文件名推测，不能标为确认运行；fscan 的某些参数明确排除了暴力破解或漏洞扫描，不能把“具有该能力”直接写成“实际实施”。

若 CISA 表给出某个 ID，但正文没有足够细节定位到唯一行为，可以保留报告级原标并将行为级 `review_status` 标为 `disputed` 或 `insufficient_evidence`，不为了凑齐 22 个 ID 编造引句。新版本的 Agent 输出会保存 `retrieved_candidate_ids`，便于区分“检索没找到正确技术”和“模型在候选中选错”。

每轮调优只改一个主要因素，并保存 `prompt_version`、输入哈希、ATT&CK 目录哈希、模型版本、每条核对行结果。第一轮先用 AA25-266A，第二轮在 AA23-319A 检查迁移；最后才打开 AA24-193A。**不要把 A01–A04 的正确 ID 写进 Agent 提示词**。

## 2. 成员 B：Sigma 规则覆盖判定表

组长先在固定 SigmaHQ commit 中选 2–3 条真实规则，对照已确认行为填写少量基准行；B 用这些行优化召回与覆盖分析，不必等待成员 A 把 Agent 调好。每个候选规则填一行：

| 字段 | 记录什么 |
|---|---|
| `candidate_id / behavior_id / technique_id` | 将真实候选规则与已确认的具体行为、技术连接 |
| `rule_id / rule_path / rule_sha256 / ruleset_commit` | SigmaHQ 规则的稳定出处、内容哈希与版本 |
| `retrieval_reason / tags` | 是 ATT&CK tag、标题还是条件命中；tag 仅负责召回 |
| `logsource / required_fields` | 规则实际要求的事件源与字段 |
| `supporting_conditions / missing_conditions / unknown_conditions` | 对完整 YAML 条件逐项注明报告支持、冲突或未提供的部分 |
| `decision / explanation` | `matches_procedure` / `partially_matches` / `does_not_match` / `insufficient_detail`，并逐条件解释 |
| `review_status` | 组长确认前保持 `draft`，争议项保留 `disputed` |

本地运行结果另存 `rule_tests`，包括 `status`、`dataset_id` 和命中事件 ID；不要把 `hit` 写进覆盖判断行。

例如 A03 的 `tasklist` 不能因为某规则带 `attack.t1057` 就判覆盖；还需看它是否监测进程创建、是否匹配 `tasklist.exe` 或命令行、日志中有无对应字段。**报告做法的规则适用性**和**OTRF 样本上的实际命中**是两个独立结论。

## 3. 候选新规则：独立开发模块

组长可现在单独开发规则生成，不依赖 B 的检索成果。先用**人工给定的检测目标**作为输入，例如：

```json
{
  "schema_version": "1.0",
  "kind": "rule_generation_request",
  "scenario_id": "manual-demo-01",
  "behavior": "可疑进程访问 LSASS 内存并尝试转储",
  "attack_ids": ["T1003.001"],
  "logsource": {"product": "windows", "category": "process_access", "service": null},
  "available_fields": ["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
  "positive_event_refs": [],
  "negative_event_refs": [],
  "executor_supported_features": ["contains", "endswith", "and", "or", "not"],
  "detection_goal": "识别具有明确 LSASS 进程访问证据的可疑转储尝试，并报告未测误报风险"
}
```

模块输出候选 YAML、字段/条件解释、解析校验结果、正反例运行结果和未评估风险。它可以用人工指定的案例反复优化；**不需要 B 先证明现有规则有缺口**。将来项目主流程要调用它时，再额外检查是否与固定版本 SigmaHQ 规则重复、是否真填补了当前目标的缺口。单靠自己写的正例命中，不能宣称规则有效或误报低。
