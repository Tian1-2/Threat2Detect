# Threat2Detect 开发日志

本文件记录**已做的改动、验证证据和遗留问题**。新增工作按日期追加，不覆盖旧结果。版本、输入文件和输出路径要一起记；模型实验不要只记一个分数。完整目标与字段约定分别见 `docs/PROJECT_HANDOFF.md`、`docs/INTERFACE_CONTRACT.md`。

## 截至 2026-11-07 的既有基线

以下是前期工作的状态汇总，并非逐日原始记录。

| 模块 | 已有内容 | 验证与限制 |
|---|---|---|
| 报告 → 行为 → ATT&CK | `agent_poc.py`，本地 Ollama `qwen3:4b`；三篇 CISA PDF 的去答案输入和报告级参考 ID | AA25-266A 的早期实验见 `docs/BASELINE_REVIEW.md`；原型输出还不是正式 `case_handoff`，行为提取和映射需要调优 |
| 人工答案 | AA25-266A 的 4 条行为及技术映射已确认；4 条报告 × Sigma 规则适用性已确认 | 样本只抽选第 8–9 页，不能据此声称全篇行为召回率 |
| 数据与规则 | Enterprise ATT&CK v20.0；SigmaHQ commit `05d1031f537e830b76da53bae2400c5814c89165`；OTRF LSASS_campaign_06 | 6 组 OTRF 事件 × 规则人工条件推演已确认；尚未用 Sigma 引擎执行；背景候选未获独立良性真值 |
| 版本管理 | 初始项目提交 `dbeb487` 已推送到 GitHub `main`；SigmaHQ 与 OTRF 作为子模块 | 之后的阅读指引简化改动在本机工作树中，尚未同步到远端；OTRF 解压 JSON 是子模块内的本地未跟踪文件 |

## 2026-11-07：第二部分拆分为独立模块

**改动**

- 新增 `sigma_retrieval.py`：读取正式 `case_handoff` 中已确认的行为与 ATT&CK 映射，扫描固定提交的 SigmaHQ `rules/` YAML；先按精确技术 tag 召回，再按行为文字与标题、检测条件、描述的词重叠排序。输出 `rule_candidates`，记录 Sigma 规则 ID、路径、SHA-256、logsource、规则字段和召回理由。`required_fields` 是规则涉及字段清单，OR 分支不要求它们同时出现。
- 新增 `sigma_coverage.py`：独立读取 `case_handoff`、候选列表和对应完整 YAML，经本地 Ollama 逐条提出 `coverage_assessments`。每条输出为 `draft`，仅判断**报告做法与规则条件**；不运行规则，不声称日志命中。规则文件哈希变化会中止运行。每完成一条就保存进度。
- `requirements-poc.txt` 增加 PyYAML 固定版本。

**已完成验证**

- 规则召回命令：`python sigma_retrieval.py data/annotations/aa25_266a_gold_draft.json artifacts/runs/aa25_266a_rule_candidates_poc.json --limit 10`。输出 35 个候选，YAML 解析跳过 0 条，契约验证通过；人工黄金中的 4 条 Sigma 规则均在对应行为的前 10 个候选中。
- 条件对照命令：`python sigma_coverage.py data/annotations/aa25_266a_gold_draft.json data/annotations/aa25_266a_rule_candidates.json artifacts/runs/aa25_266a_coverage_poc.json --max-items 4`。输出通过契约校验；与人工黄金的逐项比较见下表。

| 规则样本 | 人工答案 | 首轮模型 | 提示词修订后 | 结论 |
|---|---|---|---|---|
| C001：普通 whoami 分支 | `matches_procedure` | 同 | 同 | 正确，但解释错误地把另一个 WMI 分支也说成满足 |
| C002：whoami `/all` | `does_not_match`（针对报告列出的命令） | `matches_procedure` | `matches_procedure` | 错误；模型承认报告未给 `/all`，仍判匹配 |
| C003：whoami 父进程异常 | `insufficient_detail` | `matches_procedure` | `matches_procedure` | 错误；模型把父进程未知当成排除条件已通过 |
| C004：`ipconfig /all` 正则 | `matches_procedure` | 同 | 同 | 正确 |

提示词修订明确了目标命令、OR 分支、否定过滤条件和未知字段规则；第二轮输出位于 `artifacts/runs/aa25_266a_coverage_poc_v2.json`，仍是 2/4。两轮结果均为 `draft`，不能当自动覆盖结论。当前样本很小，不能把 2/4 当系统整体准确率。

**已知问题与下一步**

1. 召回排序只用 tag 与词重叠，`whoami` 的 Linux 规则排得靠前；需要结合报告主机平台、`logsource` 和过滤条件做重排，不能把高排名当覆盖结论。
2. 条件对照模型仍无法可靠处理必需参数与否定过滤条件。下一轮应考虑把 Sigma YAML 先解析为结构化布尔条件，再让模型只填报告中已知的字段，未知值由确定性逻辑保留；扩大样本前不能把模型输出自动升级为 `confirmed`。
3. `agent_poc.py` 仍只给每个行为一个技术 ID，且输出结构与正式契约不同；A 阶段需支持一对多映射和稳定引用。
4. 报告适用性和日志实际命中仍是两层。下一独立模块是 OTRF 字段标准化和选中 Sigma 子集的真实执行；必须保留事件 ID、跳过数、不支持语法及引擎版本。
5. 误报率需要独立、可靠标注的良性数据。现有 OTRF 背景候选只能用于条件检查和具体误命中案例。

## 2026-11-07：OTRF 标准化与离线执行

**改动**：新增 `normalize_otrf.py` 和 `run_sigma_offline.py`。前者直接读取 OTRF ZIP/JSONL，输出符合 `normalized_events` 契约的 Sysmon 1/10/11 字段；后者按选中 Sigma YAML 的检测条件对本地静态事件逐条求值，输出 `rule_tests`。命令、支持语法和边界见 `docs/OFFLINE_SIGMA_RUNBOOK.md`。

**验证**：OTRF 共保留 33,729 条事件、0 条解析错误。LSASS memdump 与 dump keyword 规则各命中 L33808、L34151；Local Accounts Discovery 命中 L20542、L20570。已复核的 E01–E06 正反例与执行结果一致。标准化文件约 45 MB，可重建，因此不纳入 Git。

**仍有问题**：执行器只实现本次选中规则所需的 Sigma 子集。规则在 OTRF 上命中不等于检测到 CISA 报告中的事件；需要继续完善跨模块汇总、更多规则语法和独立良性样本验证。

## 2026-11-07：目录整理与后续结构

**改动**：将原 `data/runs/` 移至 `artifacts/runs/`，同步更新运行说明、阅读入口和 Git 忽略规则；新增 `docs/PROJECT_STRUCTURE.md` 与 `artifacts/README.md`。固定输入、子模块及人工答案仍集中在 `data/`。主流程代码计划逐步迁入 `src/threat2detect/`，当前脚本保留原路径以维持命令兼容。

**后续整理**：将 `inspect_dataset.py`、`analyze_otrf_background.py`、`check_lsass_rule.py`、`build_cisa_cases.py`、`make_contract_examples.py` 移入 `tools/`，并更新文档命令。主流程命令暂留根目录。

**验证**：30 个测试通过；移动后的离线 `rule_tests` 及事件引用通过契约校验；`tools/` 中三个读取或补建脚本运行正常，其余脚本通过语法编译检查；阅读入口链接有效。约 45 MB 的标准化日志仍是本地可重建产物，不纳入 Git。

**仍有问题**：根目录仍有历史原型与新模块脚本。待主控编排接口稳定后逐个迁移，届时同步更新导入路径、命令与测试。本地工作树含此前未同步到 GitHub 的文档和代码改动。

## 2026-11-07 / 固定接口串联

**改动**：新增 `pipeline.py`，把报告 Agent 的实验 JSON 转为 `case_handoff`（行为、映射均为 `draft`），再通过 `rule_candidates`、`coverage_assessments`、`normalized_events`、`rule_tests` 汇总到 `case_result`。每步校验契约与外键；规则召回和条件对照增加只供流水线显式使用的草稿输入开关。新增 `docs/PIPELINE_RUNBOOK.md` 与转换、矛盾判断测试。

**输入与版本**：AA25-266A 已确认的 4 条行为；ATT&CK Enterprise 20.0；SigmaHQ commit `05d1031f537e830b76da53bae2400c5814c89165`；OTRF LSASS_campaign_06；条件对照模型 `qwen3:4b`。A 阶段旧预测另用作适配器检查，不作为人工答案。

**运行与验证**：使用 `--limit 1 --max-coverage 1 --max-rules 1` 的完整演示，得到 4 个候选、1 条条件判断和 1 条 OTRF 规则运行记录。模型把含未知必需字段的结果说成 `matches_procedure`；新增保守校验后输出 `insufficient_detail` 并保留原判。离线规则在 77 条兼容 OTRF 事件上为 `miss`。旧 A 预测中的 89 条行为、63 条映射通过转换契约，作为草稿进入检索，得到 54 个候选。`case_result` 外键校验通过；全部 33 个测试通过。

**仍有问题**：当前 A 原型每行为只输出一个 ATT&CK ID，尚未支持一对多；覆盖判断仍有模型错误，需人工复核和继续调优。首轮仅执行有限候选，未运行的状态保留为未知。OTRF 与报告属于不同事件，日志命中不能证明报告中的攻击被检测。

## 2026-11-08 / Sigma 条件分析 Agent 首版

**改动**：新增 `sigma_agent.py`，将单次条件判断改为有步骤上限的工具决策循环。可选择查看 YAML、读取报告上下文、查看所需字段，再提交 `coverage_assessments`。每个候选生成 JSONL 决策轨迹；统一入口 `pipeline.py` 加入 `--agent-coverage`。禁止重复工具调用，无法形成合格判断时以 `insufficient_detail` 停止。

**验证与发现**：在人工确认的 R001、R003 案例上运行。R001 经 `inspect_rule → finish` 得到 `matches_procedure`。R003 初次将缺失的 `ParentImage` 错当成排除条件不成立；加入否定过滤字段反馈后，轨迹为 `inspect_rule → 被退回的 finish → 修正的 finish`，最终 `insufficient_detail`，与人工判定一致。统一流水线加 Agent 选项后成功生成覆盖、日志规则运行和 `case_result`。这些只是首轮功能验证，不代表总体准确率。

**仍有问题**：当前字段护栏主要处理否定过滤中的 `ParentImage`；复杂 Sigma 条件仍可能误解。R001 解释曾混淆选择器列表中的 OR 与字段内 AND，需下一轮调优。暂未对全部人工判定样本和封存报告做量化评估。

## 2026-11-08 / Sigma Agent 第一轮错误调优

**改动**：新增 `tools/evaluate_sigma_agent.py`，按 `candidate_id` 对齐 Agent 结果、人工判定与决策轨迹；在 `sigma_agent.py` 增加显式命令缺少必需 `windash` 参数的反馈。

**对照**：同一组四条已复核判定，v1 为 3/4；R002 把没有 `/all` 的 `whoami` 错判为 `partially_matches`。v2 一次运行是 4/4；R001、R003、R004 结论未变。R002 的 v2 轨迹中没有反馈退回，模型直接给出正确结论，因此不能将这一次改善全归因于护栏。单元测试验证错误提案会被反馈退回。

**仍有问题**：四条是开发样本，不是封存测试；需要重复运行并用更大的独立案例集评估稳定性。解释中的 Sigma OR/AND 语义和 `falsepositives` 元数据理解仍需逐项核查。

**解释校验补充**：加入“规则已触发”与“信息不足却说规则不适用”的反馈。v3 四条分类仍为 4/4，R003、R004 各经过两次反馈修正；但 R001、R003、R004 的解释仍有逻辑含糊或过于笼统的问题。不能以分类标签全对宣称分析质量已达标。

## 每次新改动的记录格式

### 2026-11-22 / 独立候选规则生成与验证

新增 `generate_rule.py`，沿用规则生成请求/结果契约，支持本机 Ollama 的结构化条件生成、确定性 YAML 编译、字段和日志源校验、1–5 次错误/样例反馈修订。支持 `--candidate` 独立验证模式；保存请求、原始模型提议、每轮候选、轨迹、输入及规则哈希。无效、失败、不完整与开发样例通过分开记录，全部候选仍待人工审核。

新增 `tools/prepare_rule_generation_demo.py`，从现有 OTRF ZIP 提取 L33808/L1727；后者仅为预期不匹配的背景候选，不是已证实良性。`tests/test_rule_generation.py` 覆盖真实执行器匹配、缺失/不兼容样本、有限修订、失败记录、字段与语法限制、YAML 重复键以及必需条件遗漏。

实测：`qwen3:4b` 直接输出 YAML 时格式失败；结构化输出曾产生能通过两条样例但未限定目标的过宽候选。加入人工 `required_conditions` 护栏后，`rule-generation-0.4` 在本地 `artifacts/runs/rule-generation-ollama-v4/` 首轮生成 TargetImage 以 LSASS 文件名结尾且 GrantedAccess=0x1FFFFF 的候选，L33808 hit、L1727 miss。结果契约通过。

边界：这些是指定开发样例，不是独立效果验证；未做 SigmaHQ 重复检查和真实缺口判断，未接入主控流水线或前后端。运行方式见 `docs/RULE_GENERATION_RUNBOOK.md`。本地生成产物被 Git 忽略；原有组员开发改动保留。

### 2026-11-22 / 规则生成第二轮

新增 `rule_generation_review.py`：条件依据引用检查、逐字段/选择器诊断、开发/最终评估隔离、重命名复制事件检测。提示词 v0.5 记录条件证据 ID 和解释；仅开发样本结果反馈给模型，最终固定候选后另行执行封存事件。引用存在不代表语义被机械证明，结果仍 draft。

准备工具新增 BITS 和合成边界测试。真实开发样本 LSASS L33808/L1727、BITS L118/L149，各自本机 qwen3:4b 首轮生成，开发正例 hit、背景候选 miss，各四条合成边界事件符合预期。没有独立真实攻击/良性日志，不估计误报率。

检索保存 10 个 Sigma 官方教程/规则 URL，整理 6 个附来源的教学草稿。未更新固定规则库。当前网页规则只供阅读，本地引用按固定规则哈希追溯；旧 Rule-Creation-Guide 跳转 Wiki 首页，改用 High-Level Guide。

### 2026-11-22 / 主控 Case Agent

新增 `case_agent.py` 与 `src/threat2detect/pipeline/controller.py`，实现单主控的状态相关动作选择、共享模型调用计数、步数/检索/行为预算、调用间时间检查、检查点、工具轨迹和人审停止。复用 A 原型、Sigma 局部 Agent、召回和离线执行，原固定流水线不变。A 与 Sigma 入口只增可选 llm 回调，使内部调用计入主控预算；规则生成增预算中止异常透传。

规则生成默认关闭；仅用户计划中 `explicit_request` 或满足全部已检索候选不适用条件的 `coverage_gap` 触发，空召回/信息不足不当作缺口。生成结果与既有规则测试分开，保持 draft。BITS 准备工具可生成显式请求示例，原报告行为不自动确认。

本机 qwen3:4b 主控完成 7 步、9 次调用的 whoami 小案例，独立样例实际 miss；模型报告适用性结论仍 draft，且部分主控理由过度表述，因此理由不作为已核实事实。BITS 分支完成 4 步、1 次生成调用，开发/合成边界样例通过。首次大日志实测出现检查点反复写大文件失败，改为不可变输入只写一次、JSON 临时文件替换；小样本重新实测通过。

限制：默认只选前三条行为，剩余项明确列出；时间预算不强制打断进行中的调用；检查点暂不支持恢复。真实命令与产物见 `docs/CASE_AGENT_RUNBOOK.md`。模型推理质量仍需独立评估与人工复核；当前没有前后端或外部部署。

```text
日期 / 模块：
改动：涉及文件、接口字段、原因
输入与版本：报告哈希、ATT&CK 版本、Sigma commit、模型与提示词版本
运行命令与输出：
验证：契约、测试、人工黄金差异、日志事件 ID
仍有问题：具体失败例、影响范围、下一步负责人
```
