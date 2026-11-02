# Threat2Detect 阅读与操作指引

从项目根目录运行下列命令。组内交换 JSON 时，路径均相对项目根目录。先读本页，再按当前任务打开对应文件。

## 先读什么

1. [项目总说明](docs/PROJECT_HANDOFF.md)：目标、架构、四人分工和边界。
2. [接口契约](docs/INTERFACE_CONTRACT.md)：模块交接所用的 JSON 字段、状态和 ID。并行开发以它为准。
3. [人工审核方法](docs/REVIEW_PROTOCOL.md)：行为与 ATT&CK 映射、Sigma 适用性各怎么判。
4. [数据版本](docs/DATA_VERSIONS.md)：ATT&CK v20.0 与本地 SigmaHQ commit。

其余材料按用途读：[首个 Agent 原型运行](docs/POC_RUNBOOK.md)、[首轮实验复盘](docs/BASELINE_REVIEW.md)、[三篇报告的全篇梳理](docs/GOLDEN_REPORTS_FULL.md)、[初选报告概览](docs/GOLDEN_REPORTS.md)、[OTRF LSASS 场景](docs/FIRST_SCENARIO.md)、[OTRF 日志盘点](docs/OTRF_LOG_ANALYSIS.md)及[事件 × 规则判定样本](data/annotations/otrf_lsass_event_judgement_reviewed.md)、[成员 B 操作指引](docs/MEMBER_B_GUIDE.md)。`docs/mermaid-diagram.png` 是先前保存的流程图。

## 数据放在哪里

| 路径 | 内容 | 用途 |
|---|---|---|
| `data/reports/` | 三篇 CISA PDF、`-extracted.txt`、去答案的 `-input.txt`、官方报告级 `-reference.json` | 开发案例 AA25-266A、AA23-319A；AA24-193A 为封存测试 |
| `data/attack/enterprise-attack-20.0.json` | 固定 ATT&CK Enterprise v20.0 目录 | ID、技术名称校验 |
| `data/sigma/` | 本地 SigmaHQ 仓库 | 检索完整 YAML 检测条件；当前 commit 见版本文档 |
| `data/annotations/` | 行为黄金草稿、规则候选、覆盖判定样本、规则生成请求示例 | 组长审核与 A/B 调优交接 |
| `data/Security-Datasets/` | OTRF 原仓库及 LSASS 活动日志 | 静态日志实验；与 CISA 案例不是同一攻击 |
| `data/runs/` | 早期与当前 Agent 预测、评估、烟测和旧输入 | 原型诊断，不当作人工黄金答案 |

`agent_poc.py` 等脚本和 `tests/` 留在项目根目录。`.deps/` 是本机依赖副本。

## 组长现在核对的两张表

### 1. 行为与 ATT&CK

打开 [行为级黄金样本](data/annotations/aa25_266a_gold_draft.json)，同时阅读 [CISA 原 PDF](data/reports/cisa-aa25-266a.pdf) 第 8–9 页和 [提取原文](data/reports/cisa-aa25-266a-extracted.txt)。4 条行为及映射已由组长确认，**只抽样标注第 8–9 页，不是全篇已标完**。第 7 页 GeoServer 1 的 `ipconfig` 不在当前行为级评估范围内，因此原型没有提取它不能依据此样本计为正式行为级漏报。若后续标注它，应与第 8 页 SQL Server 的 `ipconfig /all` 分别保留主机、参数和证据；报告级 T1016 统计才去重。

行为级黄金草稿只根据去答案正文与 ATT&CK 技术定义填写，`origin` 使用 `team_review`。`rationale` 解释具体行为为什么属于该技术，不引用 CISA 给出的映射。`data/reports/*-reference.json` 保存官方报告级映射，只在盲标完成后用于评估或争议复核。给 Agent 预测时只传 `-input.txt` 与固定 ATT&CK 目录，不传黄金草稿或参考答案。

新增行确认后，将对应 `behaviors[]` 和 `mappings[]` 的 `review_status` 都改为 `confirmed`；有争议就用 `disputed` 并写说明。交给组员 A 调优前，先用验证器检查。

### 2. Sigma 覆盖

先看 [候选规则清单](data/annotations/aa25_266a_rule_candidates.json) 的 `rule_path`，逐个打开完整 YAML 的 `detection`、`condition` 与过滤器，再看 [覆盖判定样本](data/annotations/coverage_gold_template.json)。当前 4 行覆盖 `matches_procedure`、`does_not_match`、`insufficient_detail` 三种结论：

| 判定行 | 报告做法与规则条件 | 已复核结论 |
|---|---|---|
| C001 | `whoami` 对应规则中的 whoami.exe 分支 | `matches_procedure` |
| C002 | `whoami` 未出现该规则必需的 `/all` | `does_not_match` |
| C003 | whoami.exe 符合选择条件，但报告未给父进程，无法判断排除项 | `insufficient_detail` |
| C004 | `ipconfig /all` 符合规则中的命令行正则 | `matches_procedure` |

这些是**报告做法与规则条件的纸面比对**。`matches_procedure` 不表示规则已经在日志中运行或命中，也不保证该命令一定可疑。C002 的规则**要求出现** `/all`；它不是排除 `/all` 的规则。`does_not_match` 只针对报告列出的 `whoami` 这条命令；若报告只是省略参数、无法确认真实命令行，则应改判 `insufficient_detail`，不能声称真实日志必定未命中。`required_fields` 列出相关分支可能用到的字段；Sigma 的 OR 分支不要求每个字段同时存在。

现有四条覆盖行的 `review_status` 已为 `confirmed`，可供 B 调优；新增行仍需复核。`tasklist`、Stowaway 等行为尚未填覆盖行，后续由 B 检索并送审。

## 运行与校验

首次安装依赖：`python -m pip install -r requirements-poc.txt`。下面这些命令不会调用 Ollama，也不会覆盖已有的人工草稿：

```powershell
python validate_contract.py data/annotations/aa25_266a_gold_draft.json
python validate_contract.py data/annotations/aa25_266a_rule_candidates.json --handoff data/annotations/aa25_266a_gold_draft.json
python validate_contract.py data/annotations/coverage_gold_template.json --handoff data/annotations/aa25_266a_gold_draft.json --candidates data/annotations/aa25_266a_rule_candidates.json
python -m pytest -q tests/test_agent_poc.py tests/test_contract.py
```

`python make_contract_examples.py` 只补建缺少的示例文件，不覆盖现有审核结果。`python build_cisa_cases.py` 会从 PDF **重建** `data/reports/` 中的提取文本、去答案输入和报告级参考文件，运行前先确认你需要重建。OTRF 日志概览可运行 `python inspect_dataset.py`；已解压文件可显式传给它 `data/Security-Datasets/datasets/compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump.json`。本地 Agent 的 Ollama 运行方式见原型运行文档。
