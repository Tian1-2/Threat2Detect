# Threat2Detect 首个 Agent 原型

本原型先验证 **报告全文 → 带原文证据的行为 → ATT&CK 候选 → 官方报告级对照**。
Sigma 规则分析与 OTRF 日志执行仍按 `docs/PROJECT_HANDOFF.md` 的后续接口接入；当前输出不得称为规则覆盖或攻击检出。
本脚本的实验 JSON 尚非组员间最终格式；并行开发的数据契约见 `docs/INTERFACE_CONTRACT.md`。`data/annotations/aa25_266a_gold_draft.json` 虽沿用旧文件名，现有四条行为与映射已确认。

## 已准备的案例

| 报告 | 用途 | 官方映射 | 注意 |
|---|---|---:|---|
| CISA AA25-266A（GeoServer 事件响应） | 开发 | 22 个 ID | 报告使用 ATT&CK v17；程序按 v20 校验 |
| CISA AA23-319A（Rhysida 多来源通告，2025 更新版） | 开发 | 23 个 ID | 综合多个活动，不能拼成单次攻击；其中 `T1070.001` 在固定的 v20 目录中不可用，评估暂排除该 ID |
| CISA AA24-193A（红队演练） | 封存测试 | 28 个 ID | 是 CISA 授权演练而非真实威胁事件；有 Sysmon 配置与检测讨论 |

每篇有本地 PDF、`-extracted.txt`（PDF 提取原文）、`-input.txt`（移除文内 ATT&CK ID 与映射章节后的输入，保留其后的正文和时间线）、`-reference.json`（官方映射章节的 ID）。`tools/build_cisa_cases.py` 从 PDF 重建上述文件，并检查输入中无残留 ATT&CK ID。**清洗仍需人工查看图表与版式**，特别是后续加入的新报告。PDF 文本提取用 `pypdf`，可运行 `python -m pip install pypdf`；本机原型也有 `.deps` 中的本地副本。

ATT&CK 目录位于 `data/attack/enterprise-attack-20.0.json`，其 SHA-256 见 `docs/DATA_VERSIONS.md`。

## 运行

1. 安装并启动 Ollama，下载本地模型 `ollama pull qwen3:4b`。无需 OpenAI API Key。
2. 先在开发案例上运行：

```powershell
python agent_poc.py analyze data/reports/cisa-aa25-266a-input.txt data/attack/enterprise-attack-20.0.json artifacts/runs/cisa-aa25-266a-prediction-v2.json --report-id AA25-266A --model qwen3:4b
python agent_poc.py evaluate artifacts/runs/cisa-aa25-266a-prediction-v2.json data/reports/cisa-aa25-266a-reference.json artifacts/runs/cisa-aa25-266a-evaluation-v2.json
```

3. 打开预测 JSON，逐条查看 `quote`、`location.char_start`、行为事实强度与 `mapping`。评估 JSON 的 `missed_reference_ids` 是漏掉的官方标签；`additional_ids_for_human_review` 是需要人工核查的新增结果，不自动算错。
4. 只在开发案例上分析错误、修改提示词或检索。**封存案例 AA24-193A 在流程定稿前不运行**。

首轮 `poc-1` 结果已另存为 `artifacts/runs/cisa-aa25-266a-prediction.json` 和 `artifacts/runs/cisa-aa25-266a-evaluation.json`，对应的旧输入是 `artifacts/runs/cisa-aa25-266a-input-poc1.txt`；不要覆盖。当前程序使用 `poc-2` 提示词，完整报告结果在 `artifacts/runs/cisa-aa25-266a-prediction-v2.json`、`artifacts/runs/cisa-aa25-266a-evaluation-v2.json`。两次输入范围不同，不能直接作提示词 A/B 分数对比。具体错误分析见 `docs/BASELINE_REVIEW.md`。

## 当前边界

- 官方映射表是报告级参考答案，不提供每个 ID 的唯一原文句子；报告级召回率不能评估证据位置和事实强度，需要人工抽检。
- `candidate_ids` 用 ATT&CK 名称与说明做轻量词项召回。若候选未召回正确技术，模型不会选择它；需在开发集上单独记录这类错误。
- 本地 4B 模型适合验证工作流，可能漏提、误分或输出格式异常；不要把它的结果当专业结论。`agent_poc.py` 会拒绝虚构引句及候选集外 ID，但仍需审核合理性。
- 本阶段尚未计算 Sigma 覆盖率或日志检出率，也没有真实良性样本的误报率。

## 离线检查

```powershell
python -m pytest -q tests/test_agent_poc.py
python tools/build_cisa_cases.py
```
