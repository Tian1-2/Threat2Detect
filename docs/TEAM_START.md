# 四位组员的开发起点

本页用于各组员把项目交给自己的 AI 后立即开始开发。先读[项目总说明](PROJECT_HANDOFF.md)了解目标与分工，再读[接口契约](INTERFACE_CONTRACT.md)确定字段与状态值。`README.md` 和 `READING_GUIDE.md` 是仓库入口；所有路径相对仓库根目录。

## 当前已确认与尚未实现

AA25-266A 的 `data/annotations/aa25_266a_gold_draft.json` 虽沿用旧文件名，内含的 4 条行为与映射已是 `confirmed`。`data/annotations/coverage_gold_template.json` 的 4 条规则适用性判断也已确认。`data/annotations/otrf_lsass_event_judgement_reviewed.md` 的 6 组事件条件推演已确认，但**尚未运行 Sigma 执行器**。`agent_poc.py` 是实验原型，它的嵌套输出不等于正式契约。三篇报告的全篇梳理仍是候选研究材料，不是全部审核过的黄金答案。

## 各角色第一项交付

| 角色 | 先读 | 起步输入 | 第一项可运行交付 |
|---|---|---|---|
| 组长 | `INTERFACE_CONTRACT.md`、`OTRF_LOG_ANALYSIS.md` | 已确认样本、固定 ATT&CK/Sigma 版本 | `run_case` 的状态与模块调用骨架；明确报告适用性、日志实际命中、未测试三种输出；选中规则的执行器范围由组长落实 |
| A：报告理解 | `REVIEW_PROTOCOL.md`、`POC_RUNBOOK.md` | `data/reports/cisa-aa25-266a-input.txt`、固定 ATT&CK 目录、已确认 4 行 | 将报告行为与一对多技术映射输出为 `case_handoff`；记录引用位置、候选召回与错误清单；不要把官方 `*-reference.json` 放进模型输入 |
| B：Sigma 检索 | `MEMBER_B_GUIDE.md` | 确认的 `case_handoff` 行、`data/sigma`、4 条覆盖样本及 6 组 OTRF 推演 | `rule_candidates` 与 `coverage_assessments` 的最小实现；逐条件说明支持、冲突、决定性未知；新增争议交组长 |
| C：轻量数据任务 | `OTRF_LOG_ANALYSIS.md`、`FIRST_SCENARIO.md` | OTRF ZIP/JSONL 与元数据 | 数据集清单、事件字段与行号核对、少量 `normalized_events` 样例及解析错误数；把背景候选与已证实良性分开 |

各人先用 `python validate_contract.py` 验证自己的 JSON。需要变更字段或枚举时，提供具体输入、现有输出与建议修改给组长统一更新契约。不要让几个模块各自定义不同的 `behavior_id`、规则编号或日志命中含义。
