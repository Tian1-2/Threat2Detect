# Threat2Detect

课程项目：从威胁报告提取有原文证据的行为，映射 ATT&CK，检索并逐条件分析 Sigma 规则；对另行取得的静态日志运行所选规则，分别报告“做法适用”与“日志实际命中”。目前是可运行的原型与已确认的小规模样本，**不是完整的端到端检测系统**。

## 从这里开始

先读[阅读指引](READING_GUIDE.md)，再按角色读[项目总说明](docs/PROJECT_HANDOFF.md)、[接口契约](docs/INTERFACE_CONTRACT.md)和[组员启动清单](docs/TEAM_START.md)。成员 B 另有[操作指引](docs/MEMBER_B_GUIDE.md)。

## 获取数据与运行

```powershell
git clone --recurse-submodules https://github.com/Tian1-2/Threat2Detect.git
cd Threat2Detect
python -m pip install -r requirements-poc.txt
python -m pytest -q tests/test_agent_poc.py tests/test_contract.py
python validate_contract.py data/annotations/aa25_266a_gold_draft.json
python inspect_dataset.py
python analyze_otrf_background.py
```

`data/sigma` 和 `data/Security-Datasets` 是锁定提交的 Git 子模块；普通 `git clone` 后还需运行 `git submodule update --init --recursive`。OTRF 上游 ZIP 已在子模块中；盘点脚本会在本地未解压时直接读 ZIP。`data/attack/enterprise-attack-20.0.json`、CISA PDF 与已处理的文本在本仓库中。Ollama 原型的模型下载与运行见[原型说明](docs/POC_RUNBOOK.md)。

目前确认的样本：AA25-266A 的 4 条行为映射、4 条报告 × Sigma 规则条件判断，以及 6 组 OTRF 事件 × 规则人工条件推演。日志样本尚未用 Sigma 引擎执行；背景候选事件不等于已证实良性。CISA 官方映射只用于盲标后的报告级对照，不作为行为级理由。
