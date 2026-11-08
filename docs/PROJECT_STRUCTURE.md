# 项目目录约定

本页记录**当前目录**和后续集成时的目标。代码移动以不破坏现有命令和测试为前提；新增模块按目标位置开发，迁移旧脚本时提供兼容入口。

```text
Threat2Detect/
├─ README.md, READING_GUIDE.md, DEVELOPMENT_LOG.md
├─ data/                       # 固定输入与人工答案
│  ├─ reports/                 # CISA PDF、去答案正文、官方报告级对照
│  ├─ attack/                  # 固定 ATT&CK 目录
│  ├─ sigma/                   # SigmaHQ 固定提交的子模块
│  ├─ Security-Datasets/       # OTRF 固定提交的子模块
│  └─ annotations/             # 已审核样本、候选规则与示例请求
├─ artifacts/runs/             # 可重建的预测、评估、标准化日志和规则运行结果
├─ docs/                       # 契约、组员指引、运行说明、研究记录
├─ tools/                      # 数据准备与一次性分析脚本
├─ tests/                      # 回归测试
├─ src/threat2detect/          # 后续主流程代码：逐步从根目录脚本迁入
│  ├─ reports/                 # 行为提取和 ATT&CK 映射
│  ├─ sigma/                   # 规则召回、条件对照、受限执行器
│  ├─ telemetry/               # OTRF 等静态日志的标准化
│  ├─ rulegen/                 # 可选的新规则生成模块
│  └─ pipeline/                # 统一输入输出与主控编排
├─ web/                        # 需要界面时再建立
└─ requirements-poc.txt
```

**现在已经执行的整理**：`data/` 只放可追溯输入、版本锁定的上游仓库与人工标注；原 `data/runs/` 已移到 `artifacts/runs/`。两处都不要把模型输出当作人工黄金答案。标准化后的 45 MB OTRF JSON 可按命令重建，Git 忽略该文件；小型运行结果可以保留供复核。

**下一次代码迁移**：根目录的 `pipeline.py` 现按固定 JSON 契约编排 `agent_poc.py`、`sigma_retrieval.py`、`sigma_coverage.py`、`normalize_otrf.py` 和 `run_sigma_offline.py`。等接口在更多案例上稳定后，再把逻辑逐个移入 `src/threat2detect/`，根目录保留短的兼容入口或统一 `python -m threat2detect` 命令，同时改测试和文档。一次只迁一个模块并验证。

**文件归属规则**：输入或人工复核真值放 `data/`；程序产生、可重建的结果放 `artifacts/`；可复用实现逐步放入 `src/`；一次性数据准备工具放 `tools/`；用户与组员操作说明放 `docs/`；每轮结果与未解决问题追加到根目录 `DEVELOPMENT_LOG.md`。前端只有在命令行端到端流程稳定后进入 `web/`。
