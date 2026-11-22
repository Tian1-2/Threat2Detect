# 项目目录约定

根目录只保留 README、Git 配置和功能目录。主控 Case Agent、Sigma 检索、覆盖分析、执行器和规则生成均位于 `src/threat2detect/`。

```text
Threat2Detect/
├─ README.md
├─ .gitignore
├─ .gitmodules
├─ artifacts/                  # 可重建的预测、评估和运行结果
├─ config/
│  └─ requirements.txt         # Python 依赖
├─ data/                       # 固定输入与人工答案
│  ├─ reports/
│  ├─ attack/
│  ├─ sigma/
│  ├─ Security-Datasets/
│  └─ annotations/
├─ docs/                       # 契约、阅读入口、开发日志和运行说明
├─ tests/                      # 回归测试
├─ tools/                      # 数据准备和一次性分析脚本
└─ src/threat2detect/
   ├─ pipeline/
   │  ├─ controller.py         # 主控 Case Agent
   │  └─ legacy.py             # 固定流水线
   ├─ sigma/
   │  ├─ retrieval.py          # 优化后的规则召回与排序
   │  ├─ coverage.py
   │  ├─ agent.py
   │  └─ executor.py
   ├─ telemetry/otrf.py
   ├─ rule_generation/
   ├─ report_agent.py
   └─ contracts.py
```

主控与固定流水线入口：

```powershell
python -m src.threat2detect
python -m src.threat2detect.pipeline.legacy
```

Sigma 检索和契约校验：

```powershell
python -m src.threat2detect.sigma.retrieval
python -m src.threat2detect.contracts
```

`data/` 只放可追溯输入、版本锁定的上游仓库与人工标注；模型输出和可重建结果放 `artifacts/`；运行说明和开发记录放 `docs/`。主控调用 `search_rules` 时直接使用优化后的 `sigma.retrieval`，并把排名、分数和平台排除记录写入运行状态和 `case_result`。
