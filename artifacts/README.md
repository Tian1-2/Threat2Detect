# 运行产物

`runs/` 保存模型预测、报告级评估、规则召回与离线执行结果。它们是实验输出，不能覆盖 `data/annotations/` 中已确认的人工样本。大型标准化日志由 `normalize_otrf.py` 重建，默认不纳入 Git；具体命令见 `docs/OFFLINE_SIGMA_RUNBOOK.md`。
