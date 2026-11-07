# OTRF 日志标准化与离线 Sigma 执行

本流程只使用本地静态文件，不需要 SIEM 或 Ollama。运行前安装 `python -m pip install -r requirements-poc.txt` 并初始化 OTRF、SigmaHQ 子模块。所有命令从仓库根目录执行。

## 1. 标准化 OTRF

```powershell
python normalize_otrf.py artifacts/runs/otrf_lsass_normalized.json
python validate_contract.py artifacts/runs/otrf_lsass_normalized.json
```

脚本直接读取 OTRF ZIP，也可用 `--input` 指向解压的 JSONL。默认只保留 Sysmon ID 1、10、11，并从 `Message` 提取原始 Sysmon 字段名。每条事件有稳定的 `event_uid`、原始文件行号 `raw_ref`、时间、主机、`event_code` 和字段；`parse_error_count` 不会静默丢弃。首轮结果：33,729 条保留事件、0 条解析错误。生成的约 45 MB 标准化文件被 `.gitignore` 排除，可按命令重建。

## 2. 执行选中规则

```powershell
python run_sigma_offline.py artifacts/runs/otrf_lsass_normalized.json artifacts/runs/otrf_lsass_rule_tests.json --rule data/sigma/rules/windows/process_access/proc_access_win_lsass_memdump.yml --rule data/sigma/rules/windows/process_access/proc_access_win_lsass_dump_keyword_image.yml --rule data/sigma/rules/windows/process_creation/proc_creation_win_susp_local_system_owner_account_discovery.yml
python validate_contract.py artifacts/runs/otrf_lsass_rule_tests.json --events artifacts/runs/otrf_lsass_normalized.json
```

执行器支持当前选中规则使用的 `contains`、`startswith`、`endswith`、`re`、`all`、`windash`，选择器中的 OR/AND、`and/or/not`、括号和 `1 of` / `all of` 通配选择器。每条规则先按 Windows Sysmon 事件类型筛选；超出支持范围的规则返回 `unsupported_rule`，不冒充 `miss`。`rule_tests` 保存实际命中的 `event_uid`、已评估数、跳过数和引擎版本。也可用 `--candidates data/annotations/aa25_266a_rule_candidates.json` 运行候选列表并保留它们的 `candidate_id`；这仍是 OTRF 数据集结果，不属于 CISA 报告原事件。

## 首轮结果与复核边界

| 规则 | 实际命中 | 与已复核样本的关系 |
|---|---|---|
| LSASS memdump | L33808、L34151 | E01 命中；VBoxService 的 L1727 未命中 |
| LSASS dump keyword | L33808、L34151 | E02 命中 |
| Local Accounts Discovery | L20542、L20570 | E04 的 `whoami` 命中；Edge L2090 与 `systeminfo` L17255 未命中 |

这些是**规则在 OTRF 这份静态日志上的实际运行结果**，与人工条件推演 E01–E06 一致。它不能证明规则检测到了 CISA 报告中的同类行为，也不能据此计算真实环境误报率。当前执行器是选中语法的子集，未承诺完整 Sigma 兼容；更复杂的字段映射、关联/时间窗口、管道及后端语义需另行实现和验证。
