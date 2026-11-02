# OTRF LSASS_campaign_06 日志盘点（2026-11-02）

数据：[元数据](../data/Security-Datasets/datasets/compound/_metadata/LSASS_campaign_06.yaml)、[解压后的主机日志](../data/Security-Datasets/datasets/compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump.json)。可在项目根目录运行 `python analyze_otrf_background.py` 重算下面的分布。行号指 JSONL 的物理行号，从 1 开始。

## 结论

**这不是一份只有恶意指令的日志。** 元数据说明它是在模拟攻击时采集的主机数据，文件中包含同一台主机约 12 分钟的整机遥测。存在浏览器、搜索索引、Windows 错误报告、VirtualBox 服务、系统服务等背景活动。它们是有价值的非命中或疑似背景样本，但元数据没有逐事件“良性”标签；不能把未列入攻击步骤的每条事件直接定为已证实良性。

| 指标 | 数量 |
|---|---:|
| 全部事件 | 58,096 |
| Sysmon | 56,403 |
| Security / Application / PowerShell Operational / System / Windows PowerShell | 1,215 / 324 / 119 / 27 / 8 |
| Sysmon 进程创建（ID 1） | 77 |
| Sysmon 进程访问（ID 10） | 31,522 |
| 访问 LSASS 的 ID 10：VBoxService / svchost / Outflank-Dumpert | 255 / 36 / 2 |

事件时间范围：2023-09-05 10:43:28.158Z 至 10:55:40.184Z，主机均为 `MKT01.pandalab.com`。`Outflank-Dumpert.exe` 两次访问 LSASS 的权限值为 `0x1FFFFF`；VBoxService 为 `0x1400`，svchost 为 `0x1000` 或 `0x2000`。浏览器 Edge 的进程创建见第 2090 行，SearchIndexer 见第 2100 行。元数据中有攻击者操作记录，可支持识别 Dumpert、`systeminfo`、`whoami` 等攻击链活动；普通后台进程只能先标为“背景候选”。

**使用边界：**同一个攻击模拟数据集里的背景事件可帮助检查规则条件和发现可能误报，不能代替独立公开良性数据来估计真实环境误报率。某规则未命中背景事件，也不证明该事件绝对良性；某规则命中攻击期间的 `whoami`，也不证明单独运行 `whoami` 就是恶意。

逐事件的已复核判定样本见[OTRF 规则与事件判定样本](../data/annotations/otrf_lsass_event_judgement_reviewed.md)。
