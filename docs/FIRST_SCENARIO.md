# Threat2Detect 首条链路：OTRF LSASS_campaign_06

## 结论和范围

先选同一次模拟的三段可观测行为：`systeminfo.exe`（T1082）→ `whoami.exe`（T1033）→ `Outflank-Dumpert.exe` 访问 LSASS 并生成转储文件（T1003.001）。只使用 **Windows Sysmon/Operational** 一种事件源；不需要数据库日志。这里的“链路”指同一数据集中的事件顺序，不能仅凭先后顺序证明所有行为具有因果关系。

数据：`data/Security-Datasets/datasets/compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump.zip`，其中是 JSON Lines。元数据：`data/Security-Datasets/datasets/compound/_metadata/LSASS_campaign_06.yaml`。仓库同时提供 Zeek 和 pcapng；第一轮先不引入网络数据。

元数据里的完整顺序是：Metasploit `multi/handler` 接到目标机器的 Meterpreter 会话 → 运行 `systeminfo`、`whoami` → 从攻击者机器 **上传** `Outflank-Dumpert.exe` 到目标机 → 在目标机转储 LSASS 进程内存为 `dumpert.dmp` → 从目标机 **下载**这个转储到攻击者机器 → 在攻击者机器用 `pypykatz lsa minidump` **解析已有转储**。下表六行只验证了其中的主机侧可观测部分；连接建立、下载和解析不在这六行的证明范围内。

## 已核对的原始事件

按 JSON 的 `TimeCreated` 排序：

| 时间（原始 UTC 字段） | Sysmon EventID | 证据 | 对应行为 |
|---|---:|---|---|
| 2023-09-05 10:45:28.309 | 1 | `Image=C:\Windows\System32\systeminfo.exe`、`CommandLine=systeminfo` | 系统信息发现 T1082 |
| 2023-09-05 10:45:51.939 | 1 | `Image=C:\Windows\System32\whoami.exe`、`CommandLine=whoami` | 用户发现 T1033 |
| 2023-09-05 10:46:57.048 | 11 | `TargetFilename=C:\Windows\Temp\Outflank-Dumpert.exe` | 工具落地；单凭此事件不证明网络传输 T1105 |
| 2023-09-05 10:47:37.561 | 1 | `Image=C:\Windows\Temp\Outflank-Dumpert.exe` | 工具执行 |
| 2023-09-05 10:47:37.676 | 10 | `SourceImage=...Outflank-Dumpert.exe`、`TargetImage=...lsass.exe`、`GrantedAccess=0x1FFFFF` | LSASS 进程访问 |
| 2023-09-05 10:47:42.663 | 11 | `Image=...Outflank-Dumpert.exe`、`TargetFilename=C:\Windows\Temp\dumpert.dmp` | 转储文件创建；共同支持 T1003.001 |

注意：事件顶层 `TimeCreated` 与 `Message` 内的 `UtcTime` 日期相差约 19 小时。先固定使用顶层 `TimeCreated` 和事件顺序，不要混用两个字段；后续查明采集/转换原因。

## 数据盘点

主机 ZIP 中有 **58,096 条** JSON 事件，其中 Sysmon **56,403 条**。Sysmon EventID 1 有 **77 条**，10 有 **31,522 条**，11 有 **2,130 条**。EventID 10 背景量很大，规则必须加 `SourceImage`、`TargetImage` 等限制，不能把每次 LSASS 访问都当攻击。这个数据集主要用于正样本验证，不能直接估计误报率。

## 人工走通的顺序

1. 读本页的六行证据，再打开元数据 YAML，确认技术标签和模拟描述。把“元数据声称”和“事件实际显示”分开记。
2. 在项目根目录用 `python tools/inspect_dataset.py` 直接读取 ZIP；若已经解压，用 `python tools/inspect_dataset.py data/Security-Datasets/datasets/compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump.json`。脚本会打印各事件源/EventID 的数量及关键事件样例；它是一次性盘点工具，不执行检测规则。
3. 为三个行为各写一句可观察条件：T1082/T1033 看 Sysmon 1 的 `Image`、`CommandLine`；T1003.001 看同一进程的 Sysmon 10（访问 LSASS）和 11（创建 `.dmp`）。
4. 再找一篇**独立的**公开威胁报告，从报告抽行为并映射 ATT&CK；不要把 OTRF 的场景标题当作报告输入。
5. 查现有 Sigma 规则，逐条检查 `logsource` 是否支持 Sysmon 1/10/11、字段是否能从这份 JSON 映射。只在字段兼容后执行规则。
6. 记录每条规则的命中事件、未命中的原因、证据和局限。若生成候选规则，先在这份正样本上验证，再补良性样本测试误报。

这个阶段的最小产物：一张“报告行为 → ATT&CK → 所需字段 → 现有规则 → 命中事件”的表，以及一份说明哪些判断还缺证据的记录。

## 第一条 Sigma 规则的字段核对

规则：[NVISO `sysmon_lsass_memdump.yml`](https://github.com/NVISOsecurity/sigma-public/blob/master/rules/windows/sysmon/sysmon_lsass_memdump.yml)，规则 ID `5ef9853e-4d0e-4a70-846f-a9ca37d876da`。这是 2019 年的实验性规则，所在仓库已归档；用作理解和手工验证样例，不代表当前最佳检测规则。以下是规则**全部**检测条件：

| 规则要求 | OTRF 字段/值 | 结果 |
|---|---|---|
| `logsource: windows / sysmon` | `Channel=Microsoft-Windows-Sysmon/Operational` | 数据源匹配；规则引擎仍需要正确的字段映射 |
| `EventID: 10` | 31,522 条 Sysmon 进程访问事件 | 继续筛选 |
| `TargetImage: C:\windows\system32\lsass.exe` | 293 条指向 LSASS | 继续筛选；大小写按不敏感比较 |
| `GrantedAccess: 0x1fffff` | 上述事件中有 2 条 | 继续筛选 |
| `CallTrace` 包含 `dbghelp.dll` **或** `dbgcore.dll` | 其中 1 条包含 `dbgcore.DLL` | **1 条满足全部条件** |

命中的事件：`TimeCreated=2023-09-05T10:47:42.663Z`，`SourceImage=C:\Windows\Temp\Outflank-Dumpert.exe`，`TargetImage=C:\Windows\system32\lsass.exe`，`GrantedAccess=0x1FFFFF`，`CallTrace` 含 `dbgcore.DLL`。同一工具稍早的另一条 LSASS 访问事件满足前四项，但 `CallTrace` 不含这两个 DLL，因此未命中。`2023-09-05T10:47:42.663Z` 同时还有 Sysmon 11 文件创建事件，进一步佐证转储文件落地，但它不是本条规则的条件。

复核命令：`python tools/check_lsass_rule.py`。此脚本从 JSON 的 `Message` 解析字段，逐项模拟**这一条规则**的条件；它不是通用 Sigma 执行器。数据是同一次已知攻击模拟的正样本，1 条命中只能证明对这个样例有效，不能据此估计误报率，也不能证明覆盖所有 T1003.001 变体或 Unit 42 报告中的 Task Manager 做法。
