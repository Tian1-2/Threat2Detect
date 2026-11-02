# 黄金案例候选：三篇报告的行为证据

此页供人工复核与模块开发。当前表格是**首版规则执行演示的选定片段**，并非三篇报告的完整行为清单或完整 ATT&CK 映射。项目应先分析整篇报告，再对每个行为标明可能需要的日志源；表中的 Windows 主机行为只是其中可用 Sysmon 演示的一部分。每条映射都要回到报告原文；“预期 Sysmon 字段”是可观测性分析，不代表已取得报告中的原始 Sysmon 日志。

## A. Unit 42：OWASSRF 漏洞利用后的活动

来源：[Threat Brief: OWASSRF Vulnerability Exploitation](https://unit42.paloaltonetworks.com/threat-brief-owassrf/)，阅读 `Current Scope of the Attack` 段落和图 7–8。

| 报告证据定位 | 事实强度 | ATT&CK（本项目选取） | 预期 Sysmon 可观察内容 | 本地样本关系 |
|---|---|---|---|---|
| 报告写攻击者运行 `whoami` | 研究者报告的观察 | T1033：System Owner/User Discovery | 事件 1：`Image`、`CommandLine`、`ParentImage` | OTRF `LSASS_campaign_06` 有 `whoami` 事件，但不是同一次攻击 |
| 报告写攻击者通过 Task Manager 转储 LSASS 内存 | 研究者报告的观察 | T1003.001：LSASS Memory | 可能有事件 10：`SourceImage=Taskmgr.exe`、`TargetImage=lsass.exe`；可能有事件 11：`.dmp` 文件；均依赖采集配置 | OTRF 用 Dumpert，不能验证 Task Manager 特有条件 |
| 报告认为转储文件被传出并在别处提取凭据 | **作者推断**，不是同段落直接观察 | 不纳入首版的已确认行为映射 | 主机 Sysmon 1/10/11 不能单独证明文件传出或异地解析 | 不据此生成“已验证外传”结论 |

注意：报告还涉及 Exchange 漏洞利用、账户建立、隧道和远程桌面；这些行为应进入全篇清单，并标注各自所需证据。只用 Sysmon 首版无法完整验证这些环节。

## B. CISA：事件响应经验报告中的 SQL Server 发现行为

来源：[CISA Advisory AA25-266A](https://www.cisa.gov/sites/default/files/2025-09/AA25-266A_advisory_cisa_shares_lessons_learned_from_ir_engagement.pdf)，第 8 页 `SQL Server` 段落。CISA 明确列出在该服务器上观察到的命令。`SQL Server` 是**被攻击主机的角色**，下面选取的行为仍属于 Windows 主机进程，不要求数据库审计日志。

| 报告列出的命令 | 事实强度 | ATT&CK（本项目选取） | 预期 Sysmon 可观察内容 | 本地样本关系 |
|---|---|---|---|---|
| `whoami` | CISA 报告的观察；原文标 T1033 | T1033：System Owner/User Discovery | 事件 1：`Image=...whoami.exe`、`CommandLine` | OTRF 06 有同命令，可测规则对该**命令模式**，不等于重放 CISA 事件 |
| `systeminfo` | CISA 报告的观察 | T1082：System Information Discovery（本项目映射） | 事件 1：`Image=...systeminfo.exe`、`CommandLine` | OTRF 06 有同命令 |
| `tasklist` | CISA 报告的观察；原文标 T1057 | T1057：Process Discovery | 事件 1：`Image=...tasklist.exe`、`CommandLine` | 已核对 OTRF 06：没有 `Image` 含 `tasklist.exe` 的事件 1；该样本无法验证这一步 |

这篇报告还描述 GeoServer 漏洞、Linux 主机、网络扫描和横向移动。全篇清单应保留它们；首版规则执行演示只选 SQL Server 上的三条 Windows 发现行为，不把整个事件简化为 Sysmon 可完全检测。

## C. Unit 42：Stately Taurus 的凭据获取尝试

来源：[Chinese APT Abuses VSCode to Target Government in Asia](https://unit42.paloaltonetworks.com/stately-taurus-abuses-vscode-southeast-asian-espionage/)，`Credential Theft` 段落、图 10–11。

| 报告证据定位 | 事实强度 | ATT&CK（本项目选取） | 预期 Sysmon 可观察内容 | 本地样本关系 |
|---|---|---|---|---|
| 报告称攻击者**尝试**使用看似自定义的 `Lsass-dump-main` 工具将 `lsass.exe` 内存转储到磁盘 | 明确是尝试；不能改写成成功取得凭据 | T1003.001：LSASS Memory | 若发生且配置采集，可能有事件 1（工具运行）、10（访问 LSASS）、11（转储文件创建）；具体字段需看真实事件 | OTRF 的 Dumpert 样例可验证部分**行为型**规则，不能验证该自定义工具的全部细节 |
| 报告称尝试用重命名的 Mimikatz 从内存获取凭据 | 明确是尝试 | T1003.001 为候选，需结合具体操作确认 | 工具名称和命令行可能有事件 1；进程访问需事件 10 | 不把“文件名像 Mimikatz”当成运行成功的证据 |

这篇的教学价值：同一 T1003.001 下有 Task Manager、Dumpert、自定义工具等不同实现；若 Sigma 只匹配工具名，不能宣称覆盖所有变体。

## 三篇报告共同的人工参考答案

| 检查项 | 预期答案 |
|---|---|
| 哪些是事实？ | 使用报告作者明确报告的观察；保留“尝试”“认为”“可能”等限定词 |
| ATT&CK 如何用？ | 按具体行为映射，不从工具名或已有 Sigma `tags` 反推攻击事实 |
| 用什么日志？ | 对全篇行为逐项列出所需日志源；首版仅对 Sysmon 可验证片段执行规则，其余行为标 `not_evaluated` 或 `insufficient_telemetry`，但不从报告分析结果中删除 |
| 规则怎么验证？ | 固定 Sigma 规则版本，对标准化后的静态 Sysmon JSON 运行；命中事件必须可回溯到数据集和原始事件 |
| 结论如何写？ | 分开写报告做法的静态覆盖判断与独立样本的运行结果；不把不同事件说成同一次攻击 |

## 良性与负例数据方案

**优先顺序**：

1. 在隔离实验 Windows 虚拟机上安装 Sysmon，记录一段已知正常操作（例如登录、办公软件、管理员运行 `whoami`/`systeminfo`、正常系统进程访问）。保存采集配置、起止时间、执行操作清单和原始事件。这样标签依据来自操作记录，比较适合检查简单规则的误报；不使用个人日常电脑的隐私日志。
2. 调研已有公开、含正常活动的 Sysmon 数据，例如 [LMD Collections](https://github.com/ChristosSmiliotopoulos/Lateral-Movement-Dataset--LMD_Collections)（论文说明含 normal 与 malicious Sysmon 样本）。使用前要核实文件可得、标签粒度、许可和事件字段；目前**未核实能否直接用于本项目**。
3. 合成少量明确标为 `synthetic_benign` 的反例，仅检查规则逻辑是否过宽，例如普通管理员执行 `whoami`，或与 LSASS 无关的 `.dmp` 文件创建。这不能支持真实误报率数字。

OTRF 攻击数据集中存在大量背景事件，但不能把“未被场景元数据点名”的事件直接视为已标注良性。即使用多个 OTRF 场景交叉验证，也要检查是否共享采集配置、环境与生成方式。
