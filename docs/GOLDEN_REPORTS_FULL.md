# 三篇威胁报告：全篇行为与日志需求（早期候选稿）

本文保留早期研究记录，尚未逐项确认为行为级黄金答案；不是各组员当前必读材料。开发与数据入口以仓库根目录 `READING_GUIDE.md` 为准。

目标基准：Enterprise ATT&CK **v20.0**，见 `docs/DATA_VERSIONS.md`；本稿的候选映射仍需用下载后的目录逐项校验 ID 与名称。本稿遍历三篇报告的攻击活动、报告明确列出的命令和重要推断；按**行为**合并相同技术的多个命令，不逐行重复工具清单、IOC、产品营销或防护建议。它不是这些报告真实事件的原始日志，也不是已经运行 Sigma 的结果。ATT&CK 栏中“原标”表示报告作者明确标注；“候选”表示本项目推断，需人工复核。`尝试`、`可能`和跨活动簇的归属不确定性必须保留。

日志字段是**验证该行为可能需要的最小线索**，不是保证存在的字段。Sysmon 事件号只在 Windows 主机适用；网络、Web、云、Linux 和数据库行为即使本地没有数据，也保留在全篇清单。规则执行演示选段另见 `docs/GOLDEN_REPORTS.md`。

## A. Unit 42：OWASSRF 漏洞利用及后续活动

来源：[Threat Brief: OWASSRF Vulnerability Exploitation](https://unit42.paloaltonetworks.com/threat-brief-owassrf/)，重点读 `Executive Summary`、`Details of OWASSRF`、`Current Scope of the Attack`。报告讨论**多个组织和多个时间点**的活动，不能把所有段落强行串成同一台机器的一次攻击。

| 编号 | 原文位置与行为摘要 | 事实强度；ATT&CK | 所需日志与关键字段 | 本地验证 |
|---|---|---|---|---|
| A01 | `Details of OWASSRF`：已认证者向 Exchange OWA `/owa/.../powershell` 发 POST，利用 CVE-2022-41080/41082 的组合执行代码 | 利用方法与实际利用均有描述；**候选 T1190**。CVE 是漏洞编号，T1190 是利用公网应用的行为 | Exchange/IIS/OWA HTTP 日志：`timestamp, client_ip, method, uri, status, user/session`；身份验证日志与应用错误；若 TLS 在前端终止需该层请求记录 | 无对应公开日志；Sysmon 不能单独证明漏洞利用 |
| A02 | `Details`：样本利用代码发送编码 PowerShell；`Current Scope`：观察到利用尝试运行编码 PowerShell | 分清“代码能力”与“实际尝试”；**候选 T1059.001**，编码本身可另考虑 T1027 但不自动双标 | Sysmon 1 `Image, CommandLine, ParentImage`；PowerShell 4104 脚本块；Exchange 进程树 | OTRF 06 有 PowerShell 日志但不是此事件；待适配 |
| A03 | `Current Scope`：SilverArrow PowerShell 后门连接远端、循环接收命令并回传结果 | 研究者分析代码并观察 C2 服务器；**候选 T1059.001**（命令执行），C2 协议子技术需进一步确认 | PowerShell 4104 的代码/命令；Sysmon 3 `Image, DestinationIp, DestinationPort`；代理/防火墙会话 | 未测试；仅有网络连接不能证明后门语义 |
| A04 | `Current Scope`：一台未阻断的 Exchange 服务器上，攻击者在利用后执行 `whoami` | 观察；**候选 T1033** | Sysmon 1 `Image, CommandLine, ParentImage, User` | OTRF 06 有同命令的独立模拟样本 |
| A05 | 同段：建立 `Admon` 账户并加入本地管理员及远程桌面用户组 | 观察；**候选 T1136.001** 创建本地账户、**T1098.007** 加入本地组 | Windows Security 4720（账户创建）、4732（本地组成员增加），`TargetUserName, MemberSid, GroupName`；Sysmon 1 管理命令 | 仅 Sysmon 1 可能见命令，完整确认需 Security 日志 |
| A06 | 同段：下载 PuTTY Link (`pta.exe`) 与 AnyDesk，安装 AnyDesk 随重启启动 | 观察；**候选 T1105** 工具传入、**T1219** 远程访问软件、持久化方式待确认 | Sysmon 1/3/11 `Image, CommandLine, DestinationIp, TargetFilename`；安装/服务/计划任务日志，具体以安装方式决定 | 未测试；文件名出现不能证明安装或持久化 |
| A07 | 同段：用 PuTTY Link 建立 SSH 隧道以访问目标机本地 RDP | 观察；**候选 T1572** 协议隧道、**T1021.001** RDP 远程服务（实际登录需另证） | Sysmon 1/3 的 `CommandLine, DestinationIp, DestinationPort`；网络流量/代理；RDP 连接及 Windows 登录事件 | 无隧道样本；单个进程创建事件不足以证明隧道成功 |
| A08 | 同段：使用新账户与远程桌面访问，Task Manager 转储 LSASS 内存 | 观察；**候选 T1003.001** | Sysmon 10 `SourceImage=Taskmgr.exe, TargetImage=lsass.exe, GrantedAccess, CallTrace`；Sysmon 11 `Image, TargetFilename`；RDP/登录日志用于串联会话 | OTRF 06 用 Dumpert，不是 Task Manager 变体 |
| A09 | 同段：作者认为转储文件被传出并在别处解析，因为服务器上未见解析 | **作者推断**；候选 T1041/T1105 等外传映射**不定**，需知道实际通道 | 网络流量/代理/EDR 文件传输 `source, destination, bytes, file/hash`；仅 Sysmon 11 无法证明外传 | 不作为已确认动作或规则成功标准 |

人工核对重点：A01 是对漏洞利用的描述，不能由 A08 的 Sysmon 日志倒推；A06 的 AnyDesk“随重启启动”不应在未见服务/计划任务/自启动方式时细分到一个持久化子技术。来源：[Unit 42 原报告](https://unit42.paloaltonetworks.com/threat-brief-owassrf/)。

## B. CISA：GeoServer 事件响应报告

来源：[CISA AA25-266A](https://www.cisa.gov/sites/default/files/2025-09/AA25-266A_advisory_cisa_shares_lessons_learned_from_ir_engagement.pdf)，`Threat Actor Activity`（第 5–9 页）及 `MITRE ATT&CK Tactics and Techniques`（第 12–14 页）。CISA 使用**Enterprise ATT&CK v17**；下面“原标”保存其原编号，本项目再用 v20.0 目录校验。下列字段是我们建议采集的线索，不代表 CISA 使用了这些特定日志源。

| 编号 | 原文位置与行为摘要 | 事实强度；ATT&CK | 所需日志与关键字段 | 本地验证 |
|---|---|---|---|---|
| B01 | `Reconnaissance`：Burp 扫描对外 GeoServer 寻找 CVE-2024-36401 | 观察；**原标 T1595.002** | Web/WAF/反向代理 `client_ip, uri, method, status, user_agent`；扫描时序 | 无对应网络日志 |
| B02 | `Resource Development`：通过 VPS 中转/使用攻击基础设施 | CISA 报告；**原标 T1583.003**，但单从受害者端日志难证实“购买 VPS” | 外部基础设施情报/云账户记录；受害端代理/防火墙 `dst_ip, ASN, connection_time` 仅能辅助 | 不做本地规则运行 |
| B03 | `Initial Access`：两台 GeoServer 被 CVE-2024-36401 利用获得执行能力 | 观察；**原标 T1190** | GeoServer/Web 日志 `uri, method, params, status, client_ip`；应用错误；Linux 进程树与命令行 | 无对应样本 |
| B04 | `Persistence`：上传 Web shell（如 China Chopper） | 观察/部分上传尝试；**原标 T1505.003** | Web 访问日志 `uri, method, status`；文件完整性/文件创建 `path, hash, writer`；Web 进程产生子进程 | 无对应样本 |
| B05 | `Persistence`：cron 作业与有效账户维持访问；创建账户但后续使用证据不足 | 不同子动作，分别标注；**原标 T1053.003、T1078**；账户创建候选 T1136 | Linux cron 文件/审计 `path, command, user`；SSH/认证 `account, src_ip, result`；用户数据库变化 | 无对应样本 |
| B06 | `Privilege Escalation`：尝试利用 Dirty COW（CVE-2016-5195） | **尝试**；**原标 T1068** | Linux audit/eBPF `execve, uid, process`；内核异常、文件/权限变化 | 不宣称提权成功 |
| B07 | `Defense Evasion/Execution`：通过 PHP Web shell 和 `xp_cmdshell` 间接执行命令 | 观察；**原标 T1202** | Web 请求与 Web 进程子进程；SQL Server 审计/扩展事件 `xp_cmdshell invocation, principal, query_time`；Windows 进程树 | 首版仅 Sysmon 不足以验证 SQL 调用来源 |
| B08 | `Persistence/Transfer`：使用 BITS 作业及 PowerShell、bitsadmin 下载载荷 | 观察；**原标 T1197、T1059.001、T1105**，按具体步骤分别记 | Windows BITS Operational `job_id, owner, remote_url, state`；Sysmon 1/3/11 `CommandLine, DestinationIp, TargetFilename`；PowerShell 4104 | 可做静态规则分析，暂无同场景日志 |
| B09 | `Credential Access`：针对 Web 服务账户进行暴力尝试 | 观察；**原标 T1110** | Web/应用认证日志 `account, source_ip, result, timestamp`；失败率与成功转折 | Sysmon 不适合作唯一依据 |
| B10 | `Discovery`：GeoServer 上运行 `uname/df/env/ps` 等系统与进程发现命令 | 观察；候选 **T1082、T1057**；按命令实际用途细分 | Linux audit `execve, argv, uid, cwd, parent`；shell history 仅辅助 | 非 Windows，保留在全篇清单 |
| B11 | `Discovery`：读取 `/etc/passwd`、系统发行版及文件目录 | 观察；**原标 T1087.001、T1082**；目录读取候选 T1083 | Linux audit/文件访问 `path, process, user`；shell 命令历史 | 非 Windows |
| B12 | `Discovery`：GeoServer/SQL Server 上 `ipconfig`、`netstat` 等 | 观察；**原标 T1016、T1049** | Windows Sysmon 1 或 Linux audit `Image/execve, CommandLine/argv`；网络状态本身可作辅助 | OTRF 06 未逐项核对 |
| B13 | `Discovery`：`fscan` 找网络服务、ping sweep 寻主机 | 观察；**原标 T1046、T1018** | 主机进程 `Image, CommandLine` 加网络流量 `src_ip, dst_ip, dst_port, rate`；工具输出遗留文件 | 仅 Sysmon 1 不能证明扫描目标与结果 |
| B14 | `Discovery`：SQL Server 上 `whoami`、`systeminfo`、`tasklist` | 观察；**原标 T1033、T1057**；`systeminfo` **候选 T1082** | Windows Sysmon 1 `Image, CommandLine, ParentImage, User` | OTRF 06 有前两项；无 `tasklist.exe` 事件 1 |
| B15 | `Discovery`：SQL Server 上 `dir/type` 查磁盘和文件、`net group`/`net user` 查账户与组 | 观察；**原标 T1083**；账户/组发现候选 T1087/T1069，需按实际输出细分 | Sysmon 1 `Image, CommandLine`；文件访问审计或 EDR 文件事件；AD/Windows 目录查询日志 | 命令行能说明尝试，不能单独证明读到了哪些数据 |
| B16 | `Lateral Movement`：从 Web Server 到 SQL Server，使用 `xp_cmdshell` 获得命令执行 | 观察；报告原表未给这一链路独立技术 ID；候选 T1021/T1202 需人工核对 | SQL Server 审计/扩展事件 `login, query, host`；Windows 进程树 `ParentImage, CommandLine`；网络会话 | 需 SQL 日志与主机日志关联 |
| B17 | `Command and Control`：Stowaway 代理转发外部 C2 流量，并建立出站连接 | 观察；**原标 T1090** | Linux 进程/网络流量 `process, dst_ip, port, bytes, timing`；代理/防火墙日志 | 无对应样本 |

注意：报告说部分文件名“可能是”RingQ，且多数文件未恢复，**不能仅据文件名宣称确认运行了 RingQ**。报告附录的 IOC、时间线和缓解建议可做上下文，不是新的攻击行为映射。来源：[CISA 原 PDF](https://www.cisa.gov/sites/default/files/2025-09/AA25-266A_advisory_cisa_shares_lessons_learned_from_ir_engagement.pdf)。

## C. Unit 42：Stately Taurus 与同环境 ShadowPad 活动

来源：[Chinese APT Abuses VSCode to Target Government in Asia](https://unit42.paloaltonetworks.com/stately-taurus-abuses-vscode-southeast-asian-espionage/)，`The Rare Use of Visual Studio Code Abuse`、`Additional TTPs`、`Exfiltration`、`The ShadowPad Activity`、附录。**报告明确说 Stately Taurus 与 ShadowPad 两簇的归属关系未定**；黄金答案必须分别记录，不能合并为已证实的同一攻击者链路。此报告未逐项给 ATT&CK ID，下列都是本项目候选映射。

| 编号 | 原文位置与行为摘要 | 事实强度；ATT&CK 候选 | 所需日志与关键字段 | 本地验证 |
|---|---|---|---|---|
| C01 | `VSCode Abuse`：使用 `code.exe tunnel` 建立可通过 Web 访问的远程开发隧道，执行命令并传递载荷 | 观察；**T1219.001** IDE Tunneling；命令执行可另记 T1059 但不重复贴无依据子技术 | Sysmon 1 `Image=code.exe, CommandLine, ParentImage`；Sysmon 3/代理 `DestinationHostname, DestinationIp, bytes`；GitHub 认证/隧道日志可辅助 | OTRF 06 无此做法 |
| C02 | 同节：为 `startcode.bat` 创建计划任务，以重启远程 shell | 观察；**T1053.005** | Windows Task Scheduler Operational `task_name, action, creator`；Security 4698；Sysmon 1 `schtasks` 命令及后续 `code.exe` | 未测试 |
| C03 | `Connection`：先前活动用 ToneShell 将文件打包为带密码 RAR，用于外传 | 报告对前次活动的回顾，**不要当本次新观察**；候选 T1560.001（归档）及外传技术待确定 | Sysmon 1 `rar.exe CommandLine`、文件创建；网络/代理外传 | 时间和活动归属需单独记 |
| C04 | `Additional TTPs`：用 `sshd.exe` 执行命令、传文件并扩展到其他机器 | 观察；候选 **T1021.004** SSH 远程服务；传文件可考虑 T1570，但方向/细节需复核 | SSH 服务端日志 `src_ip, user, result`；Sysmon 1/3 `Image, CommandLine, dst_ip, dst_port`；文件创建 | 未测试 |
| C05 | 同节：`SharpNBTScan`（改名 `win1.exe`）扫描环境 | 观察；候选 **T1018/T1046**，具体以扫描目标与协议区分 | Sysmon 1 `Image, OriginalFileName, CommandLine`；Sysmon 3/网络流量 `dst_ip, dst_port, rate` | 未测试 |
| C06 | 同节：`Listeners.bat` 与 RAR 用于准备外传文件 | 有些行为是“on some occasions”；候选 **T1560.001**，成功外传另需证据 | Sysmon 1 `cmd/rar CommandLine`、Sysmon 11 `TargetFilename`；文件大小与哈希 | 未测试 |
| C07 | `Exfiltration`：远程运行 `rar.exe` 遍历并归档 A–Z 盘 | 报告用“tried”描述尝试；候选 **T1560.001** | Sysmon 1 `rar.exe CommandLine`；Sysmon 11 新归档；SMB 文件访问/网络日志 | 不能直接宣称全盘打包成功 |
| C08 | 同节：用 `curl` 把归档上传至 Dropbox | 报告称使用该方法；候选 **T1567.002** 云存储外传 | Sysmon 1 `curl CommandLine`、Sysmon 3 `DestinationHostname/IP`；代理/防火墙 `method, domain, bytes, status`；必要时 Dropbox 审计 | 仅命令行不足以证明传输成功 |
| C09 | `ShadowPad Activity`：`imecmnt.exe` 侧载 `imjp14k.dll`，伪装 `update.exe` | **ShadowPad 活动簇**的观察，归属未定；候选 **T1574.001** DLL side-loading、**T1036** masquerading | Sysmon 1 `Image, OriginalFileName, ParentImage`；Sysmon 7 `Image, ImageLoaded, Signed`（需配置）；文件路径/哈希 | 未测试 |
| C10 | 同节：建立 Windows 服务保持 ShadowPad 运行 | ShadowPad 簇观察；候选 **T1543.003** | Windows System 7045、Security 4697；Sysmon 12/13 注册表服务项 `TargetObject, Details`；服务配置 | 未测试 |
| C11 | 同节：ShadowPad 进程向 `wmplayer.exe`、`dllhost.exe` 注入代码 | ShadowPad 簇观察；候选 **T1055**，具体子技术报告不足以定 | Sysmon 8/10 `SourceImage, TargetImage, StartAddress, CallTrace`；EDR 进程注入遥测 | 未测试 |
| C12 | `Appendix`：Tscan 做端口扫描与环境侦察 | ShadowPad 相关附录；候选 **T1046**；工具能力中的密码喷洒不等于此处实际观察 | Sysmon 1/3 `Image, CommandLine, dst_ip, dst_port`；网络扫描时序 | 未测试 |
| C13 | `Appendix`：尝试用 AD Explorer 查询 AD | **尝试**；候选 **T1087/T1069**，具体取决于查询目标 | Sysmon 1 `ADExplorer64.exe CommandLine`；LDAP/DC 审计 `query, base_dn, account, src_ip` | 不因工具启动就宣称取得数据 |
| C14 | `Credential Theft`：In-Swor、改名 Mimikatz 尝试从内存获取凭据 | **尝试**，In-Swor 一次被拦截；候选 **T1003.001**，具体目标进程需日志确认 | Sysmon 1/10 `Image, CommandLine, TargetImage, GrantedAccess`；EDR 阻断事件 `action, process` | 不宣称成功凭据窃取 |
| C15 | 同节：LaZagne 尝试访问感染机器上存储的密码 | **尝试**；候选 **T1555**（凭据存储），具体子技术依来源细分 | Sysmon 1 `Image, CommandLine`；浏览器/凭据存储文件访问；EDR 告警 | 不应一概归入 LSASS |
| C16 | 同节：自定义 `Lsass-dump-main` 尝试将 LSASS 内存转储到磁盘 | **尝试**；候选 **T1003.001** | Sysmon 1/10/11 `Image, SourceImage, TargetImage, CallTrace, TargetFilename` | OTRF Dumpert 可测部分行为规则，不等于该工具的原始日志 |
| C17 | 同节：尝试获取 `NTDS.dit`，使用 VSS 与导出 SYSTEM 注册表配置单元 | 尝试及部分操作观察；候选 **T1003.003** | Sysmon 1 `vssadmin/ntdsutil/reg CommandLine`；Sysmon 11 文件创建；Security 4663 文件访问；VSS 服务/系统事件 | 与 LSASS 是不同子技术 |
| C18 | 同节：`PSEXESVC.exe`、WMI 用于跨机器执行 | ShadowPad 簇观察；候选 **T1021.002** SMB/服务式远程执行、**T1047** WMI；确切 PSEXESVC 路径需复核 | 远端 System 7045、Security 4624/5140；Sysmon 1 父子进程、Sysmon 3 连接；WMI-Activity 5857–5861 | 未测试 |

人工核对重点：C09–C18 属同环境 **ShadowPad 簇或附录**，不应自动归因 Stately Taurus；C03 是前次活动回顾；C14–C17 的“尝试”不能改成“成功”。来源：[Unit 42 原报告](https://unit42.paloaltonetworks.com/stately-taurus-abuses-vscode-southeast-asian-espionage/)。

## 核对和完善方式

请先核对每行的**报告段落、事实强度、ATT&CK 候选**，再核对日志字段。优先修改 A09、B16、C04、C13、C18 这些报告细节不足以唯一细分技术的条目。若原文没有证明某个动作成功，应保留 `attempted` 或 `inferred`。后续规则检索只取已确认的映射和所选验证行为；其他行为照样留在最终报告的可观测性清单中。
