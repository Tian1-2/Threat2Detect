# OTRF 事件 × Sigma 规则：人工判定样本（已复核）

组长已复核事件引用与人工条件推演；供组员 B 开发与回归使用。数据为 `data/Security-Datasets/datasets/compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump.json`，事件引用 `L数字` 表示 JSONL 物理行号。SigmaHQ commit：`05d1031f537e830b76da53bae2400c5814c89165`。下表是**依据 YAML 的人工静态推演**，尚未用 Sigma 引擎执行；`match` / `miss` 指规则条件，不是对事件恶意性的判决。

| 样本 | 事件与背景标签 | 规则 | 预期条件结果 | 核对理由 |
|---|---|---|---|---|
| E01 | L33808，Sysmon 10，`Outflank-Dumpert.exe → lsass.exe`，`0x1FFFFF`；元数据支持攻击相关 | [LSASS memdump](../sigma/rules/windows/process_access/proc_access_win_lsass_memdump.yml) | `match` | `TargetImage`、`GrantedAccess` 符合；`CallTrace` 含 `ntdll.dll`（该规则允许的值之一），`SourceUser=PANDALAB\\pedro.gustavo` 不满足 SYSTEM 用户排除项。注意不能误读成必须含 `dbgcore.dll`。 |
| E02 | L33808，同一 Dumpert 事件；攻击相关 | [dump keyword](../sigma/rules/windows/process_access/proc_access_win_lsass_dump_keyword_image.yml) | `match` | `SourceImage` 包含 `dump`，目标为 LSASS，权限值 `0x1FFFFF` 以 `FF` 结尾。这个条件比较宽，命中不等于已证明凭据被成功提取。 |
| E03 | L1727，Sysmon 10，`VBoxService.exe → lsass.exe`，`0x1400`，SYSTEM；背景候选，非正式良性标签 | [LSASS memdump](../sigma/rules/windows/process_access/proc_access_win_lsass_memdump.yml) | `miss` | `0x1400` 不在规则 `GrantedAccess` 选择列表，且 `SourceUser` 为 `NT AUTHORITY\\SYSTEM` 会触发排除项；仅凭访问 LSASS 不应算命中。 |
| E04 | L20542，Sysmon 1，`whoami`，父进程 `cmd.exe`；元数据支持攻击链中的发现步骤 | [Local Accounts Discovery](../sigma/rules/windows/process_creation/proc_creation_win_susp_local_system_owner_account_discovery.yml) | `match` | `Image` 为 `C:\\Windows\\System32\\whoami.exe`，满足该规则 whoami 分支。此规则没有把 `cmd.exe` 父进程排除；单独的 `whoami` 也可能是正常管理活动。 |
| E05 | L2090，Sysmon 1，Edge 浏览器启动；背景候选 | [Local Accounts Discovery](../sigma/rules/windows/process_creation/proc_creation_win_susp_local_system_owner_account_discovery.yml) | `miss` | `Image=msedge.exe`，命令行是浏览器 profile 参数，不满足该规则的账户发现命令分支。 |
| E06 | L17255，Sysmon 1，`systeminfo`；元数据支持攻击链中的发现步骤 | [Local Accounts Discovery](../sigma/rules/windows/process_creation/proc_creation_win_susp_local_system_owner_account_discovery.yml) | `miss` | 该规则不选 `systeminfo`。这是**攻击相关事件上的规则未命中**，说明 `miss` 不能解释成“事件良性”。 |

复核时请逐行打开原事件和完整 YAML，尤其确认 E01 的 `CallTrace` OR 条件、E03 的排除项以及 E02 的 `endswith: FF`。这些样本用于练规则条件与字段匹配；要报告真正的 `rule_tests.status=hit/miss`，还需由执行器运行规则并保存匹配事件 ID、跳过数与引擎版本。背景候选若用作正式误报评估，须进一步核对上下文，最好再引入独立良性数据。
