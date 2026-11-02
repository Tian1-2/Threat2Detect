# 项目数据版本锁定（2026-10-31）

## ATT&CK

截至 2026-10-31，MITRE 官方 [更新页](https://attack.mitre.org/resources/updates/)与[版本历史](https://attack.mitre.org/resources/previous-versions/)均将 **ATT&CK v20.0（2026-10-13）**列为当前版本。

项目使用 **Enterprise ATT&CK v20.0**，固定数据文件：[data/attack/enterprise-attack-20.0.json](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json)（STIX 2.1，实际下载约 55 MB）。MITRE 的[版本索引](https://github.com/mitre-attack/attack-stix-data/blob/master/index.md)也列出该固定版本。浏览器下载并保存此 JSON 即可；不要用 `enterprise-attack.json` 或 `master` 上的无版本文件作为最终锁定依据。

已下载至 `data/attack/enterprise-attack-20.0.json`，SHA-256：`81113BA98AFA2928F3DCFF62022539F7CE30C315C32E14422F11FF95CE534352`。可用 `Get-FileHash -Algorithm SHA256 <下载文件路径>` 复核。ATT&CK ID 校验和技术名称以该文件为准；原报告使用旧版 ATT&CK 的标签时保留原标签，同时记录 v20.0 核对结果。

## SigmaHQ

正式基库：[SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)。本地仓库路径为 `data/sigma`。固定 commit：`05d1031f537e830b76da53bae2400c5814c89165`（2026-11-01 读取）。更新仓库后需要重查规则哈希与覆盖判断。同一批黄金案例和测试都使用这一 SHA，不用浮动的 `master` 作为版本标识。

规则检索时保存仓库相对路径、规则 `id`、`status` 和 commit SHA；规则文件后来更新时，仍能复现当时的判断。项目之前用于教学的 NVISO 规则位于已归档仓库，不作为正式基库版本的一部分。
