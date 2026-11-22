# 候选 Sigma 生成与样例验证

`src/threat2detect/rule_generation/generator.py` 实现独立的 `rule_generation_request → rule_generation_result` 接口。
输入必须给出具体行为、检测目标、日志源、可用字段及执行器支持范围；ATT&CK ID 只生成标签。
不依赖成员 B 的召回输出，不自动宣称现有规则存在缺口。

## 用真实 OTRF 开发样例运行

项目根目录执行，先安装 `config/requirements.txt` 并准备本机 Ollama `qwen3:4b`。
每次使用新的空输出目录，程序拒绝覆盖旧运行。

```powershell
python tools/prepare_rule_generation_demo.py artifacts/runs/rule-generation-fixture-v1
python -m src.threat2detect.rule_generation.generator artifacts/runs/rule-generation-fixture-v1/request.json artifacts/runs/rule-generation-ollama-v1 --events artifacts/runs/rule-generation-fixture-v1/events.json --max-attempts 3
python -m src.threat2detect.contracts artifacts/runs/rule-generation-ollama-v1/result.json
```

准备脚本从现有 OTRF ZIP 提取 L33808（Dumpert 访问 LSASS）和 L1727（VBoxService 背景候选），保留原事件 UID、字段和来源位置。
检测目标由人工指定为 LSASS 的 `0x1FFFFF` 访问，属于窄范围开发案例。
L1727 的“负例”仅指该目标下预期不匹配；其来源是公开攻击模拟，**不是已证实良性日志**。
开发样例参与反馈修订，不能作为独立测试，也不能据此估计误报率或证明覆盖所有内存转储。

## 已有 YAML 的验证模式

```powershell
python -m src.threat2detect.rule_generation.generator request.json artifacts/runs/rule-validation-v1 --candidate candidate.yml --events events.json
```

此模式不调用模型，结果中 `generation_mode` 为 `supplied_candidate`，只能证明提供的候选经过检查，不能当作模型生成效果。
`--events` 可以重复传入不同的标准化数据集；重名数据集、重复事件 UID 和正负引用重叠会拒绝。
请求中的 `provenance` 由准备数据的人负责准确填写，程序保留该来源声明，不替代来源审核。

## 运行过程与产物

1. 校验请求与标准化日志契约。
2. 模型只接收行为、目标、日志源及字段约束，不接收正负事件 UID、原始事件值。CLI 模型返回结构化字段条件，由代码编译为 YAML；每轮原始条件保存在 `model-spec-N.json`。
3. 检查 YAML、字段白名单、请求日志源一致性、声明的修饰符及布尔运算。
4. 使用现有离线执行器，分别执行每条引用的样本。
5. 正例未命中或负例命中时，只返回期望/实际结果作为修订反馈；语法错误也反馈给模型。最多 1–5 次。
6. 输出 `result.json`、`trace.json`、`request.json`、每轮 `proposal-N.json` 和通过检查的 `candidate-N.yml`。

结果记录请求、数据集、候选 YAML 哈希、模型、提示词版本、执行器版本及所有测试事件引用。
模型连接或输出失败会保存结构化失败结果和轨迹；不会虚构规则或命中。
`parse_status: valid` 只表示通过本模块的受限格式/执行检查，不是完整 Sigma 标准认证或检测效果认证。
所有规则强制为 `experimental`，结果保持 `draft`，仍需人工审核条件。

`validation_outcome` 单独记录 `invalid_candidate`、`failed`、`incomplete` 或 `passed_development_samples`，避免把语法通过误读为样例验证通过。失败或候选无效时 CLI 返回非零退出码。

请求可增加 `required_conditions`，每项为 `{field, modifier, value}`，如 `TargetImage / endswith / \\lsass.exe` 和 `GrantedAccess / equals / 0x1FFFFF`。这些条件由人工明确给定；检查器要求它们以合取方式强制成立，防止只因少数测试样本碰巧命中就放过缺失关键条件的规则。该模式保守地拒绝 OR/NOT，不代表通用逻辑等价证明。

## 目前支持与限制

- 复用 Windows Sysmon `process_creation`、`process_access`、`file_event` 执行器。
- 支持非空字段字典、字典列表、标量/值列表、受支持且在请求中声明的字符串修饰符，以及 `and/or/not` 和括号。
- 不支持通配值、正则、聚合/关联、时间窗口、关键字选择器及选择器数量表达式；遇到这些返回 `unsupported_syntax`。
- 缺失样本、不兼容日志源标记 `not_tested`，不转换成 `miss`；无正例或负例单独写明未测试。
- 同一事件不能同时作正例与负例；未提供来源数据时不会补造事件。
- 达到修订次数后仍保留真实失败和限制，不把最后一轮强行算通过。
- 当前不做 SigmaHQ 重复规则搜索，不连接 SIEM、不执行规则里的命令、不自动部署。

## 本机首轮验证记录

2026-11-22 使用本机 `qwen3:4b`。直接生成 YAML 曾出现非法格式；改为结构化条件后，又观察到“少数样例通过但未限定 LSASS 目标”的过宽规则，因此加入人工必需条件护栏。
最终 `rule-generation-0.4` 在 `artifacts/runs/rule-generation-ollama-v4/` 单轮生成 `TargetImage` 以 `\\lsass.exe` 结尾 **且** `GrantedAccess=0x1FFFFF` 的候选，L33808 命中、L1727 未命中。
这次结果仅证明指定开发样例闭环跑通；不证明生成质量稳定、相对 SigmaHQ 存在新增覆盖，或具备生产检测效果。运行产物留在本地并被 Git 忽略，可按上述步骤重建。

测试：`python -m pytest -q tests/test_rule_generation.py tests/test_sigma_offline.py tests/test_contract.py`。
后续主控 Agent 可调用 `generate()`；只有主流程集成展示时，再增加已有规则重复检查与真实缺口核对。

## 第二轮：条件依据、执行诊断与封存边界测试

提示词 v0.5 将报告事实、人工目标、约束、允许的假设分开，未知项单列。提供 `evidence_items` 时每个模型条件必须引用有效依据 ID，并解释来源，保存在 `condition_basis`；程序检查引用存在，不自动证明解释正确。

`condition_diagnostics` 按选择器、分支、字段记录 `match` / `no_match` / `missing`，同时保留选择器整体真假。OR 分支内单条件失败不等于规则失败。只有开发样本的条件结果进入修订反馈，原始事件值及事件 UID 不进入模型；白名单控制提示词输入字段。

最终候选固定哈希后，才执行单独传入的封存样本，另存 `evaluation.json`；封存失败不再触发修订。若其结果用于后续调优，该组样本不再是后续版本的封存测试。

BITS 第二场景命令（选择新的空目录）：

```powershell
python tools/prepare_rule_generation_demo.py artifacts/runs/rule-generation-bits-fixture-new --scenario bits
python -m src.threat2detect.rule_generation.generator artifacts/runs/rule-generation-bits-fixture-new/request.json artifacts/runs/rule-generation-bits-new --events artifacts/runs/rule-generation-bits-fixture-new/events.json --evaluation-refs artifacts/runs/rule-generation-bits-fixture-new/evaluation_refs.json --evaluation-events artifacts/runs/rule-generation-bits-fixture-new/evaluation_events.json
```

不传 `--scenario bits` 则准备 LSASS。BITS 人工目标是 `Image` 以 `\\bitsadmin.exe` 结尾且命令包含 ` /transfer `；该参数来自人工选择的变体，不是 CISA 正文给出的事实，也不覆盖全部 BITS 方法。

本机 qwen3:4b 的 LSASS/BITS 实测均一轮生成：各两条真实开发事件符合预期（正例 hit、背景候选 miss）；各四条最终封存的**合成**边界事件符合预期，覆盖新路径/值、仅满足单条件、缺字段。合成结果不是独立真实日志验证，不能估计误报率。结果在本地 `artifacts/runs/rule-generation-lsass-v5/`、`artifacts/runs/rule-generation-bits-v5/`。

`data/research/sigma_writing_resources.json` 保存查阅的 10 个官方教程/规则链接；`data/annotations/sigma_writing_learning_samples.json` 提供 6 个自编教学草稿（含来源 URL、本地规则哈希和预期审核点），不是人工确认答案，不自动注入提示词，不混入封存事件。
