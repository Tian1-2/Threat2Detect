# 报告式合成评测集

reports/ 为五份仿照 CISA 案例结构的原创虚构报告。reference.json 为评测方使用的证据、映射、逐事件标签与主控预期。后续做模型盲测时，只向模型传入 reports/ 中的正文。

此包的 evaluate.py 使用人工标注交接包，实际运行仓库确定性主控、合成规则检索和静态执行器。安装项目 requirements-poc.txt 后运行：

    python evaluate.py --repo /path/to/Threat2Detect --dataset . --output result.json

评价范围是五个预定义边界案例。规则库为三条合成规则，模型行为提取、自动映射和模型适用性判断留待模型盲测。
