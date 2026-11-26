# Threat2Detect 前端初版

直接打开 `index.html`，或从仓库根目录运行 `python3 -m http.server 8765 --directory web` 后访问 http://localhost:8765 。

报告、Agent 活动、数据接入使用 `docs/design/frontend-example-data.json` 的静态快照。报告支持搜索、筛选、分页、详情和报告导出。Agent 活动支持逐步查看、筛选和轨迹导出。数据接入支持查看固定版本、日志源、按事件类型浏览字段和样例。复核草稿写入当前浏览器并可导出。运行分析与在线接入入口显示当前连接状态。

更新示例快照时，在仓库根目录运行：

```sh
{ printf 'window.demoData = '; cat docs/design/frontend-example-data.json; printf ';\n'; } > web/demo-data.js
```
