# Threat2Detect Workbench

Open `index.html` directly, or run `python3 -m http.server 8765 --directory web` from the repository root and visit http://localhost:8765.

The Reports, Agent Activity, and Data Sources views use a snapshot of `docs/design/frontend-example-data.json`. You can search and filter reports, inspect behavior evidence, export reports and agent traces, and browse pinned rule versions and offline log samples. Review drafts are saved in the current browser and can be exported. Live analysis and log connections require a backend.

To refresh the demo snapshot, run this from the repository root:

```sh
{ printf 'window.demoData = '; cat docs/design/frontend-example-data.json; printf ';\n'; } > web/demo-data.js
```
