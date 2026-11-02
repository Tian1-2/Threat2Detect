"""Show the key Sysmon evidence in the OTRF LSASS_campaign_06 dataset."""
import argparse
import collections
import json
import pathlib
import sys
import zipfile
from contextlib import nullcontext

sys.stdout.reconfigure(encoding="utf-8")
base = pathlib.Path("data/Security-Datasets/datasets/compound/LSASS_campaign_06")
parser = argparse.ArgumentParser(description="用中文摘要查看 LSASS_campaign_06 的关键事件")
parser.add_argument("input", nargs="?", type=pathlib.Path,
                    default=base / "metasploit_outflank-dumpert_lsass_memory_dump.zip",
                    help="ZIP 或解压后的 JSON 文件")
path = parser.parse_args().input

def details(message):
    return dict(line.split(": ", 1) for line in message.splitlines() if ": " in line)

counts = collections.Counter()
matches = []
with (zipfile.ZipFile(path) if path.suffix.lower() == ".zip" else nullcontext()) as archive:
    with (archive.open(archive.namelist()[0]) if archive else path.open("rb")) as stream:
        for line in stream:
            event = json.loads(line)
            counts["all"] += 1
            if event.get("Channel") != "Microsoft-Windows-Sysmon/Operational":
                continue
            counts["sysmon"] += 1
            eid = event.get("EventID")
            data = details(event.get("Message", ""))
            image = data.get("Image", "").lower()
            source = data.get("SourceImage", "").lower()
            target = data.get("TargetImage", "").lower()
            filename = data.get("TargetFilename", "").lower()
            label = evidence = None
            if eid == 1 and image.endswith("\\systeminfo.exe"):
                label, evidence = "系统信息发现 T1082", data.get("CommandLine")
            elif eid == 1 and image.endswith("\\whoami.exe"):
                label, evidence = "当前用户发现 T1033", data.get("CommandLine")
            elif eid == 11 and filename.endswith("\\outflank-dumpert.exe"):
                label, evidence = "工具文件创建", data.get("TargetFilename")
            elif eid == 1 and image.endswith("\\outflank-dumpert.exe"):
                label, evidence = "工具运行", data.get("CommandLine")
            elif eid == 10 and source.endswith("\\outflank-dumpert.exe") and target.endswith("\\lsass.exe"):
                label, evidence = "工具访问 LSASS T1003.001", "访问权限=" + data.get("GrantedAccess", "未知")
            elif eid == 11 and filename.endswith("\\dumpert.dmp"):
                label, evidence = "转储文件创建 T1003.001", data.get("TargetFilename")
            if label:
                matches.append((event.get("TimeCreated", ""), eid, label, evidence or ""))

print(f"总事件 {counts['all']} 条；其中 Sysmon {counts['sysmon']} 条")
print("Sysmon 事件 ID：1=进程创建，10=进程访问，11=文件创建")
print("以下是符合本场景条件的事件，不代表这些命令在任何环境下都一定是攻击：\n")
for stamp, eid, label, evidence in sorted(matches):
    print(f"{stamp} | ID {eid:>2} | {label} | {evidence}")
print("\n时间使用 JSON 顶层 TimeCreated；本数据中 Message 内 UtcTime 与它不一致，请勿混用。")
