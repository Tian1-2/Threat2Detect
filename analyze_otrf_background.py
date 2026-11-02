"""Summarize event populations in the OTRF LSASS campaign JSONL.

This is a telemetry inventory, not a benign/malicious classifier.
"""
import collections
import json
import zipfile
from pathlib import Path


PATH = Path("data/Security-Datasets/datasets/compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump.json")


def fields(message):
    return dict(part.split(": ", 1) for part in message.splitlines() if ": " in part)


def main():
    channels = collections.Counter()
    ids = collections.Counter()
    images = collections.Counter()
    access_sources = collections.Counter()
    access_examples = {}
    filenames = collections.Counter()
    hosts = collections.Counter()
    first = last = None
    examples = {}
    source = PATH if PATH.exists() else PATH.with_suffix(".zip")
    if source.suffix == ".zip":
        archive = zipfile.ZipFile(source)
        stream = (line.decode("utf-8") for line in archive.open(archive.namelist()[0]))
    else:
        archive = None
        stream = source.open(encoding="utf-8")
    try:
        for line_number, line in enumerate(stream, 1):
            event = json.loads(line)
            channel, event_id = event.get("Channel", ""), event.get("EventID")
            data = fields(event.get("Message", ""))
            channels[channel] += 1
            ids[(channel, event_id)] += 1
            hosts[event.get("Hostname", "")] += 1
            stamp = event.get("TimeCreated")
            if stamp:
                first = min(first, stamp) if first else stamp
                last = max(last, stamp) if last else stamp
            if channel != "Microsoft-Windows-Sysmon/Operational":
                continue
            if event_id == 1:
                image = data.get("Image", "")
                images[image] += 1
                if image and image not in examples:
                    examples[image] = (line_number, stamp, data.get("CommandLine", ""), data.get("ParentImage", ""))
            elif event_id == 10 and data.get("TargetImage", "").lower().endswith("\\lsass.exe"):
                access_sources[(data.get("SourceImage", ""), data.get("GrantedAccess", ""))] += 1
                key = (data.get("SourceImage", ""), data.get("GrantedAccess", ""))
                access_examples.setdefault(key, (line_number, stamp, data.get("CallTrace", ""), data.get("SourceUser", "")))
            elif event_id == 11:
                filenames[data.get("TargetFilename", "")] += 1
    finally:
        if archive:
            archive.close()
        else:
            stream.close()
    for name, value in (("events", sum(channels.values())), ("time_range", (first, last)), ("channels", channels.most_common()),
                        ("sysmon_event_ids", [(eid, n) for (ch, eid), n in ids.most_common() if ch == "Microsoft-Windows-Sysmon/Operational"]),
                        ("hosts", hosts.most_common()), ("top_process_images", images.most_common(20)),
                        ("lsass_access_sources", access_sources.most_common(20)),
                        ("lsass_access_examples", [(key, access_examples[key]) for key, _ in access_sources.most_common(20)]),
                        ("top_created_files", filenames.most_common(12)),
                        ("process_examples", [(image, examples[image]) for image, _ in images.most_common(20)])):
        print(name, json.dumps(value, ensure_ascii=False))


if __name__ == "__main__":
    main()
