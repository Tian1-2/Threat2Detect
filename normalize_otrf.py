"""Normalize OTRF Windows Sysmon JSONL/ZIP to the v1.0 normalized_events contract."""
from __future__ import annotations

import argparse
import json
import zipfile
from contextlib import contextmanager
from pathlib import Path

from validate_contract import ROOT, validate_contract


DEFAULT_SOURCE = ROOT / "data/Security-Datasets/datasets/compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump.zip"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
CATEGORY = {1: "process_creation", 10: "process_access", 11: "file_event"}


@contextmanager
def source_lines(path: Path):
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            names = [name for name in archive.namelist() if name.lower().endswith((".json", ".jsonl"))]
            if len(names) != 1:
                raise ValueError(f"Expected one JSONL member in {path}, found {len(names)}")
            with archive.open(names[0]) as stream:
                yield (line.decode("utf-8") for line in stream)
    else:
        with path.open(encoding="utf-8") as stream:
            yield stream


def parse_message(message: str) -> dict[str, str]:
    fields = {}
    for line in message.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields[key] = value
    return fields


def normalize(path: Path, dataset_id: str, event_ids: set[int] | None = None) -> dict:
    items = []
    parse_errors = 0
    seen_sysmon = 0
    with source_lines(path) as lines:
        for line_number, line in enumerate(lines, 1):
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                parse_errors += 1
                continue
            if event.get("Channel") != SYSMON_CHANNEL:
                continue
            seen_sysmon += 1
            event_code = event.get("EventID")
            if event_ids is not None and event_code not in event_ids:
                continue
            if not isinstance(event_code, (int, str)) or not isinstance(event.get("Message"), str):
                parse_errors += 1
                continue
            items.append({
                "event_uid": f"{dataset_id}:L{line_number}", "event_code": event_code,
                "channel": SYSMON_CHANNEL, "host": event.get("Hostname"),
                "timestamp_raw": event.get("TimeCreated"), "fields": parse_message(event["Message"]),
                "raw_ref": f"{path.relative_to(ROOT).as_posix()}#L{line_number}",
                "logsource": {"product": "windows", "category": CATEGORY.get(event_code), "service": "sysmon"},
            })
    return {"schema_version": "1.0", "kind": "normalized_events", "dataset_id": dataset_id,
            "source_path": path.relative_to(ROOT).as_posix(), "parse_error_count": parse_errors,
            "source_sysmon_events": seen_sysmon, "items": items}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--input", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--dataset-id", default="OTRF-LSASS_campaign_06")
    parser.add_argument("--event-ids", type=int, nargs="*", default=[1, 10, 11])
    args = parser.parse_args()
    source = args.input.resolve()
    result = normalize(source, args.dataset_id, set(args.event_ids))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    validate_contract(result, args.output)
    print(f"{len(result['items'])} events, {result['parse_error_count']} parse errors -> {args.output}")


if __name__ == "__main__":
    main()
