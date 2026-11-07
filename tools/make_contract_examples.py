"""Create draft handoff files for the two human review tables.

Run after build_cisa_cases.py. Existing human-reviewed files are never overwritten.
"""

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "annotations"


def save_new(path: Path, value: dict) -> None:
    if path.exists():
        print(f"kept existing {path}")
        return
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"created {path}")


def main() -> None:
    OUT.mkdir(exist_ok=True)
    report_path = ROOT / "data" / "reports" / "cisa-aa25-266a-input.txt"
    catalog_path = ROOT / "data" / "attack" / "enterprise-attack-20.0.json"
    report_text = report_path.read_text(encoding="utf-8")
    rows = [
        ("whoami", "identify current user", "current user on SQL Server", "T1033", "System Owner/User Discovery", "The command whoami identifies the current user on the SQL server, which fits T1033."),
        ("ipconfig /all", "inspect network configuration", "SQL Server network configuration", "T1016", "System Network Configuration Discovery", "The command ipconfig /all requests network adapter configuration on the SQL server, which fits T1016."),
        ("tasklist", "list running processes", "processes on SQL Server", "T1057", "Process Discovery", "The command tasklist enumerates running processes on the SQL server, which fits T1057."),
        ("Stowaway", "proxy C2 traffic into the internal network", "C2 traffic", "T1090", "Proxy", "Stowaway forwarded C2 traffic through the Web Server into the internal network, which fits T1090."),
    ]
    behaviors = []
    mappings = []
    for number, (quote, action, target, technique_id, technique_name, rationale) in enumerate(rows, 1):
        start = report_text.index(quote)
        pages = [int(match.group(1)) for match in re.finditer(r"=== PDF PAGE (\d+) ===", report_text[:start])]
        behavior_id = f"AA25-266A-G{number:03d}"
        behaviors.append({
            "behavior_id": behavior_id,
            "evidence": {"quote": quote, "char_start": start, "char_end": start + len(quote), "pdf_page": pages[-1] if pages else None},
            "action": action,
            "object": target,
            "fact_status": "observed",
            "confidence": "high",
            "origin": "team_review",
            "review_status": "draft",
            "context_note": "Read the surrounding paragraph/list in the source PDF before confirming this row.",
        })
        mappings.append({
            "mapping_id": f"AA25-266A-M{number:03d}",
            "behavior_id": behavior_id,
            "technique_id": technique_id,
            "technique_name": technique_name,
            "rationale": rationale,
            "confidence": "high",
            "origin": "team_review",
            "review_status": "draft",
            "retrieved_candidate_ids": None,
        })
    handoff = {
        "schema_version": "1.0", "kind": "case_handoff", "case_id": "AA25-266A",
        "report": {
            "case_id": "AA25-266A",
            "title": "CISA Shares Lessons Learned from Incident Response Engagement",
            "source_url": "https://www.cisa.gov/sites/default/files/2025-09/AA25-266A_advisory_cisa_shares_lessons_learned_from_ir_engagement.pdf",
            "input_path": report_path.relative_to(ROOT).as_posix(),
            "input_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
            "annotation_basis": "answer_hidden_report_and_attack_catalog",
        },
        "attack_catalog": {
            "version": "Enterprise 20.0",
            "sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
            "path": catalog_path.relative_to(ROOT).as_posix(),
        },
        "behaviors": behaviors, "mappings": mappings, "telemetry": [],
        "warnings": ["DRAFT: group lead must confirm source context and behavior-level mapping before B uses these rows."],
    }
    save_new(OUT / "aa25_266a_gold_draft.json", handoff)
    save_new(OUT / "coverage_gold_template.json", {
        "schema_version": "1.0", "kind": "coverage_assessments", "case_id": "AA25-266A",
        "ruleset_commit": None, "items": [],
    })
    save_new(OUT / "rule_generation_request_example.json", {
        "schema_version": "1.0", "kind": "rule_generation_request", "scenario_id": "manual-lsass-demo-01",
        "behavior": "A suspicious process accesses LSASS memory and attempts a dump",
        "attack_ids": ["T1003.001"],
        "logsource": {"product": "windows", "category": "process_access", "service": None},
        "available_fields": ["SourceImage", "TargetImage", "GrantedAccess", "CallTrace"],
        "positive_event_refs": [], "negative_event_refs": [],
        "executor_supported_features": ["contains", "endswith", "and", "or", "not"],
        "detection_goal": "Identify suspicious LSASS memory access using the stated telemetry; report untested false positives.",
    })


if __name__ == "__main__":
    main()
