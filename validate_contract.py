"""Validate Threat2Detect v1.0 module handoff JSON files.

Usage: python validate_contract.py data/annotations/aa25_266a_gold_draft.json
Requires jsonschema (`python -m pip install jsonschema`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).parent
ID = {"type": "string", "minLength": 1}
TEXT = {"type": "string"}
HASH = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
ATTACK_ID = {"type": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"}
STRINGS = {"type": "array", "items": TEXT}
FACT_STATUS = {"enum": ["observed", "attempted", "inferred", "unclear"]}
REVIEW_STATUS = {"enum": ["draft", "confirmed", "disputed", "insufficient_evidence"]}
CONFIDENCE = {"enum": ["high", "medium", "low", "unknown"]}
ORIGIN = {"enum": ["cisa_inline", "cisa_table", "team_review", "agent_proposal"]}


def record(required: list[str], properties: dict) -> dict:
    return {"type": "object", "required": required, "properties": properties, "additionalProperties": True}


EVIDENCE = record(
    ["quote", "char_start", "char_end", "pdf_page"],
    {"quote": {"type": "string", "minLength": 1}, "char_start": {"type": "integer", "minimum": 0},
     "char_end": {"type": "integer", "minimum": 1}, "pdf_page": {"type": ["integer", "null"], "minimum": 1}},
)
BEHAVIOR = record(
    ["behavior_id", "evidence", "action", "object", "fact_status", "confidence", "origin", "review_status"],
    {"behavior_id": ID, "evidence": EVIDENCE, "action": ID, "object": ID,
     "fact_status": FACT_STATUS, "confidence": CONFIDENCE, "origin": ORIGIN, "review_status": REVIEW_STATUS},
)
MAPPING = record(
    ["mapping_id", "behavior_id", "technique_id", "technique_name", "rationale", "confidence", "origin", "review_status", "retrieved_candidate_ids"],
    {"mapping_id": ID, "behavior_id": ID, "technique_id": ATTACK_ID,
     "technique_name": ID, "rationale": ID, "confidence": CONFIDENCE,
     "origin": ORIGIN, "review_status": REVIEW_STATUS,
     "retrieved_candidate_ids": {"type": ["array", "null"], "items": ATTACK_ID}},
)
LOGSOURCE = record(
    ["product", "category", "service"],
    {"product": ID, "category": {"type": ["string", "null"]}, "service": {"type": ["string", "null"]}},
)
REQUIRED_SOURCE = record(
    ["product", "category", "event_ids", "fields", "reason"],
    {"product": ID, "category": ID, "event_ids": STRINGS, "fields": STRINGS, "reason": ID},
)
TELEMETRY = record(
    ["behavior_id", "required_sources", "available_dataset_ids", "assessment", "reason"],
    {"behavior_id": ID, "required_sources": {"type": "array", "items": REQUIRED_SOURCE},
     "available_dataset_ids": STRINGS,
     "assessment": {"enum": ["testable", "partial", "unavailable", "not_assessed"]},
     "reason": TEXT},
)
RULE_CANDIDATE = record(
    ["candidate_id", "behavior_id", "technique_id", "rule_id", "rule_path", "rule_sha256", "title", "tags", "logsource", "status", "required_fields", "retrieval_reason"],
    {"candidate_id": ID, "behavior_id": ID, "technique_id": ATTACK_ID,
     "rule_id": ID, "rule_path": ID, "rule_sha256": HASH, "title": ID,
     "tags": STRINGS, "logsource": LOGSOURCE, "status": {"type": ["string", "null"]},
     "required_fields": STRINGS, "retrieval_reason": ID},
)
COVERAGE = record(
    ["coverage_id", "candidate_id", "behavior_id", "decision", "supporting_conditions", "missing_conditions", "unknown_conditions", "explanation", "review_status"],
    {"coverage_id": ID, "candidate_id": ID, "behavior_id": ID,
     "decision": {"enum": ["matches_procedure", "partially_matches", "does_not_match", "insufficient_detail"]},
     "supporting_conditions": STRINGS, "missing_conditions": STRINGS, "unknown_conditions": STRINGS,
     "explanation": ID, "review_status": REVIEW_STATUS},
)
EVENT = record(
    ["event_uid", "event_code", "channel", "host", "timestamp_raw", "fields", "raw_ref"],
    {"event_uid": ID, "event_code": {"type": ["string", "integer"]}, "channel": ID,
     "host": {"type": ["string", "null"]}, "timestamp_raw": {"type": ["string", "null"]},
     "fields": {"type": "object"}, "raw_ref": ID},
)
RULE_TEST = record(
    ["candidate_id", "dataset_id", "status", "matched_event_uids", "events_evaluated", "events_skipped", "unsupported_features", "reason", "engine_version"],
    {"candidate_id": ID, "dataset_id": ID,
     "status": {"enum": ["hit", "miss", "not_tested", "incompatible_logsource", "unsupported_rule"]},
     "matched_event_uids": STRINGS, "events_evaluated": {"type": "integer", "minimum": 0},
     "events_skipped": {"type": "integer", "minimum": 0}, "unsupported_features": STRINGS,
     "reason": TEXT, "engine_version": ID},
)
EVENT_REF = record(
    ["dataset_id", "event_uid", "provenance"],
    {"dataset_id": ID, "event_uid": ID,
     "provenance": {"enum": ["public_attack", "public_benign", "local_capture", "synthetic"]}},
)
GEN_TEST = record(
    ["dataset_id", "tested_event_uids", "matched_event_uids", "status", "reason"],
    {"dataset_id": ID, "tested_event_uids": STRINGS, "matched_event_uids": STRINGS,
     "status": {"enum": ["hit", "miss", "not_tested", "unsupported_rule"]},
     "reason": TEXT},
)


def envelope(kind: str, required: list[str], fields: dict) -> dict:
    return record(["schema_version", "kind", *required], {
        "schema_version": {"const": "1.0"}, "kind": {"const": kind}, **fields,
    })


SCHEMAS = {
    "case_handoff": envelope("case_handoff", ["case_id", "report", "attack_catalog", "behaviors", "mappings", "telemetry", "warnings"], {
        "case_id": ID,
        "report": record(["case_id", "title", "source_url", "input_path", "input_sha256", "annotation_basis"], {
            "case_id": ID, "title": ID, "source_url": {"type": "string", "format": "uri"},
            "input_path": ID, "input_sha256": HASH,
            "annotation_basis": {"const": "answer_hidden_report_and_attack_catalog"},
        }),
        "attack_catalog": record(["version", "sha256", "path"], {"version": ID, "sha256": HASH, "path": ID}),
        "behaviors": {"type": "array", "items": BEHAVIOR},
        "mappings": {"type": "array", "items": MAPPING},
        "telemetry": {"type": "array", "items": TELEMETRY},
        "warnings": STRINGS,
    }),
    "rule_candidates": envelope("rule_candidates", ["case_id", "ruleset_commit", "items"], {
        "case_id": ID, "ruleset_commit": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"},
        "items": {"type": "array", "items": RULE_CANDIDATE},
    }),
    "coverage_assessments": envelope("coverage_assessments", ["case_id", "ruleset_commit", "items"], {
        "case_id": ID, "ruleset_commit": {"type": ["string", "null"], "pattern": "^[0-9a-f]{40}$"},
        "items": {"type": "array", "items": COVERAGE},
    }),
    "normalized_events": envelope("normalized_events", ["dataset_id", "source_path", "parse_error_count", "items"], {
        "dataset_id": ID, "source_path": ID, "parse_error_count": {"type": "integer", "minimum": 0},
        "items": {"type": "array", "items": EVENT},
    }),
    "rule_tests": envelope("rule_tests", ["case_id", "items"], {
        "case_id": ID, "items": {"type": "array", "items": RULE_TEST},
    }),
    "rule_generation_request": envelope("rule_generation_request", ["scenario_id", "behavior", "attack_ids", "logsource", "available_fields", "positive_event_refs", "negative_event_refs", "executor_supported_features", "detection_goal"], {
        "scenario_id": ID, "behavior": ID,
        "attack_ids": {"type": "array", "items": ATTACK_ID, "minItems": 1},
        "logsource": LOGSOURCE, "available_fields": STRINGS,
        "positive_event_refs": {"type": "array", "items": EVENT_REF},
        "negative_event_refs": {"type": "array", "items": EVENT_REF},
        "executor_supported_features": STRINGS, "detection_goal": ID,
    }),
    "rule_generation_result": envelope("rule_generation_result", ["scenario_id", "candidate_yaml_path", "candidate_yaml_sha256", "parse_status", "required_fields", "positive_tests", "negative_tests", "limitations"], {
        "scenario_id": ID, "candidate_yaml_path": {"type": ["string", "null"]},
        "candidate_yaml_sha256": {"anyOf": [HASH, {"type": "null"}]},
        "parse_status": {"enum": ["valid", "invalid", "unsupported_syntax"]},
        "required_fields": STRINGS, "positive_tests": {"type": "array", "items": GEN_TEST},
        "negative_tests": {"type": "array", "items": GEN_TEST}, "limitations": STRINGS,
    }),
    "case_result": envelope("case_result", ["case_id", "behavior_ids", "coverage_ids", "rule_test_candidate_ids", "limitations"], {
        "case_id": ID, "behavior_ids": STRINGS, "coverage_ids": STRINGS,
        "rule_test_candidate_ids": STRINGS, "limitations": STRINGS,
    }),
}


def workspace_path(relative: str) -> Path:
    candidate = (ROOT / relative).resolve()
    if not candidate.is_relative_to(ROOT.resolve()):
        raise ValueError(f"Path leaves project workspace: {relative}")
    return candidate


def validate_contract(data: dict, file_path: Path) -> None:
    kind = data.get("kind")
    if kind not in SCHEMAS:
        raise ValueError(f"Unknown kind {kind!r}; expected one of {', '.join(SCHEMAS)}")
    errors = sorted(Draft202012Validator(SCHEMAS[kind]).iter_errors(data), key=lambda e: str(e.path))
    if errors:
        error = errors[0]
        raise ValueError(f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}")
    if kind == "case_handoff":
        if "official_technique_ids" in data["report"] or "official_attack_version" in data["report"]:
            raise ValueError("Official mapping metadata must stay in the separate reference file")
        if data["case_id"] != data["report"]["case_id"]:
            raise ValueError("case_id differs from report.case_id")
        ids = [item["behavior_id"] for item in data["behaviors"]]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate behavior_id")
        mapping_ids = [item["mapping_id"] for item in data["mappings"]]
        if len(mapping_ids) != len(set(mapping_ids)):
            raise ValueError("Duplicate mapping_id")
        if any(item["behavior_id"] not in ids for item in [*data["mappings"], *data["telemetry"]]):
            raise ValueError("Mapping or telemetry refers to missing behavior_id")
        report_path = workspace_path(data["report"]["input_path"])
        if report_path.is_file():
            if hashlib.sha256(report_path.read_bytes()).hexdigest() != data["report"]["input_sha256"]:
                raise ValueError("Report input SHA-256 mismatch")
            text = report_path.read_text(encoding="utf-8")
            for item in data["behaviors"]:
                ev = item["evidence"]
                if text[ev["char_start"] : ev["char_end"]] != ev["quote"]:
                    raise ValueError(f"{item['behavior_id']}: evidence quote does not match report input")
        else:
            raise ValueError(f"Report input not found: {report_path}")
        catalog_path = workspace_path(data["attack_catalog"]["path"])
        if not catalog_path.is_file() or hashlib.sha256(catalog_path.read_bytes()).hexdigest() != data["attack_catalog"]["sha256"]:
            raise ValueError("ATT&CK catalog missing or SHA-256 mismatch")
        catalog_data = json.loads(catalog_path.read_text(encoding="utf-8"))
        if "objects" in catalog_data:
            names = {}
            for item in catalog_data["objects"]:
                if item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
                    continue
                for ref in item.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        names[ref["external_id"]] = item["name"]
        else:
            names = catalog_data
        for mapping in data["mappings"]:
            if mapping["technique_id"] not in names or mapping["technique_name"] != names[mapping["technique_id"]]:
                raise ValueError(f"{mapping['mapping_id']}: ATT&CK ID or name differs from fixed catalog")
    elif kind in {"rule_candidates", "coverage_assessments"} and data["items"] and not data["ruleset_commit"]:
        raise ValueError("Nonempty rule items require ruleset_commit")
    elif kind == "rule_tests":
        for result in data["items"]:
            if result["status"] == "hit" and not result["matched_event_uids"]:
                raise ValueError(f"{result['candidate_id']}: hit requires matched_event_uids")
            if result["status"] != "hit" and result["matched_event_uids"]:
                raise ValueError(f"{result['candidate_id']}: non-hit result cannot contain matched events")


def validate_links(data: dict, handoff: dict | None = None, candidates: dict | None = None, events: dict | None = None) -> None:
    """Check foreign keys when upstream stage files are supplied."""
    kind = data["kind"]
    if handoff:
        if handoff["kind"] != "case_handoff" or handoff["case_id"] != data.get("case_id"):
            raise ValueError("Handoff kind or case_id does not match")
        behavior_ids = {row["behavior_id"] for row in handoff["behaviors"]}
        mapping_pairs = {(row["behavior_id"], row["technique_id"]) for row in handoff["mappings"]}
        if kind == "rule_candidates":
            for candidate in data["items"]:
                pair = (candidate["behavior_id"], candidate["technique_id"])
                if pair not in mapping_pairs:
                    raise ValueError(f"{candidate['candidate_id']}: missing behavior-to-technique mapping in handoff")
        if kind == "coverage_assessments":
            for assessment in data["items"]:
                if assessment["behavior_id"] not in behavior_ids:
                    raise ValueError(f"{assessment['coverage_id']}: missing behavior_id in handoff")
        if kind == "case_result" and set(data["behavior_ids"]) - behavior_ids:
            raise ValueError("case_result contains behavior_id absent from handoff")
    if candidates:
        if candidates["kind"] != "rule_candidates" or candidates["case_id"] != data.get("case_id"):
            raise ValueError("Rule candidates kind or case_id does not match")
        candidate_by_id = {row["candidate_id"]: row for row in candidates["items"]}
        if kind == "coverage_assessments":
            for assessment in data["items"]:
                candidate = candidate_by_id.get(assessment["candidate_id"])
                if not candidate or candidate["behavior_id"] != assessment["behavior_id"]:
                    raise ValueError(f"{assessment['coverage_id']}: candidate_id or behavior_id mismatch")
        if kind == "rule_tests":
            for result in data["items"]:
                if result["candidate_id"] not in candidate_by_id:
                    raise ValueError(f"{result['candidate_id']}: missing candidate_id in rule candidates")
        if kind == "case_result":
            for row in data.get("items", []):
                candidate = candidate_by_id.get(row["candidate_id"])
                if not candidate or row["behavior_id"] != candidate["behavior_id"] or row["technique_id"] != candidate["technique_id"]:
                    raise ValueError(f"{row['candidate_id']}: case_result candidate link mismatch")
            if set(data["rule_test_candidate_ids"]) - candidate_by_id.keys():
                raise ValueError("case_result contains rule test ID absent from candidates")
    if events:
        if events["kind"] != "normalized_events":
            raise ValueError("Events file must be normalized_events")
        event_ids = {row["event_uid"] for row in events["items"]}
        if kind == "rule_tests":
            for result in data["items"]:
                if result["dataset_id"] != events["dataset_id"]:
                    raise ValueError(f"{result['candidate_id']}: dataset_id mismatch")
                unknown = set(result["matched_event_uids"]) - event_ids
                if unknown:
                    raise ValueError(f"{result['candidate_id']}: matched_event_uids not in normalized events: {sorted(unknown)}")
        if kind == "case_result":
            for row in data.get("items", []):
                if row["dataset_id"] != events["dataset_id"]:
                    raise ValueError(f"{row['candidate_id']}: case_result dataset_id mismatch")
                if set(row.get("matched_event_uids") or []) - event_ids:
                    raise ValueError(f"{row['candidate_id']}: case_result references absent events")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--handoff", type=Path, help="Upstream case_handoff JSON for foreign-key checks")
    parser.add_argument("--candidates", type=Path, help="Upstream rule_candidates JSON for foreign-key checks")
    parser.add_argument("--events", type=Path, help="Upstream normalized_events JSON for hit-event checks")
    args = parser.parse_args()
    data = json.loads(args.file.read_text(encoding="utf-8"))
    validate_contract(data, args.file)
    upstream = {}
    for key in ("handoff", "candidates", "events"):
        path = getattr(args, key)
        if path:
            upstream[key] = json.loads(path.read_text(encoding="utf-8"))
            validate_contract(upstream[key], path)
    validate_links(data, **upstream)
    print(f"VALID {data['kind']}: {args.file}")


if __name__ == "__main__":
    main()
