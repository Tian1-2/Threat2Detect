"""Connect report mapping, Sigma analysis, and offline event testing via v1.0 JSON contracts.

Run from the repository root. See docs/PIPELINE_RUNBOOK.md for examples.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agent_poc import analyze, load_catalog
from normalize_otrf import DEFAULT_SOURCE, normalize
from run_sigma_offline import run_rule
from sigma_agent import run as assess_with_agent
from sigma_coverage import run as assess_coverage
from sigma_retrieval import DEFAULT_RULES, retrieve
from validate_contract import validate_contract, validate_links, workspace_path


ROOT = Path(__file__).resolve().parent


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(path: Path) -> str:
    path = path.resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError(f"Input must be inside the project: {path}")
    return path.relative_to(ROOT).as_posix()


def save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    validate_contract(data, path)


def prediction_to_handoff(prediction: dict, report: Path, catalog_path: Path,
                          case_id: str, title: str, source_url: str, catalog_version: str) -> dict:
    """Keep proposals as drafts; reject stale or ungrounded experimental output."""
    if prediction.get("report_id") != case_id:
        raise ValueError("Prediction report_id differs from case_id")
    if prediction.get("input_sha256") != sha256(report) or prediction.get("catalog_sha256") != sha256(catalog_path):
        raise ValueError("Prediction input or ATT&CK catalog hash differs from current files")
    report_text = report.read_text(encoding="utf-8")
    catalog = load_catalog(catalog_path)
    behaviors, mappings = [], []
    warnings = list(prediction.get("warnings") or [])
    for index, raw in enumerate(prediction.get("behaviors") or [], 1):
        quote = raw.get("quote")
        start = (raw.get("location") or {}).get("char_start")
        if not isinstance(quote, str) or not isinstance(start, int) or report_text[start:start + len(quote)] != quote:
            raise ValueError(f"Prediction behavior {index} has no exact report quote")
        behavior_id = f"{case_id}-P{index:03d}"
        status = raw.get("observed_or_inferred", "unclear")
        if status not in {"observed", "attempted", "inferred", "unclear"}:
            status = "unclear"
        mapping = raw.get("mapping") or {}
        confidence = mapping.get("confidence", "unknown")
        if confidence not in {"high", "medium", "low", "unknown"}:
            confidence = "unknown"
        behaviors.append({"behavior_id": behavior_id,
                          "evidence": {"quote": quote, "char_start": start, "char_end": start + len(quote), "pdf_page": None},
                          "action": raw.get("action") or "unspecified action", "object": raw.get("object") or "unspecified object",
                          "fact_status": status, "confidence": confidence,
                          "origin": "agent_proposal", "review_status": "draft"})
        technique_id = mapping.get("technique_id")
        if technique_id is None:
            continue
        if technique_id not in catalog:
            raise ValueError(f"Prediction has ATT&CK ID outside catalog: {technique_id}")
        mappings.append({"mapping_id": f"{case_id}-M{len(mappings)+1:03d}", "behavior_id": behavior_id,
                         "technique_id": technique_id, "technique_name": catalog[technique_id]["name"],
                         "rationale": mapping.get("rationale") or "Agent proposal requires human review",
                         "confidence": confidence, "origin": "agent_proposal", "review_status": "draft",
                         "retrieved_candidate_ids": mapping.get("retrieved_candidate_ids") or None})
    warnings.append("Agent behavior and ATT&CK mappings are draft proposals, not human-confirmed findings.")
    return {"schema_version": "1.0", "kind": "case_handoff", "case_id": case_id,
            "report": {"case_id": case_id, "title": title, "source_url": source_url,
                       "input_path": relative(report), "input_sha256": sha256(report),
                       "annotation_basis": "answer_hidden_report_and_attack_catalog"},
            "attack_catalog": {"version": catalog_version, "sha256": sha256(catalog_path),
                               "path": relative(catalog_path)},
            "behaviors": behaviors, "mappings": mappings, "telemetry": [], "warnings": warnings}


def execute(args: argparse.Namespace) -> dict:
    output = args.output_dir.resolve()
    if not output.is_relative_to(ROOT):
        raise ValueError("Output directory must be inside the project")
    output.mkdir(parents=True, exist_ok=True)
    if args.handoff:
        handoff = json.loads(args.handoff.read_text(encoding="utf-8"))
    else:
        if not args.case_id or not args.source_url:
            raise ValueError("--report requires --case-id and --source-url")
        report, catalog_path = args.report.resolve(), args.catalog.resolve()
        relative(report)
        relative(catalog_path)
        if args.prediction:
            prediction = json.loads(args.prediction.read_text(encoding="utf-8"))
        else:
            prediction = analyze(args.case_id, report.read_text(encoding="utf-8"),
                                 load_catalog(catalog_path), args.model, args.endpoint, output / "prediction.json")
            prediction["input_sha256"] = sha256(report)
            prediction["catalog_sha256"] = sha256(catalog_path)
            (output / "prediction.json").write_text(json.dumps(prediction, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        handoff = prediction_to_handoff(prediction, report, catalog_path, args.case_id,
                                        args.title or args.case_id, args.source_url, args.catalog_version)
    handoff_path = output / "handoff.json"
    save(handoff_path, handoff)
    include_draft = any(row["review_status"] == "draft" for row in handoff["behaviors"])

    candidates = retrieve(handoff, args.rules.resolve(), args.limit, include_draft=include_draft)
    candidate_path = output / "candidates.json"
    save(candidate_path, candidates)
    validate_links(candidates, handoff=handoff)

    coverage_path = output / "coverage.json"
    if args.skip_coverage:
        coverage = {"schema_version": "1.0", "kind": "coverage_assessments", "case_id": handoff["case_id"],
                    "ruleset_commit": candidates["ruleset_commit"], "items": [],
                    "case_level_limitations": ["Sigma procedure comparison was skipped; candidate retrieval is not a coverage judgment."]}
        save(coverage_path, coverage)
    elif args.agent_coverage:
        coverage = assess_with_agent(handoff, candidates, coverage_path, args.model, args.endpoint,
                                     args.max_coverage, args.agent_max_steps, include_draft=include_draft)
    else:
        coverage = assess_coverage(handoff, candidates, coverage_path, args.model, args.endpoint,
                                   args.max_coverage, include_draft=include_draft)
    validate_links(coverage, handoff=handoff, candidates=candidates)

    events_path = args.events.resolve() if args.events else output / "events.json"
    if args.events:
        events = json.loads(events_path.read_text(encoding="utf-8"))
    else:
        source = args.otrf_source.resolve()
        relative(source)
        events = normalize(source, args.dataset_id, {1, 10, 11})
        save(events_path, events)
    validate_contract(events, events_path)

    selected = [row for row in candidates["items"] if row["logsource"]["product"] == "windows"
                and row["logsource"]["service"] in (None, "sysmon")]
    if args.max_rules is not None:
        selected = selected[:args.max_rules]
    tests = {"schema_version": "1.0", "kind": "rule_tests", "case_id": handoff["case_id"],
             "items": [run_rule(workspace_path(row["rule_path"]), row["candidate_id"], events,
                                row["rule_sha256"]) for row in selected]}
    test_path = output / "rule_tests.json"
    save(test_path, tests)
    validate_links(tests, candidates=candidates, events=events)

    coverage_by_candidate = {row["candidate_id"]: row for row in coverage["items"]}
    tests_by_candidate = {row["candidate_id"]: row for row in tests["items"]}
    result = {"schema_version": "1.0", "kind": "case_result", "case_id": handoff["case_id"],
              "behavior_ids": [row["behavior_id"] for row in handoff["behaviors"]],
              "coverage_ids": [row["coverage_id"] for row in coverage["items"]],
              "rule_test_candidate_ids": [row["candidate_id"] for row in tests["items"]],
              "input_paths": {"handoff": relative(handoff_path), "candidates": relative(candidate_path),
                              "coverage": relative(coverage_path), "events": relative(events_path),
                              "rule_tests": relative(test_path)},
              "items": [{"candidate_id": row["candidate_id"], "behavior_id": row["behavior_id"],
                         "technique_id": row["technique_id"], "rule_id": row["rule_id"],
                         "coverage_id": coverage_by_candidate.get(row["candidate_id"], {}).get("coverage_id"),
                         "procedure_decision": coverage_by_candidate.get(row["candidate_id"], {}).get("decision"),
                         "procedure_review_status": coverage_by_candidate.get(row["candidate_id"], {}).get("review_status"),
                         "dataset_id": events["dataset_id"],
                         "sample_test_status": tests_by_candidate.get(row["candidate_id"], {}).get("status"),
                         "matched_event_uids": tests_by_candidate.get(row["candidate_id"], {}).get("matched_event_uids")}
                        for row in candidates["items"]],
              "limitations": ["Sigma candidate retrieval does not establish procedure coverage.",
                              "OTRF sample events are independent of the CISA report; a hit is not detection of the reported incident.",
                              "Agent proposals and coverage judgments require human review before being treated as confirmed."]}
    save(output / "case_result.json", result)
    validate_links(result, handoff=handoff, candidates=candidates, events=events)
    print(f"{handoff['case_id']}: {len(handoff['behaviors'])} behaviors, {len(candidates['items'])} candidates, "
          f"{len(coverage['items'])} procedure judgments, {len(tests['items'])} rule tests -> {output}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--handoff", type=Path, help="Existing v1.0 case_handoff, including reviewed gold")
    source.add_argument("--report", type=Path, help="Answer-hidden report text for A-stage analysis")
    parser.add_argument("--prediction", type=Path, help="Use existing agent_poc output instead of calling Ollama")
    parser.add_argument("--case-id")
    parser.add_argument("--title")
    parser.add_argument("--source-url")
    parser.add_argument("--catalog", type=Path, default=ROOT / "data/attack/enterprise-attack-20.0.json")
    parser.add_argument("--catalog-version", default="Enterprise 20.0")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--events", type=Path, help="Existing normalized_events JSON; otherwise normalize OTRF")
    parser.add_argument("--otrf-source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--dataset-id", default="OTRF-LSASS_campaign_06")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--max-coverage", type=int)
    parser.add_argument("--max-rules", type=int)
    parser.add_argument("--skip-coverage", action="store_true", help="Offline smoke test without Ollama; output records unknown coverage")
    parser.add_argument("--agent-coverage", action="store_true", help="Use bounded tool Agent for Sigma procedure judgments")
    parser.add_argument("--agent-max-steps", type=int, default=5)
    parser.add_argument("--model", default="qwen3:4b")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434/api/chat")
    execute(parser.parse_args())


if __name__ == "__main__":
    main()
