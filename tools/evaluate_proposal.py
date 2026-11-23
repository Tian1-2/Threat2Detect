#!/usr/bin/env python3
"""Score saved Threat2Detect runs against the proposal's evaluation table."""

import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import re

DECISIONS = (
    "matches_procedure", "partially_matches", "does_not_match", "insufficient_detail",
)
BASELINE = "artifacts/runs/"
ANNOTATIONS = "data/annotations/"
DATASET = "OTRF-LSASS_campaign_06"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def catalog_ids(path):
    return {
        ref["external_id"]
        for item in read_json(path)["objects"]
        if item["type"] == "attack-pattern" and not item.get("revoked")
        and not item.get("x_mitre_deprecated")
        for ref in item.get("external_references", [])
        if ref["source_name"] == "mitre-attack" and "external_id" in ref
    }


def evidence(row):
    if "evidence" in row:
        source = row["evidence"]
        return source["char_start"], source["char_end"], source["quote"]
    quote = row["quote"]
    start = row["location"]["char_start"]
    return start, start + len(quote), quote


def mappings(document):
    by_behavior = defaultdict(set)
    rows = document.get("mappings")
    if rows is None:
        rows = [
            dict(row.get("mapping") or {}, behavior_id=row["behavior_id"])
            for row in document["behaviors"]
        ]
    for row in rows:
        if row.get("technique_id"):
            by_behavior[row["behavior_id"]].add(row["technique_id"])
    return by_behavior


def evaluate_behaviors(prediction, gold, source, valid_ids, alignment):
    if prediction.get("case_id", prediction.get("report_id")) != gold["case_id"]:
        raise ValueError("Behavior prediction and reference must describe the same case")
    reference_hash = gold["report"].get("input_sha256")
    source = source.replace("\r\n", "\n")
    source_hashes = {
        sha256(text.encode()).hexdigest() for text in (source, source.replace("\n", "\r\n"))
    }
    if reference_hash and reference_hash not in source_hashes:
        raise ValueError("Report text differs from the reference's pinned input")
    predicted = {row["behavior_id"]: row for row in prediction["behaviors"]}
    confirmed = {
        row["behavior_id"]: row for row in gold["behaviors"]
        if row.get("review_status") == "confirmed"
    }
    if not set(alignment) <= confirmed.keys() or not set(alignment.values()) <= predicted.keys():
        raise ValueError("Manual alignment must map confirmed reference IDs to prediction IDs")
    if len(set(alignment.values())) != len(alignment):
        raise ValueError("Manual alignment must be one-to-one")
    invalid_quotes = [
        key for key, row in predicted.items()
        if not (0 <= (span := evidence(row))[0] < span[1] <= len(source)
                and source[span[0]:span[1]] == span[2])
    ]
    reference_ids = mappings({
        "mappings": [row for row in gold["mappings"] if row["review_status"] == "confirmed"]
    })
    pred_ids = mappings(prediction)
    used = set(alignment.values())
    rows = []
    for key, row in confirmed.items():
        start, end, quote = evidence(row)
        if source[start:end] != quote:
            raise ValueError(f"Reference quote does not match the pinned source for {key}")
        overlaps = {
            pred_id: evidence(pred_row) for pred_id, pred_row in predicted.items()
            if pred_id not in invalid_quotes
            and start < evidence(pred_row)[1] and evidence(pred_row)[0] < end
        }
        exact = [pred_id for pred_id, span in overlaps.items()
                 if span == (start, end, quote) and pred_id not in used]
        pred_id = alignment.get(key)
        outcome = "human_aligned"
        if pred_id is None:
            pred_id = exact[0] if len(exact) == 1 else None
            outcome = "exact_evidence_anchor" if pred_id else (
                "overlap_requires_review" if overlaps else "no_evidence_overlap"
            )
        expected, actual = reference_ids[key], pred_ids[pred_id]
        if pred_id:
            used.add(pred_id)
        rows.append({
            "reference_id": key, "prediction_id": pred_id, "alignment": outcome,
            "overlap_prediction_ids": sorted(overlaps), "expected_technique_ids": sorted(expected),
            "actual_technique_ids": sorted(actual) if pred_id else None,
            "matched_ids": sorted(expected & actual) if pred_id else None,
            "missing_ids": sorted(expected - actual) if pred_id and expected else None,
            "extra_ids_for_review": sorted(actual - expected) if pred_id and expected else None,
        })
    invalid_ids = None if valid_ids is None else [
        {"behavior_id": key, "technique_id": tid}
        for key, ids in sorted(pred_ids.items()) for tid in sorted(ids - valid_ids)
    ]
    return {
        "case_id": gold["case_id"], "predicted_behaviors": len(predicted),
        "predicted_mappings": sum(map(len, pred_ids.values())),
        "confirmed_reference_behaviors": len(confirmed),
        "invalid_quote_ids": invalid_quotes, "invalid_catalog_ids": invalid_ids,
        "aligned_mapping_id_counts": {
            "matched": sum(len(row["matched_ids"] or []) for row in rows),
            "missing": sum(len(row["missing_ids"] or []) for row in rows),
            "extra_for_review": sum(len(row["extra_ids_for_review"] or []) for row in rows),
        },
        "alignment_counts": dict(Counter(row["alignment"] for row in rows)),
        "unpaired_prediction_count": len(predicted) - len(used),
        "behavior_precision_recall": None,
        "notes": "Partial reference. Exact evidence anchors are provisional; "
                 "semantic disagreements and mapping rationales require human review.",
        "items": rows,
    }


def rule_key(row):
    return row["behavior_id"], row["technique_id"], row["rule_id"]


def by_id(document):
    return {row["candidate_id"]: row for row in document["items"]}


def check_ruleset(*documents):
    if len({document["ruleset_commit"] for document in documents}) != 1:
        raise ValueError("Rule evaluations require the same pinned Sigma ruleset")
    if len({document["case_id"] for document in documents}) != 1:
        raise ValueError("Rule evaluations require the same case")


def evaluate_rules(reference_candidates, retrieval, gold, coverage, coverage_candidates):
    check_ruleset(reference_candidates, retrieval, gold, coverage, coverage_candidates)
    refs = by_id(reference_candidates)
    ranked = defaultdict(list)
    for row in retrieval["items"]:
        behavior_id, technique_id, rule_id = rule_key(row)
        rules = ranked[behavior_id, technique_id]
        if rule_id not in rules:
            rules.append(rule_id)
    coverage_index = by_id(coverage_candidates)
    actual = {
        rule_key(coverage_index[row["candidate_id"]]): row for row in coverage["items"]
    }
    items = []
    matrix = {state: dict.fromkeys((*DECISIONS, "unassessed"), 0) for state in DECISIONS}
    for row in gold["items"]:
        if row["review_status"] != "confirmed":
            continue
        key = rule_key(refs[row["candidate_id"]])
        rules = ranked[key[:2]]
        rank = rules.index(key[2]) + 1 if key[2] in rules else None
        prediction = actual.get(key)
        observed = prediction["decision"] if prediction else None
        expected = row["decision"]
        matrix[expected][observed or "unassessed"] += 1
        items.append({
            "reference_candidate_id": row["candidate_id"], "behavior_id": key[0],
            "technique_id": key[1], "rule_id": key[2], "rank": rank,
            "expected": expected, "observed": observed,
            "agreement": expected == observed if observed else None,
            "expected_explanation": row.get("explanation"),
            "observed_explanation": prediction.get("explanation") if prediction else None,
        })
    return {
        "reference_scope": "reviewed examples; retrieval reference list is incomplete",
        "retrieved_candidate_count": len(retrieval["items"]),
        "reference_pairs": len(items),
        "sample_hits_at_5": sum(1 for row in items if row["rank"] and row["rank"] <= 5),
        "sample_hits_at_10": sum(1 for row in items if row["rank"] and row["rank"] <= 10),
        "coverage_assessed": sum(row["observed"] is not None for row in items),
        "coverage_agreements": sum(row["agreement"] is True for row in items),
        "coverage_matrix": matrix, "items": items,
    }


def evaluate_execution(tests, review_text):
    expected = re.findall(
        r"^\| (E\d+) \| (L\d+)[^|]*\| \[[^\]]+\]\(\.\./sigma/([^\)]+)\)"
        r" \| `(match|miss)`", review_text, re.MULTILINE,
    )
    if not expected:
        raise ValueError("No event references found in the reviewed OTRF table")
    tests_by_path = {row["rule_path"]: row for row in tests["items"] if row["dataset_id"] == DATASET}
    pairs = []
    for sample, line, path, label in expected:
        row = tests_by_path.get("data/sigma/" + path)
        uid = f"{DATASET}:{line}"
        expected_status = "hit" if label == "match" else "miss"
        if not row:
            observed = "not_tested"
        elif uid in row["matched_event_uids"]:
            observed = "hit"
        elif row["status"] in ("hit", "miss") and row["events_skipped"] == 0:
            observed = "miss"
        elif row["status"] in ("hit", "miss"):
            observed = "not_listed_as_hit"
        else:
            observed = row["status"]
        pairs.append({
            "sample_id": sample, "event_uid": uid, "rule_path": path,
            "expected": expected_status, "observed": observed,
            "agreement": expected_status == observed
            if observed in ("hit", "miss") else None,
            "agreement_if_reviewed_event_was_evaluated": expected_status == "miss"
            if observed == "not_listed_as_hit" else None,
        })
    return {
        "reference_pairs": len(pairs),
        "confirmed_agreements": sum(row["agreement"] is True for row in pairs),
        "rule_status_counts": dict(Counter(row["status"] for row in tests["items"])),
        "rules": [{
            "candidate_id": row["candidate_id"], "dataset_id": row["dataset_id"],
            "status": row["status"], "hits": len(row["matched_event_uids"]),
            "evaluated_non_hits": row["events_evaluated"] - len(row["matched_event_uids"]),
            "skipped": row["events_skipped"], "matched_event_uids": row["matched_event_uids"],
            "engine_version": row["engine_version"],
        } for row in tests["items"]],
        "notes": "Aggregate artifacts omit per-event skip IDs. With skipped events, "
                 "absence from the hit list alone does not establish an evaluated miss.",
        "reviewed_event_comparisons": pairs,
    }


def evaluate_agent(run, generated):
    result, trace = run["result"], run["trace"]
    selected = {row.get("behavior_id") for row in run["candidates"]["items"]}
    generation_results = []
    for document in generated:
        generation_results.append({
            "candidate_sha256": document.get("candidate_yaml_sha256"),
            "parse_status": document["parse_status"],
            "validation_outcome": document["validation_outcome"],
            "target": dict(Counter(row["status"] for row in document["positive_tests"])),
            "control": dict(Counter(row["status"] for row in document["negative_tests"])),
            "targets_hit": sum(row["status"] == "hit" for row in document["positive_tests"]),
            "controls_missed": sum(row["status"] == "miss" for row in document["negative_tests"]),
        })
    return {
        "workflow_status": result["workflow_status"], "steps": len(trace),
        "model_calls": result["model_calls_used"], "behaviors_with_retrieved_candidates": sorted(selected),
        "retrieved_candidate_count": len(run["candidates"]["items"]),
        "pending_behavior_ids": result["pending_behavior_ids"],
        "unselected_behavior_ids": result["unselected_behavior_ids"],
        "review_queue": result["review_queue"],
        "tool_sequence": [step.get("action", {}).get("tool") for step in trace],
        "decisions_outside_offered_actions": [
            step["step"] for step in trace
            if step.get("decision", {}).get("action_id")
            and step["decision"]["action_id"] not in step.get("available_action_ids", [])
        ],
        "generated_rules": result["generated_rules"],
        "generation_validation": generation_results,
        "validation_outcome_counts": dict(Counter(row["validation_outcome"] for row in generation_results)),
        "generation_validation_status": "scored" if generated else "no_generation_artifacts_supplied",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", help="Source repository revision, if known")
    parser.add_argument("--prediction", type=Path)
    parser.add_argument("--behavior-reference", type=Path)
    parser.add_argument("--additional-behavior-reference", type=Path)
    parser.add_argument("--report-text", type=Path)
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--alignment", type=Path, help="JSON object matching gold IDs to prediction IDs")
    parser.add_argument("--retrieval", type=Path)
    parser.add_argument("--coverage", type=Path)
    parser.add_argument("--coverage-candidates", type=Path)
    parser.add_argument("--rule-tests", type=Path)
    parser.add_argument("--run-dir", type=Path, help="Case Agent output directory instead of the demo fixture")
    parser.add_argument("--generated-result", type=Path, action="append", default=[])
    parser.add_argument("--compare-previous", type=Path, help="Compare with an independently produced evaluation JSON")
    args = parser.parse_args()
    hashes = {}

    def source(path):
        data = path.read_bytes()
        hashes[str(path)] = sha256(data).hexdigest()
        return data.decode("utf-8")

    def load(path, default=None):
        return json.loads(source(path or args.repo / default))

    catalog = args.catalog or args.repo / "data/attack/enterprise-attack-20.0.json"
    if args.catalog and not catalog.is_file():
        parser.error(f"ATT&CK catalog not found: {catalog}")
    ids = None
    if catalog.is_file():
        source(catalog)
        ids = catalog_ids(catalog)

    if args.run_dir:
        run = {
            key: load(args.run_dir / filename)
            for key, filename in (
                ("result", "case_result.json"), ("candidates", "candidates.json"),
            )
        }
        run["trace"] = [json.loads(line) for line in source(args.run_dir / "trace.jsonl").splitlines()
                        if line.strip()]
    else:
        run = load(None, "docs/design/frontend-example-data.json")["runs"][0]

    prediction = load(args.prediction, BASELINE + "cisa-aa25-266a-prediction-v2.json")
    text = source(args.report_text or args.repo / "data/reports/cisa-aa25-266a-input.txt")
    result = {
        "behavior_and_attack": evaluate_behaviors(
            prediction, load(args.behavior_reference, ANNOTATIONS + "aa25_266a_gold_draft.json"),
            text, ids, load(args.alignment) if args.alignment else {},
        ),
        "retrieval_and_coverage": evaluate_rules(
            load(None, ANNOTATIONS + "aa25_266a_rule_candidates.json"),
            load(args.retrieval, BASELINE + "aa25_266a_rule_candidates_poc.json"),
            load(None, ANNOTATIONS + "coverage_gold_template.json"),
            load(args.coverage, BASELINE + "aa25_266a_coverage_poc_v2.json"),
            load(args.coverage_candidates, ANNOTATIONS + "aa25_266a_rule_candidates.json"),
        ),
        "rule_execution": evaluate_execution(
            load(args.rule_tests, BASELINE + "otrf_lsass_rule_tests.json"),
            source(args.repo / (ANNOTATIONS + "otrf_lsass_event_judgement_reviewed.md")),
        ),
        "candidate_generation_and_agent": evaluate_agent(
            run, [load(path) for path in args.generated_result],
        ),
        "input_sha256": hashes,
        "source_revision": args.revision,
    }
    if args.additional_behavior_reference:
        result["additional_behavior_reference"] = evaluate_behaviors(
            prediction, load(args.additional_behavior_reference), text, ids, {},
        )
    result["reproducibility"] = {
        "clean_checkout_pipeline_rerun": "not_performed_by_evaluator",
        "contract_and_test_pass_rate": None,
        "metric_sections_equal_to_previous": None,
        "input_digests_equal_to_previous": None,
    }
    if args.compare_previous:
        old = read_json(args.compare_previous)
        result["reproducibility"]["input_digests_equal_to_previous"] = (
            sorted(hashes.values()) == sorted(old.get("input_sha256", {}).values())
        )
        result["reproducibility"]["metric_sections_equal_to_previous"] = {
            key: result.get(key) == old.get(key)
            for key in result if key not in ("input_sha256", "reproducibility", "source_revision")
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
