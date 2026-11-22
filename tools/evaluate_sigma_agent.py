"""Compare Agent procedure judgments with human-reviewed candidate-level gold rows."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def evaluate(gold: dict, predicted: dict, trace_path: Path | None = None) -> dict:
    if gold.get("kind") != "coverage_assessments" or predicted.get("kind") != "coverage_assessments":
        raise ValueError("Both inputs must be coverage_assessments")
    if gold["case_id"] != predicted["case_id"] or gold["ruleset_commit"] != predicted["ruleset_commit"]:
        raise ValueError("Case or Sigma ruleset differs")
    truth = {row["candidate_id"]: row for row in gold["items"] if row["review_status"] == "confirmed"}
    if len(truth) != sum(row["review_status"] == "confirmed" for row in gold["items"]):
        raise ValueError("Duplicate confirmed candidate_id in gold")
    traces = {}
    if trace_path:
        for line in trace_path.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            traces[entry["candidate_id"]] = entry["steps"]
    rows = []
    for row in predicted["items"]:
        expected = truth.get(row["candidate_id"])
        if not expected:
            continue
        steps = traces.get(row["candidate_id"], [])
        rows.append({"candidate_id": row["candidate_id"], "expected": expected["decision"],
                     "predicted": row["decision"], "correct": row["decision"] == expected["decision"],
                     "tool_calls": [step["action"] for step in steps if step["action"] != "finish"],
                     "rejected_proposals": sum(bool(step.get("feedback")) for step in steps),
                     "steps": len(steps), "explanation": row["explanation"]})
    return {"case_id": gold["case_id"], "gold_count": len(truth), "evaluated_count": len(rows),
            "correct_count": sum(row["correct"] for row in rows),
            "accuracy_on_evaluated": sum(row["correct"] for row in rows) / len(rows) if rows else None,
            "items": rows,
            "note": "This small reviewed set is a development check, not a general accuracy estimate."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gold", type=Path)
    parser.add_argument("prediction", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--trace", type=Path)
    args = parser.parse_args()
    result = evaluate(json.loads(args.gold.read_text(encoding="utf-8")),
                      json.loads(args.prediction.read_text(encoding="utf-8")), args.trace)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{result['correct_count']}/{result['evaluated_count']} reviewed decisions correct -> {args.output}")


if __name__ == "__main__":
    main()
