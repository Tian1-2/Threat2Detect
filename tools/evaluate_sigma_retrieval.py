"""Compare Sigma retrieval outputs against reviewed behavior-rule pairs."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.threat2detect.sigma.retrieval import behavior_context, platform_compatible, ruleset_commit


def _ordered_ranks(result: dict) -> dict[tuple[str, str], int]:
    positions: dict[str, int] = {}
    ranks = {}
    for row in result["items"]:
        positions[row["behavior_id"]] = positions.get(row["behavior_id"], 0) + 1
        ranks[(row["behavior_id"], row["rule_id"])] = int(row.get("rank") or positions[row["behavior_id"]])
    return ranks


def _metrics(result: dict, handoff: dict, reviewed: dict) -> dict:
    expected = {(row["behavior_id"], row["rule_id"]) for row in reviewed["items"]}
    ranks = _ordered_ranks(result)
    expected_ranks = [ranks.get(pair, 10**6) for pair in sorted(expected)]
    behaviors = {row["behavior_id"]: row for row in handoff["behaviors"]}
    wrong_platform = []
    for row in result["items"]:
        behavior = behaviors.get(row["behavior_id"])
        if not behavior:
            continue
        platforms, _ = behavior_context(behavior)
        if not platform_compatible({"logsource": row["logsource"]}, platforms):
            wrong_platform.append({
                "behavior_id": row["behavior_id"],
                "rule_id": row["rule_id"],
                "product": row["logsource"]["product"],
                "inferred_platforms": sorted(platforms),
            })
    stable_ids = sum(
        row["candidate_id"].endswith(row["rule_id"].split("-", 1)[0])
        for row in result["items"]
    )
    return {
        "candidate_count": len(result["items"]),
        "labelled_rule_count": len(expected),
        "ranks": {f"{behavior_id}|{rule_id}": rank for (behavior_id, rule_id), rank in ranks.items() if (behavior_id, rule_id) in expected},
        "recall_at": {
            str(k): round(sum(rank <= k for rank in expected_ranks) / len(expected_ranks), 4)
            for k in (1, 3, 5, 10)
        },
        "mrr": round(sum(1 / rank for rank in expected_ranks) / len(expected_ranks), 4),
        "mean_rank": round(sum(expected_ranks) / len(expected_ranks), 2),
        "wrong_platform_top10": wrong_platform,
        "stable_candidate_ids": stable_ids,
        "candidate_id_stability": round(stable_ids / max(len(result["items"]), 1), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("handoff", type=Path)
    parser.add_argument("reviewed", type=Path)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("optimized", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    handoff = json.loads(args.handoff.read_text(encoding="utf-8"))
    reviewed = json.loads(args.reviewed.read_text(encoding="utf-8"))
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    optimized = json.loads(args.optimized.read_text(encoding="utf-8"))
    if baseline["ruleset_commit"] != optimized["ruleset_commit"]:
        raise ValueError("Baseline and optimized outputs use different Sigma commits")

    baseline_metrics = _metrics(baseline, handoff, reviewed)
    optimized_metrics = _metrics(optimized, handoff, reviewed)
    result = {
        "kind": "sigma_retrieval_comparison",
        "ruleset_commit": ruleset_commit(ROOT / "data" / "sigma"),
        "baseline": baseline_metrics,
        "optimized": optimized_metrics,
        "delta": {
            "recall_at_1": round(optimized_metrics["recall_at"]["1"] - baseline_metrics["recall_at"]["1"], 4),
            "recall_at_3": round(optimized_metrics["recall_at"]["3"] - baseline_metrics["recall_at"]["3"], 4),
            "recall_at_5": round(optimized_metrics["recall_at"]["5"] - baseline_metrics["recall_at"]["5"], 4),
            "recall_at_10": round(optimized_metrics["recall_at"]["10"] - baseline_metrics["recall_at"]["10"], 4),
            "mrr": round(optimized_metrics["mrr"] - baseline_metrics["mrr"], 4),
            "mean_rank": round(baseline_metrics["mean_rank"] - optimized_metrics["mean_rank"], 2),
            "wrong_platform_top10": len(baseline_metrics["wrong_platform_top10"]) - len(optimized_metrics["wrong_platform_top10"]),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["delta"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
