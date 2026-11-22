"""Regression check that the independent retriever can recall reviewed rules."""
import json
from pathlib import Path

import pytest

from src.threat2detect.contracts import validate_contract, validate_links
from src.threat2detect.sigma.retrieval import index_rules, retrieve


ROOT = Path(__file__).resolve().parents[1]


def test_retrieval_recalls_reviewed_candidates(monkeypatch):
    rules_root = ROOT / "data" / "sigma"
    if not (rules_root / "rules").exists():
        pytest.skip("Sigma submodule not initialized")
    handoff = json.loads((ROOT / "data" / "annotations" / "aa25_266a_gold_draft.json").read_text(encoding="utf-8"))
    reviewed = json.loads((ROOT / "data" / "annotations" / "aa25_266a_rule_candidates.json").read_text(encoding="utf-8"))
    index, warnings = index_rules(rules_root)
    monkeypatch.setattr("src.threat2detect.sigma.retrieval.index_rules", lambda _root: (index, warnings))
    result = retrieve(handoff, rules_root, limit=10)
    validate_contract(result, ROOT / "unused.json")
    validate_links(result, handoff=handoff)
    assert result["ruleset_commit"] == reviewed["ruleset_commit"]
    found = {(row["behavior_id"], row["rule_id"]) for row in result["items"]}
    expected = {(row["behavior_id"], row["rule_id"]) for row in reviewed["items"]}
    assert expected <= found


def test_retrieval_ranks_reviewed_rules_and_excludes_wrong_platform(monkeypatch):
    rules_root = ROOT / "data" / "sigma"
    if not (rules_root / "rules").exists():
        pytest.skip("Sigma submodule not initialized")
    handoff = json.loads((ROOT / "data" / "annotations" / "aa25_266a_gold_draft.json").read_text(encoding="utf-8"))
    reviewed = json.loads((ROOT / "data" / "annotations" / "aa25_266a_rule_candidates.json").read_text(encoding="utf-8"))
    index, warnings = index_rules(rules_root)
    monkeypatch.setattr("src.threat2detect.sigma.retrieval.index_rules", lambda _root: (index, warnings))
    result = retrieve(handoff, rules_root, limit=10)

    expected = {(row["behavior_id"], row["rule_id"]) for row in reviewed["items"]}
    ranked = {
        (row["behavior_id"], row["rule_id"]): row["rank"]
        for row in result["items"]
    }
    assert expected <= set(ranked)
    assert sum(rank <= 5 for rank in (ranked[pair] for pair in expected)) >= 3
    assert ranked[("AA25-266A-G001", "502b42de-4306-40b4-9596-6f590c81f073")] == 1
    assert ranked[("AA25-266A-G001", "8de1cbe8-d6f5-496d-8237-5f44a721c7a0")] <= 5
    assert ranked[("AA25-266A-G001", "c248c896-e412-4279-8c15-1c558067b6fa")] > 5

    for row in result["items"]:
        if row["behavior_id"] in {"AA25-266A-G001", "AA25-266A-G002", "AA25-266A-G003"}:
            assert row["logsource"]["product"] == "windows"
        assert row["candidate_id"].endswith(row["rule_id"].split("-", 1)[0])
