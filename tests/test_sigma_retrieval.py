"""Regression check that the independent retriever can recall reviewed rules."""
import json
from pathlib import Path

import pytest

from sigma_retrieval import index_rules, retrieve
from validate_contract import validate_contract, validate_links


ROOT = Path(__file__).resolve().parents[1]


def test_retrieval_recalls_reviewed_candidates(monkeypatch):
    rules_root = ROOT / "data" / "sigma"
    if not (rules_root / "rules").exists():
        pytest.skip("Sigma submodule not initialized")
    handoff = json.loads((ROOT / "data" / "annotations" / "aa25_266a_gold_draft.json").read_text(encoding="utf-8"))
    reviewed = json.loads((ROOT / "data" / "annotations" / "aa25_266a_rule_candidates.json").read_text(encoding="utf-8"))
    index, warnings = index_rules(rules_root)
    monkeypatch.setattr("sigma_retrieval.index_rules", lambda _root: (index, warnings))
    result = retrieve(handoff, rules_root, limit=10)
    validate_contract(result, ROOT / "unused.json")
    validate_links(result, handoff=handoff)
    assert result["ruleset_commit"] == reviewed["ruleset_commit"]
    found = {(row["behavior_id"], row["rule_id"]) for row in result["items"]}
    expected = {(row["behavior_id"], row["rule_id"]) for row in reviewed["items"]}
    assert expected <= found
