import json
from pathlib import Path

import pytest

from pipeline import prediction_to_handoff
from sigma_coverage import guard_decision
from validate_contract import validate_contract


ROOT = Path(__file__).resolve().parents[1]


def test_existing_prediction_converts_to_valid_draft_handoff():
    prediction = json.loads((ROOT / "artifacts/runs/cisa-aa25-266a-prediction-v2.json").read_text(encoding="utf-8"))
    handoff = prediction_to_handoff(
        prediction, ROOT / "data/reports/cisa-aa25-266a-input.txt",
        ROOT / "data/attack/enterprise-attack-20.0.json",
        "AA25-266A", "CISA report", "https://www.cisa.gov", "Enterprise 20.0")
    validate_contract(handoff, ROOT / "artifacts/runs/conversion-check.json")
    assert len(handoff["behaviors"]) == 89
    assert len(handoff["mappings"]) == 63
    assert all(row["review_status"] == "draft" and row["origin"] == "agent_proposal"
               for row in handoff["behaviors"] + handoff["mappings"])


def test_prediction_rejects_stale_report_hash():
    prediction = json.loads((ROOT / "artifacts/runs/cisa-aa25-266a-prediction-v2.json").read_text(encoding="utf-8"))
    prediction["input_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="hash differs"):
        prediction_to_handoff(prediction, ROOT / "data/reports/cisa-aa25-266a-input.txt",
                              ROOT / "data/attack/enterprise-attack-20.0.json",
                              "AA25-266A", "CISA report", "https://www.cisa.gov", "Enterprise 20.0")


def test_complete_match_with_unknown_condition_is_downgraded():
    proposal = {"decision": "matches_procedure", "missing_conditions": [],
                "unknown_conditions": ["User not specified"]}
    guarded = guard_decision(proposal)
    assert guarded["decision"] == "insufficient_detail"
    assert guarded["model_decision"] == "matches_procedure"
    assert proposal["decision"] == "matches_procedure"
