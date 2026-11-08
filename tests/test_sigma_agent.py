import json
from pathlib import Path

from sigma_agent import analyze_candidate, unresolved_filter_fields
from sigma_coverage import prepare


ROOT = Path(__file__).resolve().parents[1]


def reviewed_parent_filter_item():
    handoff = json.loads((ROOT / "data/annotations/aa25_266a_gold_draft.json").read_text(encoding="utf-8"))
    candidates = json.loads((ROOT / "data/annotations/aa25_266a_rule_candidates.json").read_text(encoding="utf-8"))
    return next(item for item in prepare(handoff, candidates) if item["candidate"]["candidate_id"] == "AA25-266A-R003")


def test_unknown_parent_filter_feedback_causes_revision(monkeypatch):
    item = reviewed_parent_filter_item()
    assert unresolved_filter_fields(item) == ["ParentImage"]
    calls = iter([
        {"action": "inspect_rule", "reason": "Need YAML", "decision": "none",
         "supporting_conditions": [], "missing_conditions": [], "unknown_conditions": [], "explanation": ""},
        {"action": "finish", "reason": "Initial guess", "decision": "matches_procedure",
         "supporting_conditions": ["whoami selector"], "missing_conditions": [],
         "unknown_conditions": [], "explanation": "whoami matches"},
        {"action": "finish", "reason": "Corrected after feedback", "decision": "insufficient_detail",
         "supporting_conditions": ["whoami selector"], "missing_conditions": [],
         "unknown_conditions": ["ParentImage not reported"], "explanation": "Parent filter cannot be resolved"},
    ])

    def fake_model(_model, _system, _payload, _endpoint, schema):
        result = next(calls)
        assert result["action"] in schema["properties"]["action"]["enum"]
        if result["action"] == "finish":
            assert "inspect_rule" not in schema["properties"]["action"]["enum"]
        return result

    monkeypatch.setattr("sigma_agent.ollama_json", fake_model)
    proposal, trace = analyze_candidate(item, "fake", "local", 5)
    assert proposal["decision"] == "insufficient_detail"
    assert len(trace) == 3
    assert "ParentImage" in trace[1]["feedback"][0]
    assert trace[2]["accepted"] is True


def test_agent_stops_with_unknown_after_step_limit(monkeypatch):
    item = reviewed_parent_filter_item()
    calls = iter([
        {"action": "inspect_rule", "reason": "read", "decision": "none",
         "supporting_conditions": [], "missing_conditions": [], "unknown_conditions": [], "explanation": ""},
        {"action": "finish", "reason": "wrong", "decision": "matches_procedure",
         "supporting_conditions": ["whoami"], "missing_conditions": [],
         "unknown_conditions": [], "explanation": "Matches"},
    ])
    monkeypatch.setattr("sigma_agent.ollama_json", lambda *_args: next(calls))
    proposal, trace = analyze_candidate(item, "fake", "local", 2)
    assert proposal["decision"] == "insufficient_detail"
    assert proposal["agent_stop_reason"] == "step_limit"
    assert len(trace) == 2
