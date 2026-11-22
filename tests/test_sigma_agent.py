import json
from pathlib import Path

from sigma_agent import absent_required_flags, analyze_candidate, feedback_for_finish, unresolved_filter_fields
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


def test_explicit_whoami_lacks_mandatory_all_flag():
    handoff = json.loads((ROOT / "data/annotations/aa25_266a_gold_draft.json").read_text(encoding="utf-8"))
    candidates = json.loads((ROOT / "data/annotations/aa25_266a_rule_candidates.json").read_text(encoding="utf-8"))
    item = next(row for row in prepare(handoff, candidates) if row["candidate"]["candidate_id"] == "AA25-266A-R002")
    assert absent_required_flags(item) == ["all"]
    proposal = {"decision": "partially_matches", "explanation": "Maybe /all was omitted",
                "missing_conditions": ["/all"], "unknown_conditions": [], "supporting_conditions": ["whoami"]}
    assert any("does_not_match" in issue for issue in feedback_for_finish(proposal, True, item))


def test_missing_flag_feedback_revises_partial_match(monkeypatch):
    handoff = json.loads((ROOT / "data/annotations/aa25_266a_gold_draft.json").read_text(encoding="utf-8"))
    candidates = json.loads((ROOT / "data/annotations/aa25_266a_rule_candidates.json").read_text(encoding="utf-8"))
    item = next(row for row in prepare(handoff, candidates) if row["candidate"]["candidate_id"] == "AA25-266A-R002")
    calls = iter([
        {"action": "inspect_rule", "reason": "read", "decision": "none",
         "supporting_conditions": [], "missing_conditions": [], "unknown_conditions": [], "explanation": ""},
        {"action": "finish", "reason": "guess omitted args", "decision": "partially_matches",
         "supporting_conditions": ["whoami"], "missing_conditions": ["/all"],
         "unknown_conditions": [], "explanation": "Maybe /all was omitted"},
        {"action": "finish", "reason": "use quoted procedure", "decision": "does_not_match",
         "supporting_conditions": ["whoami"], "missing_conditions": ["/all"],
         "unknown_conditions": [], "explanation": "The reported command lacks the mandatory /all argument"},
    ])
    monkeypatch.setattr("sigma_agent.ollama_json", lambda *_args: next(calls))
    proposal, trace = analyze_candidate(item, "fake", "local", 5)
    assert proposal["decision"] == "does_not_match"
    assert "does_not_match" in trace[1]["feedback"][0]
    assert trace[2]["accepted"] is True


def test_explanation_guard_separates_procedure_fit_from_log_hit():
    proposal = {"decision": "matches_procedure", "explanation": "The rule is triggered.",
                "supporting_conditions": ["ipconfig /all"], "missing_conditions": [], "unknown_conditions": []}
    assert any("No event log" in issue for issue in feedback_for_finish(proposal, True))
    proposal["decision"] = "insufficient_detail"
    proposal["explanation"] = "The rule does not apply because ParentImage is unknown."
    assert any("cannot resolve" in issue for issue in feedback_for_finish(proposal, True))
