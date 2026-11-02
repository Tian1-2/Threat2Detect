import copy
import json
from pathlib import Path

import pytest

from validate_contract import validate_contract, validate_links


ROOT = Path(__file__).resolve().parents[1]


def fixture(name):
    path = ROOT / "data" / "annotations" / name
    return json.loads(path.read_text(encoding="utf-8")), path


def test_handoff_fixture_and_cross_references():
    data, path = fixture("aa25_266a_gold_draft.json")
    validate_contract(data, path)
    broken = copy.deepcopy(data)
    broken["mappings"][0]["behavior_id"] = "missing-behavior"
    with pytest.raises(ValueError, match="missing behavior_id"):
        validate_contract(broken, path)


def test_quote_must_match_input_offsets():
    data, path = fixture("aa25_266a_gold_draft.json")
    data["behaviors"][0]["evidence"]["char_start"] += 1
    with pytest.raises(ValueError, match="evidence quote"):
        validate_contract(data, path)


def test_mapping_must_use_fixed_catalog_name():
    data, path = fixture("aa25_266a_gold_draft.json")
    data["mappings"][0]["technique_name"] = "Wrong title"
    with pytest.raises(ValueError, match="fixed catalog"):
        validate_contract(data, path)


def test_coverage_template_and_rule_generation_request():
    for name in ("coverage_gold_template.json", "rule_generation_request_example.json"):
        data, path = fixture(name)
        validate_contract(data, path)


def test_hit_requires_event_evidence():
    result = {
        "schema_version": "1.0", "kind": "rule_tests", "case_id": "AA25-266A",
        "items": [{"candidate_id": "c1", "dataset_id": "d1", "status": "hit",
                   "matched_event_uids": [], "events_evaluated": 1, "events_skipped": 0,
                   "unsupported_features": [], "reason": "", "engine_version": "1"}],
    }
    with pytest.raises(ValueError, match="hit requires"):
        validate_contract(result, ROOT / "unused.json")


def test_rule_candidate_must_join_behavior_mapping():
    handoff, _ = fixture("aa25_266a_gold_draft.json")
    candidate = {"kind": "rule_candidates", "case_id": "AA25-266A", "items": [
        {"candidate_id": "c1", "behavior_id": "AA25-266A-G002", "technique_id": "T1016"}
    ]}
    validate_links(candidate, handoff=handoff)
    candidate["items"][0]["technique_id"] = "T1033"
    with pytest.raises(ValueError, match="missing behavior-to-technique"):
        validate_links(candidate, handoff=handoff)


def test_coverage_must_reference_same_behavior_as_candidate():
    candidates = {"kind": "rule_candidates", "case_id": "AA25-266A", "items": [
        {"candidate_id": "c1", "behavior_id": "AA25-266A-G002", "technique_id": "T1016"}
    ]}
    coverage = {"kind": "coverage_assessments", "case_id": "AA25-266A", "items": [
        {"coverage_id": "a1", "candidate_id": "c1", "behavior_id": "AA25-266A-G003"}
    ]}
    with pytest.raises(ValueError, match="mismatch"):
        validate_links(coverage, candidates=candidates)
