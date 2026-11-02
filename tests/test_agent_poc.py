import json
import re
from pathlib import Path

import agent_poc


def test_prepare_removes_inline_ids_and_mapping_table():
    text = "They used whoami [T1033] and BITS [T1 197] and a proxy [5 T1 090].\nMITRE ATT&CK Tactics and Techniques\nT1033 Summary"
    assert agent_poc.prepare_report(text) == "They used whoami and BITS and a proxy."


def test_prepare_keeps_later_timeline():
    text = "Actor narrative.\nMITRE ATT&CK Tactics and Techniques\nT1033 Summary\nMitigations\nDefender advice.\nAppendix: Key Events Timeline\nLater attacker action."
    clean = agent_poc.prepare_report(text)
    assert "T1033 Summary" not in clean
    assert "Appendix: Key Events Timeline" in clean
    assert "Later attacker action." in clean


def test_real_cisa_case_has_no_answer_ids_and_reference_ids_are_valid():
    root = Path(__file__).resolve().parents[1]
    catalog = agent_poc.load_catalog(root / "data" / "attack" / "enterprise-attack-20.0.json")
    for stem in ("cisa-aa25-266a", "cisa-aa23-319a", "cisa-aa24-193a"):
        report = (root / "data" / "reports" / f"{stem}-input.txt").read_text(encoding="utf-8")
        reference = json.loads((root / "data" / "reports" / f"{stem}-reference.json").read_text(encoding="utf-8"))
        assert not agent_poc.INLINE_ID.search(report)
        assert not re.search(r"\bT\d{4}(?:\.\d{3})?\b", report)
        assert set(reference["technique_ids"]) <= set(catalog)
    assert len(json.loads((root / "data" / "reports" / "cisa-aa25-266a-reference.json").read_text())["technique_ids"]) == 22


def test_candidate_search_finds_known_examples():
    root = Path(__file__).resolve().parents[1]
    catalog = agent_poc.load_catalog(root / "data" / "attack" / "enterprise-attack-20.0.json")
    whoami = agent_poc.candidate_ids({"quote": "They used whoami to discover the current user."}, catalog)
    lsass = agent_poc.candidate_ids({"quote": "They dumped LSASS process memory."}, catalog)
    assert "T1033" in whoami
    assert "T1003.001" in lsass


def test_pdf_line_wrap_is_accepted_but_paraphrase_is_not():
    chunk = "The actors used PowerShell\n to download payloads."
    assert agent_poc.resolve_quote(chunk, "used PowerShell to download payloads") == ("used PowerShell\n to download payloads", 11)
    assert agent_poc.resolve_quote(chunk, "used PowerShell to steal payloads") is None


def test_analyze_rejects_fake_quote_and_invalid_id(monkeypatch):
    calls = iter([
        {"behaviors": [
            {"quote": "not present", "observed_or_inferred": "observed"},
            {"quote": "They used whoami.", "action": "used whoami", "object": "current user", "observed_or_inferred": "observed"},
            {"quote": "They ran tasklist.", "action": "ran tasklist", "object": "processes", "observed_or_inferred": "observed"},
        ]},
        {"mappings": [
            {"behavior_id": "sample-001", "technique_id": "T9999", "rationale": "guess", "confidence": "high"},
            {"behavior_id": "sample-002", "technique_id": "T1057", "rationale": "process list", "confidence": "high"},
        ]},
    ])
    monkeypatch.setattr(agent_poc, "ollama_json", lambda *args: next(calls))
    catalog = {"T1033": {"name": "System Owner/User Discovery", "description": "whoami"},
               "T1057": {"name": "Process Discovery", "description": "tasklist"}}
    result = agent_poc.analyze("sample", "They used whoami. They ran tasklist.", catalog, "fake", "unused")
    assert len(result["behaviors"]) == 2
    assert [b["behavior_id"] for b in result["behaviors"]] == ["sample-001", "sample-002"]
    assert result["behaviors"][0]["mapping"]["technique_id"] is None
    assert result["behaviors"][1]["mapping"]["technique_id"] == "T1057"
    assert "T1057" in result["behaviors"][1]["mapping"]["retrieved_candidate_ids"]
    assert len(result["warnings"]) == 2


def test_unlisted_prediction_is_review_item():
    prediction = {"report_id": "sample", "behaviors": [
        {"mapping": {"technique_id": "T1033"}},
        {"mapping": {"technique_id": "T1003.001"}},
    ]}
    reference = {"source": "test", "technique_ids": ["T1033", "T1082"]}
    result = agent_poc.compare(prediction, reference)
    assert result["matched"] == ["T1033"]
    assert result["missed_reference_ids"] == ["T1082"]
    assert result["additional_ids_for_human_review"] == ["T1003.001"]
