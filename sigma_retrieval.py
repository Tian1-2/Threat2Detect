"""Deterministic Sigma candidate retrieval for a case_handoff file.

Run from the project root. Retrieval is not a coverage judgment or rule execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent
DEFAULT_RULES = ROOT / "data" / "sigma"
TOKEN = re.compile(r"[a-z0-9]{3,}")
FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\|.*)?$")
STOP = {"the", "and", "for", "from", "with", "into", "current", "server", "system", "process", "traffic", "network", "config", "configuration", "command", "discovery", "identify", "inspect", "list", "proxy"}


def tokens(value: str) -> set[str]:
    return {word for word in TOKEN.findall(value.lower()) if word not in STOP}


def scalar_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(scalar_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(f"{key} {scalar_text(item)}" for key, item in value.items())
    return "" if value is None else str(value)


def referenced_fields(detection: dict) -> list[str]:
    fields: set[str] = set()

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key != "condition" and FIELD.fullmatch(str(key)) and ("|" in key or key[0].isupper()):
                    fields.add(key.split("|", 1)[0])
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(detection)
    return sorted(fields)


def ruleset_commit(rules_root: Path) -> str:
    result = subprocess.run(["git", "-C", str(rules_root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    commit = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Sigma checkout has no valid commit SHA")
    return commit


def index_rules(rules_root: Path) -> tuple[dict[str, list[dict]], list[str]]:
    index: dict[str, list[dict]] = {}
    warnings: list[str] = []
    for path in sorted((rules_root / "rules").rglob("*.yml")):
        try:
            raw = path.read_bytes()
            rule = yaml.safe_load(raw)
        except (OSError, yaml.YAMLError) as exc:
            warnings.append(f"{path.relative_to(rules_root)}: {exc}")
            continue
        if not isinstance(rule, dict) or not rule.get("id") or not isinstance(rule.get("detection"), dict):
            continue
        tags = [str(tag).lower() for tag in (rule.get("tags") or [])]
        item = {
            "rule_id": str(rule["id"]), "rule_path": path.relative_to(ROOT).as_posix(),
            "rule_sha256": hashlib.sha256(raw).hexdigest(), "title": str(rule.get("title", "")),
            "description": str(rule.get("description", "")), "tags": tags,
            "logsource": rule.get("logsource") or {}, "status": rule.get("status"),
            "required_fields": referenced_fields(rule["detection"]),
            "detection_text": scalar_text(rule["detection"]),
        }
        for tag in tags:
            if tag.startswith("attack.t"):
                index.setdefault(tag[7:].upper(), []).append(item)
    return index, warnings


def score_rule(behavior: dict, rule: dict) -> tuple[int, list[str]]:
    evidence = behavior.get("evidence") or {}
    query = tokens(" ".join(str(value) for value in (evidence.get("quote"), behavior.get("action"), behavior.get("object")) if value))
    title_hits = query & tokens(rule["title"])
    condition_hits = query & tokens(rule["detection_text"])
    description_hits = query & tokens(rule["description"])
    score = 5 * len(title_hits) + 3 * len(condition_hits) + len(description_hits)
    reasons = ["exact ATT&CK technique tag"]
    if condition_hits:
        reasons.append("detection terms: " + ", ".join(sorted(condition_hits)))
    if title_hits:
        reasons.append("title terms: " + ", ".join(sorted(title_hits)))
    return score, reasons


def retrieve(handoff: dict, rules_root: Path, limit: int) -> dict:
    if handoff.get("kind") != "case_handoff":
        raise ValueError("Expected kind=case_handoff")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    commit = ruleset_commit(rules_root)
    index, warnings = index_rules(rules_root)
    behaviors = {item["behavior_id"]: item for item in handoff["behaviors"] if item["review_status"] == "confirmed"}
    items = []
    for mapping in handoff["mappings"]:
        behavior = behaviors.get(mapping["behavior_id"])
        if not behavior or mapping["review_status"] != "confirmed":
            continue
        technique_id = mapping["technique_id"]
        ranked = sorted(((*score_rule(behavior, rule), rule) for rule in index.get(technique_id, [])),
                        key=lambda row: (-row[0], row[2]["rule_path"]))
        for rank, (score, reasons, rule) in enumerate(ranked[:limit], 1):
            source = rule["logsource"]
            items.append({
                "candidate_id": f"{mapping['mapping_id']}-R{rank:03d}",
                "behavior_id": behavior["behavior_id"], "technique_id": technique_id,
                "rule_id": rule["rule_id"], "rule_path": rule["rule_path"],
                "rule_sha256": rule["rule_sha256"], "title": rule["title"],
                "tags": rule["tags"],
                "logsource": {"product": source.get("product") or "unknown", "category": source.get("category"), "service": source.get("service")},
                "status": rule["status"], "required_fields": rule["required_fields"],
                "retrieval_reason": "; ".join(reasons) + f"; lexical score {score}",
            })
    return {"schema_version": "1.0", "kind": "rule_candidates", "case_id": handoff["case_id"],
            "ruleset_commit": commit, "items": items, "retrieval_warnings": warnings,
            "retrieval_note": "Candidates are ranked by tag and text overlap; coverage requires separate YAML condition review."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("handoff", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--limit", type=int, default=10, help="maximum candidates per confirmed mapping")
    args = parser.parse_args()
    handoff = json.loads(args.handoff.read_text(encoding="utf-8"))
    result = retrieve(handoff, args.rules.resolve(), args.limit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{result['case_id']}: {len(result['items'])} candidates, {len(result['retrieval_warnings'])} skipped rules -> {args.output}")


if __name__ == "__main__":
    main()
