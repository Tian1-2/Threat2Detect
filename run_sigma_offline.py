"""Run a bounded subset of Sigma YAML conditions over normalized static events.

Unsupported syntax is reported as unsupported_rule, never silently treated as a miss.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
from pathlib import Path

import yaml

from validate_contract import ROOT, validate_contract, validate_links, workspace_path


ENGINE_VERSION = "sigma-offline-subset-0.1"
SUPPORTED = {"contains", "startswith", "endswith", "re", "all", "windash"}
SYSMON_CATEGORY = {1: "process_creation", 10: "process_access", 11: "file_event"}
TOKEN = re.compile(r"\s*(1 of [\w*]+|all of [\w*]+|[()]|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_]*)", re.I)


class UnsupportedRule(ValueError):
    pass


def field_matches(actual, expected, modifiers: list[str]) -> bool:
    if isinstance(expected, list):
        fn = all if "all" in modifiers else any
        return fn(field_matches(actual, item, [m for m in modifiers if m != "all"]) for item in expected)
    if expected is None:
        return actual is None
    if actual is None:
        return False
    actual = str(actual).casefold()
    expected = str(expected).casefold()
    variants = {expected}
    if "windash" in modifiers:
        variants |= {expected.replace(" -", " /"), expected.replace(" /", " -")}
    for pattern in variants:
        if "re" in modifiers:
            try:
                if re.search(pattern, actual, re.IGNORECASE):
                    return True
            except re.error as exc:
                raise UnsupportedRule(f"invalid regex {pattern}: {exc}") from exc
        elif "contains" in modifiers and pattern in actual:
            return True
        elif "startswith" in modifiers and actual.startswith(pattern):
            return True
        elif "endswith" in modifiers and actual.endswith(pattern):
            return True
        elif not any(m in modifiers for m in ("contains", "startswith", "endswith", "re")) and actual == pattern:
            return True
    return False


def selector_matches(selector, fields: dict) -> bool:
    if isinstance(selector, list):
        return any(selector_matches(item, fields) for item in selector)
    if not isinstance(selector, dict):
        raise UnsupportedRule("selector must be a mapping or list")
    for name, expected in selector.items():
        field, *modifiers = name.split("|")
        unknown = set(modifiers) - SUPPORTED
        if unknown:
            raise UnsupportedRule(f"unsupported field modifiers: {sorted(unknown)}")
        actual = fields.get(field)
        if not field_matches(actual, expected, modifiers):
            return False
    return True


def parse_condition(expression: str, selectors: dict, fields: dict) -> bool:
    tokens = []
    position = 0
    while position < len(expression):
        match = TOKEN.match(expression, position)
        if not match:
            if expression[position:].strip():
                raise UnsupportedRule(f"unsupported condition syntax: {expression[position:]}")
            break
        tokens.append(match.group(1))
        position = match.end()
    cursor = 0

    def atom():
        nonlocal cursor
        if cursor >= len(tokens):
            raise UnsupportedRule("incomplete condition")
        word = tokens[cursor]
        cursor += 1
        if word == "(":
            value = disjunction()
            if cursor >= len(tokens) or tokens[cursor] != ")":
                raise UnsupportedRule("unclosed condition parenthesis")
            cursor += 1
            return value
        if word.lower().startswith(("1 of ", "all of ")):
            mode, pattern = word.split(" of ", 1)
            names = [name for name in selectors if fnmatch.fnmatchcase(name, pattern)]
            if not names:
                raise UnsupportedRule(f"condition pattern matched no selectors: {pattern}")
            values = [selector_matches(selectors[name], fields) for name in names]
            return all(values) if mode.lower() == "all" else any(values)
        if word not in selectors:
            raise UnsupportedRule(f"unknown selector: {word}")
        return selector_matches(selectors[word], fields)

    def negation():
        nonlocal cursor
        if cursor < len(tokens) and tokens[cursor].lower() == "not":
            cursor += 1
            return not negation()
        return atom()

    def conjunction():
        nonlocal cursor
        value = negation()
        while cursor < len(tokens) and tokens[cursor].lower() == "and":
            cursor += 1
            other = negation()
            value = value and other
        return value

    def disjunction():
        nonlocal cursor
        value = conjunction()
        while cursor < len(tokens) and tokens[cursor].lower() == "or":
            cursor += 1
            other = conjunction()
            value = value or other
        return value

    result = disjunction()
    if cursor != len(tokens):
        raise UnsupportedRule(f"unconsumed condition tokens: {tokens[cursor:]}")
    return result


def check_supported(detection: dict) -> None:
    for name, selector in detection.items():
        if name == "condition":
            continue
        def walk(value):
            if isinstance(value, list):
                for item in value:
                    walk(item)
            elif isinstance(value, dict):
                for field, expected in value.items():
                    unknown = set(field.split("|")[1:]) - SUPPORTED
                    if unknown:
                        raise UnsupportedRule(f"unsupported field modifiers: {sorted(unknown)}")
                    walk(expected)
        walk(selector)


def compatible(rule: dict, event: dict) -> bool:
    source = rule.get("logsource") or {}
    if source.get("product") != "windows":
        return False
    if source.get("service") not in (None, "sysmon"):
        return False
    event_category = SYSMON_CATEGORY.get(int(event["event_code"]))
    return source.get("category") in (None, event_category)


def evaluate(rule: dict, event: dict) -> bool:
    detection = rule.get("detection")
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), str):
        raise UnsupportedRule("missing single string detection condition")
    selectors = {key: value for key, value in detection.items() if key != "condition"}
    return parse_condition(detection["condition"], selectors, event["fields"])


def run_rule(path: Path, candidate_id: str, events: dict, expected_hash: str | None = None) -> dict:
    raw = path.read_bytes()
    if expected_hash and hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError(f"rule SHA-256 mismatch: {path}")
    rule = yaml.safe_load(raw)
    row = {"candidate_id": candidate_id, "dataset_id": events["dataset_id"], "status": "not_tested",
           "matched_event_uids": [], "events_evaluated": 0, "events_skipped": 0,
           "unsupported_features": [], "reason": "", "engine_version": ENGINE_VERSION,
           "rule_path": path.relative_to(ROOT).as_posix()}
    try:
        check_supported(rule.get("detection") or {})
        for event in events["items"]:
            if not compatible(rule, event):
                row["events_skipped"] += 1
                continue
            row["events_evaluated"] += 1
            if evaluate(rule, event):
                row["matched_event_uids"].append(event["event_uid"])
    except UnsupportedRule as exc:
        row["status"] = "unsupported_rule"
        row["unsupported_features"].append(str(exc))
        row["matched_event_uids"] = []
        row["reason"] = "Rule uses syntax outside the bounded offline evaluator"
        return row
    row["status"] = "incompatible_logsource" if not row["events_evaluated"] else ("hit" if row["matched_event_uids"] else "miss")
    row["reason"] = f"Evaluated {row['events_evaluated']} compatible events; skipped {row['events_skipped']} others"
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--rule", action="append", type=Path, default=[])
    parser.add_argument("--candidates", type=Path)
    parser.add_argument("--case-id", default="OTRF-LSASS_campaign_06")
    args = parser.parse_args()
    events = json.loads(args.events.read_text(encoding="utf-8"))
    validate_contract(events, args.events)
    specs = [(path.resolve(), path.stem, None) for path in args.rule]
    candidates = None
    if args.candidates:
        candidates = json.loads(args.candidates.read_text(encoding="utf-8"))
        validate_contract(candidates, args.candidates)
        specs.extend((workspace_path(row["rule_path"]), row["candidate_id"], row["rule_sha256"]) for row in candidates["items"])
    if not specs:
        parser.error("provide --rule PATH (repeatable) or --candidates FILE")
    result = {"schema_version": "1.0", "kind": "rule_tests",
              "case_id": candidates["case_id"] if candidates else args.case_id,
              "items": [run_rule(path, candidate_id, events, expected_hash) for path, candidate_id, expected_hash in specs]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    validate_contract(result, args.output)
    validate_links(result, candidates=candidates, events=events)
    for row in result["items"]:
        print(f"{row['candidate_id']}: {row['status']}, {len(row['matched_event_uids'])} matches, {row['events_evaluated']} evaluated")


if __name__ == "__main__":
    main()
