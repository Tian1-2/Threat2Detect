"""Deterministic Sigma candidate retrieval for a case_handoff file.

Run from the project root. Retrieval is not a coverage judgment or rule execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
from collections import Counter
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from .. import PROJECT_ROOT


ROOT = PROJECT_ROOT
DEFAULT_RULES = ROOT / "data" / "sigma"
TOKEN = re.compile(r"[a-z0-9]{3,}")
FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\|.*)?$")
STOP = {
    "the", "and", "for", "from", "with", "into", "that", "this", "was",
    "were", "are", "use", "used", "using", "via",
}

PLATFORM_HINTS = {
    "windows": {
        "windows", "active directory", "sysmon", "powershell", "cmd",
        "wmi", "sql server", "whoami", "ipconfig", "tasklist", "systeminfo",
        "netstat", "bitsadmin", "certutil", ".exe",
    },
    "linux": {
        "linux", "bash", "uname", "rpm", "yum", "apt", "systemctl",
        "/etc/", "/var/", "/tmp/", "ps -aux", "df -h", "who -b",
    },
    "macos": {"macos", "osascript", "launchctl"},
}

CATEGORY_HINTS = {
    "process_creation": {
        "command", "execute", "executed", "run", "ran", "tool", "whoami",
        "ipconfig", "tasklist", "systeminfo", "powershell", "cmd", "wmic",
    },
    "process_access": {"lsass", "process access", "memory dump", "dump memory"},
    "file_event": {"write", "written", "create file", "created file", "upload", "download", "dmp"},
    "network_connection": {"c2", "traffic", "proxy", "connection", "network resources", "tunnel"},
}


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


def behavior_context(behavior: dict) -> tuple[set[str], set[str]]:
    evidence = behavior.get("evidence") or {}
    text = " ".join(
        str(value or "")
        for value in (
            evidence.get("quote"),
            behavior.get("action"),
            behavior.get("object"),
        )
    ).casefold()
    platforms = {
        platform
        for platform, hints in PLATFORM_HINTS.items()
        if any(hint in text for hint in hints)
    }
    categories = {
        category
        for category, hints in CATEGORY_HINTS.items()
        if any(hint in text for hint in hints)
    }
    if any(token in text for token in ("whoami", "ipconfig", "tasklist", "systeminfo")):
        categories.add("process_creation")
    return platforms, categories


def platform_compatible(rule: dict, platforms: set[str]) -> bool:
    if not platforms:
        return True
    product = str((rule.get("logsource") or {}).get("product") or "").casefold()
    return not product or product in platforms


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for child in value for item in _strings(child)]
    return []


def _selector_support(selector, behavior_text: str) -> bool:
    if isinstance(selector, list):
        return any(_selector_support(item, behavior_text) for item in selector)
    if not isinstance(selector, dict):
        return False
    for field_spec, expected in selector.items():
        field, *modifiers = field_spec.split("|")
        values = _strings(expected)
        if field in {"Image", "OriginalFileName"}:
            basenames = {
                Path(value.replace("\\", "/")).name.casefold()
                for value in values
            }
            stems = {Path(name).stem for name in basenames} | basenames
            if not any(stem and stem in behavior_text for stem in stems):
                return False
        elif field == "CommandLine":
            if "re" in modifiers:
                for pattern in values:
                    try:
                        if re.search(pattern, behavior_text, re.IGNORECASE):
                            return True
                    except re.error:
                        pass
                return False
            needles = {value.casefold() for value in values}
            if "windash" in modifiers:
                needles |= {
                    value.replace(" -", " /").casefold()
                    for value in values
                }
                needles |= {
                    value.replace(" /", " -").casefold()
                    for value in values
                }
            checks = [needle in behavior_text for needle in needles]
            if not (all(checks) if "all" in modifiers else any(checks)):
                return False
        else:
            return False
    return True


def condition_adjustment(behavior: dict, rule: dict) -> tuple[float, list[str], dict[str, object]]:
    detection = rule.get("detection") or {}
    condition = str(detection.get("condition") or "")
    evidence = behavior.get("evidence") or {}
    behavior_text = " ".join(
        str(value or "")
        for value in (evidence.get("quote"), behavior.get("action"), behavior.get("object"))
    ).casefold()
    selectors = {name: value for name, value in detection.items() if name != "condition"}
    adjustment = 0.0
    reasons = []
    details: dict[str, object] = {"supported_selectors": [], "unsupported_selectors": []}

    for match in re.finditer(r"\ball of\s+([A-Za-z0-9_*]+)", condition, re.IGNORECASE):
        pattern = match.group(1)
        names = [name for name in selectors if fnmatchcase(name, pattern)]
        unsupported = [name for name in names if not _selector_support(selectors[name], behavior_text)]
        broken = bool(unsupported)
        details["unsupported_selectors"].extend(unsupported)
        if broken:
            adjustment -= 100
            reasons.append("required argument, user, or process condition is not evidenced")

    if re.search(r"\band\s+not\s+(?:1 of\s+)?filter", condition, re.IGNORECASE):
        filters = {name: value for name, value in selectors.items() if name.startswith("filter")}
        filter_fields = {
            field.split("|", 1)[0]
            for selector in filters.values()
            for selector_item in (selector if isinstance(selector, list) else [selector])
            if isinstance(selector_item, dict)
            for field in selector_item
        }
        executable_filter_match = any(
            _selector_support(selector, behavior_text)
            for selector in filters.values()
            if any(
                field.split("|", 1)[0] in {"Image", "OriginalFileName"}
                for selector_item in (selector if isinstance(selector, list) else [selector])
                if isinstance(selector_item, dict)
                for field in selector_item
            )
        )
        if executable_filter_match:
            adjustment -= 120
            reasons.append("reported executable is likely removed by the rule filter")
        elif "ParentImage" in filter_fields:
            adjustment -= 70
            reasons.append("parent-process filter cannot be resolved from the report")

    if condition.strip().casefold() == "selection" and "selection" in selectors:
        if not _selector_support(selectors["selection"], behavior_text):
            adjustment -= 70
            reasons.append("the sole selection does not match the reported command detail")

    supported = [
        name for name, selector in selectors.items()
        if not name.startswith("filter") and _selector_support(selector, behavior_text)
    ]
    details["supported_selectors"] = supported
    if supported:
        bonus = min(20.0, 10.0 * len(supported))
        adjustment += bonus
        reasons.append("supported Sigma selector evidence")
    details["adjustment"] = round(adjustment, 3)
    return adjustment, reasons, details


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
    """Read the pinned commit without requiring a child git process when possible."""
    marker = rules_root / ".git"
    git_dir = marker
    if marker.is_file():
        text = marker.read_text(encoding="utf-8").strip()
        if not text.startswith("gitdir:"):
            raise ValueError("Sigma .git file has no gitdir pointer")
        git_dir = (rules_root / text.split(":", 1)[1].strip()).resolve()
    if git_dir.is_dir():
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[0-9a-f]{40}", head):
            return head
        if head.startswith("ref:"):
            ref_name = head.split(":", 1)[1].strip()
            ref_path = git_dir / ref_name
            if ref_path.is_file():
                commit = ref_path.read_text(encoding="utf-8").strip()
                if re.fullmatch(r"[0-9a-f]{40}", commit):
                    return commit
            packed = git_dir / "packed-refs"
            if packed.is_file():
                for line in packed.read_text(encoding="utf-8").splitlines():
                    if line and not line.startswith(("#", "^")):
                        commit, _, name = line.partition(" ")
                        if name == ref_name and re.fullmatch(r"[0-9a-f]{40}", commit):
                            return commit
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
            "detection": rule["detection"],
        }
        for tag in tags:
            if tag.startswith("attack.t"):
                index.setdefault(tag[7:].upper(), []).append(item)
    return index, warnings


def build_idf(index: dict[str, list[dict]]) -> dict[str, float]:
    unique = {rule["rule_id"]: rule for rules in index.values() for rule in rules}
    document_frequency: Counter[str] = Counter()
    for rule in unique.values():
        text = " ".join((rule["title"], rule["description"], rule["detection_text"]))
        document_frequency.update(tokens(text))
    count = max(len(unique), 1)
    return {token: math.log((count + 1) / (frequency + 1)) + 1 for token, frequency in document_frequency.items()}


def score_rule(
    behavior: dict,
    rule: dict,
    idf: dict[str, float],
    categories: set[str],
) -> tuple[float, list[str], dict[str, object]]:
    evidence = behavior.get("evidence") or {}
    query = tokens(" ".join(str(value) for value in (evidence.get("quote"), behavior.get("action"), behavior.get("object")) if value))
    title_hits = query & tokens(rule["title"])
    condition_hits = query & tokens(rule["detection_text"])
    description_hits = query & tokens(rule["description"])
    quote_hits = tokens(str(evidence.get("quote") or "")) & (title_hits | condition_hits | description_hits)
    score = sum(idf.get(term, 1.0) * (5 if term in title_hits else 0) for term in title_hits)
    score += sum(idf.get(term, 1.0) * (4 if term in condition_hits else 0) for term in condition_hits)
    score += sum(idf.get(term, 1.0) * (1.5 if term in description_hits else 0) for term in description_hits)
    score += sum(idf.get(term, 1.0) * (6 if term in condition_hits else 2) for term in quote_hits)
    rule_category = str((rule.get("logsource") or {}).get("category") or "").casefold()
    category_match = bool(categories and rule_category in categories)
    if category_match:
        score += 4
    status = str(rule.get("status") or "").casefold()
    if status == "stable":
        score += 2
    elif status == "test":
        score += 1
    elif status == "deprecated":
        score -= 5
    condition_score, condition_reasons, condition_components = condition_adjustment(behavior, rule)
    score += condition_score
    reasons = ["exact ATT&CK technique tag"]
    if condition_hits:
        reasons.append("detection terms: " + ", ".join(sorted(condition_hits)))
    if title_hits:
        reasons.append("title terms: " + ", ".join(sorted(title_hits)))
    if category_match:
        reasons.append(f"compatible category: {rule_category}")
    if status:
        reasons.append(f"rule status: {status}")
    reasons.extend(condition_reasons)
    components = {
        "title_hits": sorted(title_hits),
        "detection_hits": sorted(condition_hits),
        "description_hits": sorted(description_hits),
        "quote_hits": sorted(quote_hits),
        "category_match": category_match,
        "status": status or None,
        "condition_adjustment": condition_components,
    }
    return round(score, 3), reasons, components


def retrieve(handoff: dict, rules_root: Path, limit: int, include_draft: bool = False) -> dict:
    if handoff.get("kind") != "case_handoff":
        raise ValueError("Expected kind=case_handoff")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    commit = ruleset_commit(rules_root)
    index, warnings = index_rules(rules_root)
    idf = build_idf(index)
    allowed = {"confirmed", "draft"} if include_draft else {"confirmed"}
    behaviors = {item["behavior_id"]: item for item in handoff["behaviors"] if item["review_status"] in allowed}
    items = []
    platform_exclusions = []
    for mapping in handoff["mappings"]:
        behavior = behaviors.get(mapping["behavior_id"])
        if not behavior or mapping["review_status"] not in allowed:
            continue
        technique_id = mapping["technique_id"]
        platforms, categories = behavior_context(behavior)
        technique_rules = index.get(technique_id, [])
        compatible = [rule for rule in technique_rules if platform_compatible(rule, platforms)]
        if not compatible:
            compatible = technique_rules
        excluded = [rule for rule in technique_rules if rule not in compatible]
        for rule in excluded:
            platform_exclusions.append({
                "behavior_id": behavior["behavior_id"],
                "rule_id": rule["rule_id"],
                "rule_path": rule["rule_path"],
                "reason": f"logsource product {rule['logsource'].get('product')!r} is incompatible with inferred platforms {sorted(platforms)}",
            })
        scored = []
        for rule in compatible:
            score, reasons, components = score_rule(behavior, rule, idf, categories)
            scored.append((score, reasons, components, rule))
        ranked = sorted(scored, key=lambda row: (-row[0], row[3]["rule_path"]))
        for rank, (score, reasons, components, rule) in enumerate(ranked[:limit], 1):
            source = rule["logsource"]
            stable_id = rule["rule_id"].split("-", 1)[0]
            items.append({
                "candidate_id": f"{mapping['mapping_id']}-{stable_id}",
                "rank": rank,
                "behavior_id": behavior["behavior_id"], "technique_id": technique_id,
                "rule_id": rule["rule_id"], "rule_path": rule["rule_path"],
                "rule_sha256": rule["rule_sha256"], "title": rule["title"],
                "tags": rule["tags"],
                "logsource": {"product": source.get("product") or "unknown", "category": source.get("category"), "service": source.get("service")},
                "status": rule["status"], "required_fields": rule["required_fields"],
                "retrieval_score": score,
                "retrieval_components": components,
                "retrieval_reason": "; ".join(reasons) + f"; score {score}",
            })
    return {"schema_version": "1.0", "kind": "rule_candidates", "case_id": handoff["case_id"],
            "ruleset_commit": commit, "items": items, "retrieval_warnings": warnings,
            "platform_exclusions": platform_exclusions,
            "retrieval_note": "Candidates use exact technique tags, platform filtering, IDF-weighted field terms, category compatibility, and rule status; coverage requires separate YAML condition review."}


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
