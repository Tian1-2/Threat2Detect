"""Check the bounded executor against reviewed OTRF event/condition examples."""
import json
from pathlib import Path

import pytest

from normalize_otrf import SYSMON_CHANNEL, parse_message, source_lines
from run_sigma_offline import run_rule


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data/Security-Datasets/datasets/compound/LSASS_campaign_06/metasploit_outflank-dumpert_lsass_memory_dump.zip"
DATASET_ID = "OTRF-LSASS_campaign_06"


def test_reviewed_event_rule_examples():
    if not SOURCE.exists():
        pytest.skip("OTRF submodule not initialized")
    selected = {1727, 2090, 17255, 20542, 33808}
    items = []
    with source_lines(SOURCE) as lines:
        for line_number, line in enumerate(lines, 1):
            if line_number not in selected:
                continue
            raw = json.loads(line)
            assert raw["Channel"] == SYSMON_CHANNEL
            items.append({"event_uid": f"{DATASET_ID}:L{line_number}", "event_code": raw["EventID"],
                          "fields": parse_message(raw["Message"])})
    assert len(items) == len(selected)
    events = {"dataset_id": DATASET_ID, "items": items}
    base = ROOT / "data/sigma/rules/windows"
    memdump = run_rule(base / "process_access/proc_access_win_lsass_memdump.yml", "memdump", events)
    keyword = run_rule(base / "process_access/proc_access_win_lsass_dump_keyword_image.yml", "keyword", events)
    accounts = run_rule(base / "process_creation/proc_creation_win_susp_local_system_owner_account_discovery.yml", "accounts", events)
    assert memdump["matched_event_uids"] == [f"{DATASET_ID}:L33808"]
    assert keyword["matched_event_uids"] == [f"{DATASET_ID}:L33808"]
    assert accounts["matched_event_uids"] == [f"{DATASET_ID}:L20542"]
    assert all(row["status"] == "hit" for row in (memdump, keyword, accounts))
