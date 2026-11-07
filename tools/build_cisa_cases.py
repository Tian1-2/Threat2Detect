"""Create reproducible answer-hidden CISA cases from locally downloaded PDFs.

Page ranges are deliberately explicit: inspect them again if CISA changes a PDF.
Requires pypdf (`python -m pip install pypdf`).
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".deps"))
sys.path.insert(0, str(ROOT))
from pypdf import PdfReader  # noqa: E402

from agent_poc import load_catalog, prepare_report


REPORTS = ROOT / "data" / "reports"
CASES = [
    {
        "id": "AA25-266A",
        "stem": "cisa-aa25-266a",
        "mapping_pages": (12, 14),
        "attack_version": "Enterprise v17",
        "split": "development",
        "source": "https://www.cisa.gov/sites/default/files/2025-09/AA25-266A_advisory_cisa_shares_lessons_learned_from_ir_engagement.pdf",
    },
    {
        "id": "AA23-319A",
        "stem": "cisa-aa23-319a",
        "mapping_pages": (12, 15),
        "attack_version": "Enterprise v17 (2025 update)",
        "split": "development",
        "source": "https://www.cisa.gov/sites/default/files/2025-04/aa23-319a-stopransomware-rhysida-ransomware_2.pdf",
    },
    {
        "id": "AA24-193A",
        "stem": "cisa-aa24-193a",
        "mapping_pages": (25, 29),
        "attack_version": "see source PDF",
        "split": "holdout",
        "source": "https://www.cisa.gov/sites/default/files/2024-07/csa-cisa-red-team%27s-operations-against-a-fceb-organization-highlights-the-necessity-of-defense-in-depth_0.pdf",
    },
]


def main() -> None:
    catalog = load_catalog(ROOT / "data" / "attack" / "enterprise-attack-20.0.json")
    for case in CASES:
        stem = case["stem"]
        reader = PdfReader(REPORTS / f"{stem}.pdf")
        pages = [page.extract_text() or "" for page in reader.pages]
        raw = "\n\n".join(f"=== PDF PAGE {i + 1} ===\n{page}" for i, page in enumerate(pages))
        (REPORTS / f"{stem}-extracted.txt").write_text(raw, encoding="utf-8")
        clean = prepare_report(raw)
        leaked_id = re.search(r"\bT\d{4}(?:\.\d{3})?\b|\[[^\]\n]{0,35}\bT\s*\d[^\]\n]{0,35}\]", clean)
        if clean == raw.strip() or leaked_id:
            raise ValueError(f"{stem}: mapping section missing or an ATT&CK ID remains in model input")
        (REPORTS / f"{stem}-input.txt").write_text(clean, encoding="utf-8")
        start, end = case["mapping_pages"]
        reference_text = "\n".join(pages[start - 1 : end])
        ids = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", reference_text)))
        if not ids:
            raise ValueError(f"{stem}: no ATT&CK IDs found in official mapping table")
        unavailable = sorted(set(ids) - set(catalog))
        reference = {
            "report_id": case["id"],
            "source": case["source"],
            "reference_pages": f"PDF pages {start}-{end}",
            "attack_version": case["attack_version"],
            "split": case["split"],
            "official_technique_ids": ids,
            "technique_ids": sorted(set(ids) & set(catalog)),
            "v20_unavailable_ids": unavailable,
            "reference_scope": "IDs in CISA's mapping section; human review is needed for behavior-level alignment",
        }
        (REPORTS / f"{stem}-reference.json").write_text(json.dumps(reference, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"{stem}: {len(clean)} input characters, {len(ids)} official IDs, {case['split']}; v20 unavailable={unavailable}")


if __name__ == "__main__":
    main()
