"""Venkathanu Evidence Trust Model (prototype scoring -- see docs/limitations.md).

Threat Score  = how dangerous the incident appears (produced by the investigator).
Evidence Trust Score = how strongly the AVAILABLE evidence supports that conclusion.

These are deliberately kept separate per the spec: a high-threat finding
with weak, uncorroborated, or successfully-contradicted evidence should show
a LOW trust score even though the threat score stays high, and vice versa.

Weights: evidence coverage 25%, source corroboration 25%,
counter-evidence check 20%, evidence integrity 20%, reviewer agreement 10%.
"""
from typing import List, Dict


def compute_trust_score(
    findings: List[Dict],
    evidence_items: List[Dict],
    review_result: Dict,
) -> Dict:
    total_evidence = len(evidence_items) or 1
    cited = {eid for f in findings for eid in f.get("supporting_evidence", [])}
    evidence_coverage = min(1.0, len(cited) / total_evidence)

    sources = {evidence_items[i]["source"] for i in range(len(evidence_items)) if evidence_items[i]["evidence_id"] in cited}
    source_corroboration = min(1.0, len(sources) / 2) if cited else 0.0

    if findings:
        counter_check = 1 - (sum(len(f.get("contradicting_evidence", [])) for f in findings) / (len(findings) * 3))
        counter_check = max(0.0, min(1.0, counter_check))
    else:
        counter_check = 1.0

    hashed = sum(1 for e in evidence_items if e.get("content_hash"))
    evidence_integrity = hashed / total_evidence

    reviewer_agreement = 1.0 if review_result.get("approved") else 0.5

    score = (
        evidence_coverage * 0.25
        + source_corroboration * 0.25
        + counter_check * 0.20
        + evidence_integrity * 0.20
        + reviewer_agreement * 0.10
    )

    return {
        "evidence_trust_score": round(score * 100),
        "components": {
            "evidence_coverage": round(evidence_coverage, 2),
            "source_corroboration": round(source_corroboration, 2),
            "counter_evidence_check": round(counter_check, 2),
            "evidence_integrity": round(evidence_integrity, 2),
            "reviewer_agreement": round(reviewer_agreement, 2),
        },
        "label": "Venkathanu Evidence Trust Model (prototype scoring, not a validated forensic metric)",
    }
