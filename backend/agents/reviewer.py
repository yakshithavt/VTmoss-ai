"""Security Reviewer -- validates the investigation before it can be finalized.

Checks structural integrity, not investigative correctness: every cited
evidence_id must exist, contradictions must have been checked, and
confidence values must be in sane bounds. This mirrors the audit-boundary
enforcement pattern (findings can't cite evidence that doesn't exist).
"""
from typing import List, Dict


def review(findings: List[Dict], evidence_by_id: Dict[str, Dict]) -> Dict:
    issues = []

    for f in findings:
        for eid in f.get("supporting_evidence", []):
            if eid not in evidence_by_id:
                issues.append(f"Finding '{f['title']}' cites nonexistent evidence_id {eid}")
        conf = f.get("adjusted_confidence", f.get("confidence", 0))
        if not (0 <= conf <= 1):
            issues.append(f"Finding '{f['title']}' has out-of-range confidence {conf}")
        if f.get("contradicting_evidence") and f.get("alternative_hypothesis") is None:
            issues.append(f"Finding '{f['title']}' has contradicting evidence but no alternative hypothesis recorded")

    approved = len(issues) == 0
    if approved:
        reason = "All findings are supported by valid evidence references and contradictions were addressed." if findings else "No findings were raised; evidence does not support an incident."
    else:
        reason = "Investigation failed structural review; see issues."

    return {
        "approved": approved,
        "confidence": round(sum(f.get("adjusted_confidence", f.get("confidence", 0)) for f in findings) / len(findings), 2) if findings else 1.0,
        "issues": issues,
        "reason": reason,
    }
