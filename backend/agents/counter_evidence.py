"""Counter-Evidence Agent.

For every finding the investigator produced, this agent explicitly tries to
break it: it searches the REST of the case's evidence (everything not
already cited as supporting_evidence) for anything that shares the same
user/host/process context and looks authorized, benign, or contradictory --
then lowers confidence and records exactly what it found and why.

This does not just apply a flat discount: the adjustment is proportional to
how directly the counter-evidence contradicts the finding.
"""
from typing import List, Dict


def _same_context(a: Dict, b: Dict) -> bool:
    """Two evidence items are 'about the same thing' only if they share the
    exact command (the literal signal a detection rule fired on) or the
    same process+host pair. Matching on a bare shared user/host alone was
    too loose -- it let one unrelated benign event on a shared host explain
    away completely unrelated findings (a malicious URL hit, an auth
    anomaly) just because the same user triggered both, which is not
    counter-evidence, it's coincidence.
    """
    if a.get("command") and b.get("command") and a["command"] == b["command"]:
        return True
    if a.get("process") and a.get("host") and a["process"] == b.get("process") and a["host"] == b.get("host"):
        return True
    return False


def challenge(findings: List[Dict], evidence_by_id: Dict[str, Dict]) -> List[Dict]:
    challenged = []
    for finding in findings:
        supporting = [evidence_by_id[eid] for eid in finding["supporting_evidence"] if eid in evidence_by_id]
        contradicting = []
        alt_hypothesis = None

        # Self-contained case: the very evidence that triggered the finding
        # already carries its own authorization/benign context (e.g. a
        # ticketed admin task), rather than being contradicted by a
        # *separate* item. This is the strongest form of counter-evidence.
        self_authorized = [s for s in supporting if s["content"].get("authorized") or s["content"].get("known_admin_activity")]
        for s in self_authorized:
            contradicting.append({
                "evidence_id": s["evidence_id"],
                "reason": s["content"].get("context") or "This evidence is itself marked as authorized administrative activity",
            })

        for eid, ev in evidence_by_id.items():
            if eid in finding["supporting_evidence"]:
                continue
            content = ev["content"]
            is_context_match = any(_same_context(content, s["content"]) for s in supporting)
            looks_benign = bool(content.get("authorized") or content.get("known_admin_activity") or content.get("context"))
            if is_context_match and looks_benign:
                contradicting.append({
                    "evidence_id": eid,
                    "reason": content.get("context") or "Marked as authorized / known administrative activity",
                })

        original_confidence = finding["confidence"]
        if contradicting:
            # Direct self-authorization (the flagged event IS the ticketed
            # activity) is near-conclusive and discounts heavily; each
            # additional piece of *separate* corroborating context chips
            # away more modestly on top of that.
            discount = (0.70 if self_authorized else 0.0) + 0.13 * len([c for c in contradicting if c["evidence_id"] not in {s["evidence_id"] for s in self_authorized}])
            discount = min(0.80, discount)
            adjusted = round(max(0.05, original_confidence - discount), 2)
            alt_hypothesis = "Legitimate administrative or authorized activity"
        else:
            adjusted = original_confidence

        challenged.append({
            **finding,
            "original_confidence": original_confidence,
            "adjusted_confidence": adjusted,
            "contradicting_evidence": [c["evidence_id"] for c in contradicting],
            "contradiction_reasons": contradicting,
            "alternative_hypothesis": alt_hypothesis,
            "uncertainty": "unresolved" if contradicting and adjusted > 0.5 else ("low" if not contradicting else "resolved_toward_benign"),
        })
    return challenged
