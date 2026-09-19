"""Primary AI Investigator.

Uses Gemini when GEMINI_API_KEY is configured; otherwise runs the
deterministic detection-rule engine (detection_rules.py) and returns the
exact same structured shape, tagged with mode so the frontend can render a
"FALLBACK MODE" badge honestly instead of pretending an LLM ran.

The investigator NEVER invents evidence IDs: every finding's
supporting_evidence must be a real evidence_id that exists in this case,
enforced in build_findings() below.
"""
import json
from collections import defaultdict
from typing import List, Dict

from agents.ai_provider import gemini_available, call_gemini
from agents.detection_rules import run_rules

INCIDENT_LABELS = {
    "T1059.001": "Suspicious PowerShell Activity",
    "T1078": "Anomalous Authentication Activity",
    "T1003": "Credential Access Activity",
    "T1021": "Lateral Movement Activity",
    "T1560": "Data Staging Activity",
    "T1566": "Phishing / Malicious URL Activity",
}


def _severity_weight(sev: str) -> float:
    return {"critical": 1.0, "high": 0.9, "medium": 0.6, "low": 0.3}.get(str(sev).lower(), 0.3)


def _build_findings_from_rule_hits(hits: List[Dict]) -> List[Dict]:
    by_technique = defaultdict(list)
    for h in hits:
        by_technique[h["mitre_id"]].append(h)

    findings = []
    for mitre_id, group in by_technique.items():
        evidence_ids = sorted({g["evidence_id"] for g in group})
        avg_conf = sum(g["base_confidence"] * _severity_weight(g["severity"]) for g in group) / len(group)
        findings.append({
            "title": group[0]["title"],
            "mitre_id": mitre_id,
            "confidence": round(min(avg_conf + 0.03 * (len(evidence_ids) - 1), 0.99), 2),
            "supporting_evidence": evidence_ids,
        })
    return findings


def compute_threat_score(findings: List[Dict], confidence_key: str = "confidence") -> int:
    """Recomputes an overall threat score from a set of findings, using
    whichever confidence field is passed in -- 'confidence' for the raw
    investigator output, or 'adjusted_confidence' once the Counter-Evidence
    Agent has had a chance to challenge each finding. This is what lets a
    successfully-contradicted finding actually pull the case's threat score
    down, instead of counter-evidence being cosmetic.
    """
    live = [f for f in findings if f.get(confidence_key, 0) > 0.15]
    if not live:
        return 10
    top = max(f[confidence_key] for f in live)
    return min(99, round(top * 100 * (0.6 + 0.4 * min(len(live), 3) / 3)))


def investigate(case_id: str, evidence_items: List[Dict]) -> Dict:
    valid_ids = {e["evidence_id"] for e in evidence_items}

    if gemini_available():
        try:
            prompt = (
                "You are a cybersecurity investigation AI. Analyze this normalized "
                "evidence and return ONLY JSON with keys incident_type, severity, "
                "threat_score (0-100), findings (list of {title, mitre_id, confidence, "
                "supporting_evidence: [real evidence_id]}), hypotheses (list of strings). "
                "You MUST only cite evidence_id values that appear in the input.\n\n"
                f"EVIDENCE:\n{json.dumps(evidence_items, default=str)}"
            )
            raw = call_gemini(prompt)
            result = json.loads(raw)
            # Anti-hallucination gate: strip any cited evidence_id that doesn't exist
            for f in result.get("findings", []):
                f["supporting_evidence"] = [eid for eid in f.get("supporting_evidence", []) if eid in valid_ids]
            result["mode"] = "gemini"
            return result
        except Exception as e:
            # Fall through to deterministic mode rather than fail the case
            fallback_note = f"Gemini call failed ({e}); used deterministic fallback."
    else:
        fallback_note = "GEMINI_API_KEY not configured; used deterministic fallback."

    hits = run_rules(evidence_items)
    findings = _build_findings_from_rule_hits(hits)

    if not findings:
        return {
            "incident_type": "No significant activity detected",
            "severity": "LOW",
            "threat_score": 10,
            "findings": [],
            "hypotheses": ["Benign / authorized activity"],
            "mode": "fallback",
            "fallback_note": fallback_note,
        }

    top = max(findings, key=lambda f: f["confidence"])
    threat_score = min(99, round(top["confidence"] * 100 * (0.6 + 0.4 * min(len(findings), 3) / 3)))
    severity = "CRITICAL" if threat_score >= 90 else "HIGH" if threat_score >= 70 else "MEDIUM" if threat_score >= 40 else "LOW"

    return {
        "incident_type": INCIDENT_LABELS.get(top["mitre_id"], "Suspicious Activity"),
        "severity": severity,
        "threat_score": threat_score,
        "findings": findings,
        "hypotheses": ["Malicious activity", "Legitimate administrative or authorized activity"],
        "mode": "fallback",
        "fallback_note": fallback_note,
    }
