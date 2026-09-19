"""Deterministic detection signatures used by the fallback investigator.

Each rule maps a MITRE ATT&CK technique to a matcher over normalized
evidence content. These are intentionally simple/explainable -- this is a
prototype trust model, not a production EDR ruleset (see docs/limitations).
"""
import re
from typing import List, Dict

RULES = [
    {
        "mitre_id": "T1059.001",
        "title": "Encoded PowerShell execution",
        "technique": "PowerShell (encoded command)",
        "match": lambda c: bool(re.search(r"powershell.*(-enc|-e |-EncodedCommand)", str(c.get("command", "")), re.I)),
        "base_confidence": 0.94,
    },
    {
        "mitre_id": "T1078",
        "title": "Anomalous authentication",
        "technique": "Valid Accounts",
        "match": lambda c: c.get("event_type") == "authentication" and str(c.get("result", "")).lower() in ("failed_then_success", "impossible_travel", "off_hours"),
        "base_confidence": 0.7,
    },
    {
        "mitre_id": "T1003",
        "title": "Credential access indicator",
        "technique": "OS Credential Dumping",
        "match": lambda c: any(k in str(c.get("process", "")).lower() for k in ("lsass", "mimikatz", "procdump")),
        "base_confidence": 0.9,
    },
    {
        "mitre_id": "T1021",
        "title": "Lateral movement indicator",
        "technique": "Remote Services",
        "match": lambda c: c.get("event_type") == "network" and str(c.get("connection_type", "")).lower() in ("smb_admin_share", "wmi", "psexec", "rdp_new_host"),
        "base_confidence": 0.75,
    },
    {
        "mitre_id": "T1560",
        "title": "Data staging / archiving",
        "technique": "Archive Collected Data",
        "match": lambda c: c.get("event_type") == "file" and str(c.get("file", "")).lower().endswith((".zip", ".rar", ".7z")) and c.get("size_mb", 0) and float(c.get("size_mb", 0)) > 50,
        "base_confidence": 0.8,
    },
    {
        "mitre_id": "T1566",
        "title": "Suspicious inbound URL/domain",
        "technique": "Phishing",
        "match": lambda c: c.get("event_type") in ("url", "network") and bool(c.get("known_malicious_domain")),
        "base_confidence": 0.85,
    },
]


def run_rules(evidence_items: List[Dict]) -> List[Dict]:
    """Returns one match dict per (rule, evidence item) hit."""
    hits = []
    for item in evidence_items:
        content = item["content"]
        for rule in RULES:
            try:
                if rule["match"](content):
                    hits.append({
                        "mitre_id": rule["mitre_id"],
                        "title": rule["title"],
                        "technique": rule["technique"],
                        "base_confidence": rule["base_confidence"],
                        "evidence_id": item["evidence_id"],
                        "severity": item.get("severity", "low"),
                    })
            except Exception:
                continue
    return hits
