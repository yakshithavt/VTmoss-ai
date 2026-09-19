"""Response Orchestrator -- generates a SAFE, non-destructive response plan.

Every action is either SIMULATED (logged as if it happened, nothing real is
touched) or REQUIRES_APPROVAL (a human must explicitly approve before any
real system could act on it). Nothing in this module ever calls out to a
real endpoint, identity provider, or firewall -- this is intentional per
the spec's safety requirements for this project.
"""
from typing import Dict, List

PLAYBOOK = {
    "CRITICAL": [
        ("Preserve forensic evidence", "SIMULATED", False),
        ("Isolate affected endpoint", "REQUIRES_APPROVAL", True),
        ("Revoke suspicious session", "REQUIRES_APPROVAL", True),
        ("Reset compromised credentials", "REQUIRES_APPROVAL", True),
        ("Block malicious IOC at perimeter", "SIMULATED", False),
        ("Notify security team", "SIMULATED", False),
    ],
    "HIGH": [
        ("Preserve forensic evidence", "SIMULATED", False),
        ("Isolate affected endpoint", "REQUIRES_APPROVAL", True),
        ("Reset compromised credentials", "REQUIRES_APPROVAL", True),
        ("Block malicious IOC at perimeter", "SIMULATED", False),
        ("Notify security team", "SIMULATED", False),
    ],
    "MEDIUM": [
        ("Preserve forensic evidence", "SIMULATED", False),
        ("Flag account for manual review", "REQUIRES_APPROVAL", True),
        ("Notify security team", "SIMULATED", False),
    ],
    "LOW": [
        ("Log for audit trail", "SIMULATED", False),
        ("No further action recommended", "SIMULATED", False),
    ],
}


def generate_response_plan(severity: str) -> List[Dict]:
    steps = PLAYBOOK.get(severity.upper(), PLAYBOOK["LOW"])
    return [
        {"action": action, "status": status, "requires_approval": requires_approval, "severity": severity}
        for action, status, requires_approval in steps
    ]
