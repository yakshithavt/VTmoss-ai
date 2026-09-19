# 5-Minute Demo Script

0:00-0:30  Problem: AI accelerates investigations, but can we verify the evidence behind an AI verdict, and detect if the record changes later?
0:30-1:00  Solution: Investigate -> Challenge -> Verify -> Anchor -> Respond.
1:00-2:00  Run VK-DEMO-COMPROMISED: threat 90, trust 100, "Likely compromised". Show evidence graph.
2:00-2:40  Run VK-DEMO-SUSPICIOUS: PowerShell finding gets contradicted by EVT-204 (signed maintenance task) but the auth anomaly and malicious URL don't -> "Suspicious", not falsely resolved either way.
2:40-3:30  Web3: SHA-256 -> Merkle root -> anchor transaction -> show tx hash + contract address.
3:30-4:00  Tamper: mutate threat_score post-anchor, click Verify -> INTEGRITY_FAILURE. Restore, verify -> VERIFIED.
4:00-4:30  Response plan: CRITICAL severity -> isolation/credential-reset REQUIRES_APPROVAL, IOC blocking SIMULATED.
4:30-5:00  Close: "We don't ask you to blindly trust the AI verdict — we challenge it, cryptographically fingerprint it, anchor it, and prove tampering."
