# Architecture

```
Evidence (JSON/CSV/TXT)
      -> Parser + SHA-256 (backend/evidence/)
      -> AI Investigator (backend/agents/investigator.py; Gemini or deterministic fallback)
      -> Counter-Evidence Agent (backend/agents/counter_evidence.py)
      -> Security Reviewer (backend/agents/reviewer.py)
      -> Trust Engine (backend/agents/trust_engine.py)
      -> Merkle Tree over evidence hashes (backend/evidence/merkle.py)
      -> Report hash (backend/evidence/hashing.py)
      -> EvidenceLedger.sol on Ethereum (Sepolia or local Hardhat) via web3.py
      -> Verify Integrity (recompute + compare on-chain)
      -> Response Orchestrator (SIMULATED / REQUIRES_APPROVAL only)
```

See `docs/limitations.md` for what this does and does not prove.
