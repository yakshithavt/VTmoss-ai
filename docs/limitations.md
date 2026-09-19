# Limitations

- This prototype uses **synthetic, controlled cybersecurity evidence** (three demo cases). It has not been validated against real enterprise telemetry.
- The investigator runs in **deterministic fallback mode** by default (no GEMINI_API_KEY configured). Fallback mode uses an explainable rule engine (see `backend/agents/detection_rules.py`), not an LLM. Set GEMINI_API_KEY to switch to real Gemini reasoning.
- The **Evidence Trust Score** ("Venkathanu Evidence Trust Model") is a prototype, deterministic scoring formula. It is not a formally validated forensic-confidence metric.
- **Blockchain anchoring proves that a specific cryptographic record was registered at a specific time by a specific address — it does not prove the underlying AI conclusion is factually correct.**
- The contract is deployed and tested against a **local Hardhat network** in this build (real transactions, real EVM, just not a public chain). Pointing it at Ethereum Sepolia is a config change (`RPC_URL`, `PRIVATE_KEY`, redeploy) documented in the README, but requires your own funded testnet wallet.
- All response actions are **SIMULATED or REQUIRES_APPROVAL**. Nothing in this system ever touches a real endpoint, identity provider, or firewall.
- Ethereum Sepolia itself is a public test network with no real economic value.
