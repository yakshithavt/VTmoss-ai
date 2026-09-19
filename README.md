# Venkathanu.Ai
**Trusted Autonomous Cyber Investigation & Response**

> AI investigates. AI challenges. Cryptography proves. Web3 preserves. Response acts.

## Problem
AI can accelerate cybersecurity investigations, but an AI-generated conclusion raises a real question: can we verify the evidence behind it, and detect if the investigation record changes later?

## Solution
Evidence → AI Investigation → Counter-Evidence Challenge → Trust Scoring → SHA-256 → Merkle Tree → Ethereum Anchor → Integrity Verification → Controlled Response Plan.

See `docs/architecture.md`, `docs/demo-script.md`, `docs/ai-disclosure.md`, `docs/limitations.md`.

## Status (honest, as of this build)
✅ Backend, evidence pipeline, Merkle tree, deterministic investigator + counter-evidence + trust engine, EvidenceLedger.sol (7/7 tests passing), real anchor/verify/tamper-detection cycle run end-to-end against a **local Hardhat chain**.
⚠️ No GEMINI_API_KEY configured — investigator runs in labeled fallback mode.
⚠️ Not yet deployed to public Sepolia — needs your own funded testnet wallet (see below).
⚠️ Frontend is a lightweight static HTML/JS client (Tailwind via CDN), not a full Vite/React build — functional, calls the same API.

## Running it

### 1. Backend
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

### 2. Blockchain (local, no funds needed)
```bash
npm install
npx hardhat node                       # terminal 1 — local chain
npx hardhat run scripts/deploy.js --network localhost   # terminal 2
```
This writes `backend/blockchain/abi/EvidenceLedger.json` and `backend/blockchain/deployment.json`, which the backend reads automatically.

### 3. Frontend
```bash
cd frontend
python -m http.server 5173   # or any static file server
```
Open http://localhost:5173

### 4. Going live on Sepolia (when you have a funded testnet wallet)
```bash
# .env
RPC_URL=https://sepolia.infura.io/v3/<your-key>
PRIVATE_KEY=<your-testnet-only-private-key>   # never your real wallet's key
npm run deploy:sepolia
```
No code changes needed — `contract_client.py` picks up `RPC_URL`/`PRIVATE_KEY` from the environment automatically.

## Contract tests
```bash
npx hardhat test
```
7 passing, including tamper-detection (`verifyCase` returns `false` when the report hash doesn't match).

## Demo cases
`demo_data/{benign_case,suspicious_case,compromised_case}/evidence.json` — upload via `POST /api/cases/{id}/evidence`. Results from this build:

| Case | Threat | Trust | Verdict |
|---|---|---|---|
| Benign | 10 | 59 | Likely benign |
| Suspicious | 44 | 93 | Suspicious |
| Compromised | 90 | 100 | Likely compromised |

## Security
Upload types restricted to `.json/.csv/.txt`, 2MB limit, Pydantic-validated case IDs, CORS restricted, secrets never sent to frontend, blockchain private key stays backend-only, response actions never touch real systems.

## Limitations
See `docs/limitations.md` — read this before presenting to judges.
