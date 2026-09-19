# AI Usage Disclosure

Venkathanu.Ai's investigator, counter-evidence agent, and response planner are built to optionally use **Google Gemini** (`GEMINI_API_KEY`) for:
- Investigation reasoning and structured finding generation
- Counter-evidence / alternative-hypothesis analysis
- Investigation explanations

**As shipped in this build, no Gemini key is configured**, so every run in this repo used the **deterministic rule-based fallback engine** instead (`backend/agents/detection_rules.py`, `backend/agents/counter_evidence.py`). All threat scores, findings, and trust scores shown in this README/demo were produced by that deterministic engine, not an LLM — this is stated honestly rather than implied to be AI-generated.

**Claude (Anthropic)** was used as a development assistant: writing this codebase (backend, smart contract, tests, docs), running the local test suite and local blockchain, and debugging.

Only tools actually used are listed above.
