"""Thin AI-provider abstraction.

If GEMINI_API_KEY is set in the environment, calls Gemini and returns its
raw text. Otherwise (the default for this build -- no key configured yet)
callers fall back to the deterministic rule engine and the response is
tagged mode="fallback" everywhere it surfaces, per the spec's requirement
to clearly label demo/fallback mode rather than silently faking AI output.
"""
import json
import os
import urllib.request
import urllib.error

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"


def gemini_available() -> bool:
    return bool(GEMINI_API_KEY)


def call_gemini(prompt: str, timeout: int = 30) -> str:
    """Real call -- only exercised once GEMINI_API_KEY is configured."""
    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY not configured")

    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"response_mime_type": "application/json"},
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{GEMINI_URL}?key={GEMINI_API_KEY}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except urllib.error.URLError as e:
        raise RuntimeError(f"Gemini call failed: {e}")
