"""Optional AI commentary on local verdict and enumerated rule IDs only."""

import asyncio
import json
import os
import re
from urllib.parse import quote

from app.engines.legacy_intel import LOOKUP_ERRORS
from app.engines.provider_http import failure, request_json
from app.scoring import RULES
from app.security import printable

AI_PROVIDERS = {
    "Groq": ("GROQ_API_KEY", "GROQ_MODEL", "openai/gpt-oss-20b", "https://api.groq.com/openai/v1/chat/completions"),
    "Gemini": ("GEMINI_API_KEY", "GEMINI_MODEL", "gemini-3.1-flash-lite", "https://generativelanguage.googleapis.com/v1beta/models/"),
    "OpenRouter": ("OPENROUTER_API_KEY", "OPENROUTER_MODEL", "openrouter/free", "https://openrouter.ai/api/v1/chat/completions"),
}
TASK = "Write one short SOC triage sentence using these rule labels. Keep the supplied verdict. Do not infer an attack, actor, or victim beyond the evidence. No commands or links."


async def summarize(client, result):
    states = {}
    available = {}
    enabled = os.getenv("PHISHMATRIX_AI_SUMMARY") == "1"
    for name, config in AI_PROVIDERS.items():
        key = os.getenv(config[0], "").strip()
        states[name] = "Not configured" if not key else "Standby" if enabled else "Sharing disabled"
        if key and enabled:
            available[name] = key
    if not available:
        return {"providers": states}

    evidence = sorted({item["rule_id"] for item in result["evidence"] if item["rule_id"] in RULES})
    prompt = TASK + " " + json.dumps({
        "verdict": result["verdict"],
        "rules": [f"{code}: {RULES[code][0]}" for code in evidence],
    })
    try:
        async with asyncio.timeout(5.0):
            for name, key in available.items():
                states[name] = "Unavailable"
                output, status = await generate(client, name, key, prompt)
                states[name] = status
                if output:
                    return {"providers": states, "advisory": {"source": name, "text": output}}
    except TimeoutError:
        pass
    return {"providers": states}


async def generate(client, name, key, prompt):
    _, model_var, default, endpoint = AI_PROVIDERS[name]
    model = os.getenv(model_var, default).strip() or default
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+(?:/[A-Za-z0-9_.:-]+)?", model) or (name == "Gemini" and "/" in model):
        return None, "Invalid configuration"
    try:
        if name == "Gemini":
            status, body = await request_json(
                client, "POST", f"{endpoint}{quote(model, safe='-._')}:generateContent",
                headers={"x-goog-api-key": key},
                json={"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"maxOutputTokens": 180}},
                timeout=1.8,
            )
            if status != 200:
                return None, failure(status)
            parts = body["candidates"][0]["content"]["parts"]
            content = " ".join(part["text"] for part in parts if isinstance(part.get("text"), str) and not part.get("thought"))
        else:
            payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "max_completion_tokens": 400}
            if name == "Groq" and model.startswith("openai/gpt-oss-"):
                payload.update(include_reasoning=False, reasoning_effort="low")
            status, body = await request_json(
                client, "POST", endpoint, headers={"Authorization": f"Bearer {key}"}, json=payload,
                timeout=1.8,
            )
            if status != 200:
                return None, failure(status)
            content = body["choices"][0]["message"]["content"]
        if not isinstance(content, str) or not content.strip():
            return None, "Unavailable"
        return printable(content.replace(key, "[redacted]"), 450), "Observed"
    except LOOKUP_ERRORS + (IndexError,):
        return None, "Unavailable"
