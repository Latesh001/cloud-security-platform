"""Google Gemini client for fast chat replies.

Uses the Interactions API (current Gemini 3.8 path) first, then a single
generateContent call on a Flash-Lite model. The working combo is cached so
later questions are one HTTP request. Failed models are not retried.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger("cloud_security.gemini")

REQUEST_TIMEOUT = 8

FAST_MODELS = (
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-3.8-flash",
)

GENERAL_SYSTEM_PROMPT = (
    "You are a general-purpose AI assistant powered by Google Gemini, running "
    "inside Cloud Security Monitoring and Automated Incident Response using AI.\n\n"
    "Answer ANY question the user asks. That includes general knowledge, science, "
    "math, history, programming, writing, career advice, cybersecurity theory, "
    "CVE/OWASP explanations, and questions about this product or the signed-in "
    "developer's uploaded projects.\n\n"
    "Rules:\n"
    "- If the question is general, answer it fully. Do not force it into a "
    "security or project template. Do not say you can only answer predefined topics.\n"
    "- If optional product or project context is provided and the question is "
    "about this platform or the developer's work, use that context. Never invent "
    "project IDs, scores, findings, or incident IDs.\n"
    "- Phase 3 containment actions in this product are simulated and do not "
    "change a real cloud account.\n"
    "- Write a complete, self-contained answer in markdown. Start with the "
    "direct answer, then explain.\n"
)

_working: Dict[str, Optional[str]] = {"path": None, "model": None}
_failed: set = set()


def _auth(api_key: str) -> Tuple[dict, dict]:
    headers = {"Content-Type": "application/json"}
    if api_key.startswith("AIza"):
        return {"key": api_key}, headers
    headers["x-goog-api-key"] = api_key
    return {}, headers


def _extract_generate_text(payload: dict) -> str:
    candidates = payload.get("candidates") or []
    if not candidates:
        return ""
    parts = (candidates[0].get("content") or {}).get("parts") or []
    return "".join(part.get("text") or "" for part in parts).strip()


def _walk_text(value: Any, bucket: List[str]) -> None:
    if isinstance(value, str) and value.strip():
        bucket.append(value.strip())
        return
    if isinstance(value, dict):
        for key in ("output_text", "text", "content"):
            if key in value:
                _walk_text(value[key], bucket)
        for key in ("outputs", "output", "steps", "parts", "candidates"):
            if key in value:
                _walk_text(value[key], bucket)
        return
    if isinstance(value, list):
        for item in value:
            _walk_text(item, bucket)


def _extract_interaction_text(payload: dict) -> str:
    direct = (payload.get("output_text") or "").strip()
    if direct:
        return direct
    bucket: List[str] = []
    _walk_text(payload.get("outputs") or payload.get("output") or payload, bucket)
    # Prefer the longest non-empty chunk; skip tiny status strings.
    texts = [t for t in bucket if len(t) > 1]
    return max(texts, key=len) if texts else ""


def _user_prompt(question: str, extra_context: Optional[str]) -> str:
    if not extra_context:
        return question
    extra = extra_context.strip()
    if len(extra) > 4000:
        extra = extra[:4000] + "\n[context truncated]"
    return (
        f"{question}\n\n---\nOptional grounding context (use only when relevant):\n{extra}"
    )


def _try_interactions(api_key: str, model: str, prompt: str, system_prompt: str) -> Dict:
    params, headers = _auth(api_key)
    url = "https://generativelanguage.googleapis.com/v1beta/interactions"
    body = {
        "model": model,
        "input": prompt,
        "system_instruction": system_prompt,
        "generation_config": {
            "temperature": 0.5,
            "max_output_tokens": 1536,
        },
    }
    try:
        response = requests.post(
            url, params=params, headers=headers, json=body, timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": f"Interactions {model}: {exc.__class__.__name__}"}
    if response.status_code != 200:
        return {"ok": False, "error": f"Interactions {model} HTTP {response.status_code}: {response.text[:180]}"}
    try:
        payload = response.json()
    except ValueError:
        return {"ok": False, "error": f"Interactions {model} returned invalid JSON"}
    text = _extract_interaction_text(payload)
    if not text:
        return {"ok": False, "error": f"Interactions {model} returned empty text"}
    return {"ok": True, "text": text, "model": model}


def _try_generate_content(api_key: str, model: str, prompt: str, system_prompt: str) -> Dict:
    params, headers = _auth(api_key)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    body = {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.5,
            "maxOutputTokens": 1536,
            "topP": 0.95,
        },
    }
    try:
        response = requests.post(
            url, params=params, headers=headers, json=body, timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": f"{model} generateContent: {exc.__class__.__name__}"}
    if response.status_code != 200:
        return {"ok": False, "error": f"{model} HTTP {response.status_code}: {response.text[:180]}"}
    try:
        text = _extract_generate_text(response.json())
    except ValueError:
        return {"ok": False, "error": f"{model} returned invalid JSON"}
    if not text:
        return {"ok": False, "error": f"{model} returned an empty candidate"}
    return {"ok": True, "text": text, "model": model}


def generate(question: str, api_key: str, model: str = "",
             system_prompt: Optional[str] = None,
             extra_context: Optional[str] = None,
             temperature: float = 0.6,
             max_output_tokens: int = 2048) -> Dict:
    """Call Gemini. Always returns a dict; never raises to the caller."""
    del temperature, max_output_tokens  # kept for call-site compatibility
    api_key = (api_key or "").strip()
    question = (question or "").strip()
    if not api_key:
        return {"ok": False, "text": "", "model": None, "error": "GEMINI_API_KEY is not configured"}
    if not question:
        return {"ok": False, "text": "", "model": None, "error": "Question is empty"}

    prompt = _user_prompt(question, extra_context)
    system = system_prompt or GENERAL_SYSTEM_PROMPT
    last_error = "Gemini did not return a reply"

    attempts: List[Tuple[str, str]] = []
    cached = (_working.get("path"), _working.get("model"))
    if cached[0] and cached[1] and cached[1] not in _failed:
        attempts.append((cached[0], cached[1]))

    preferred = (model or "").strip() or "gemini-3.5-flash-lite"
    # Flash-Lite generateContent is the path that returns quickly on this key.
    # 3.8 generateContent currently hangs, so it is not the first try.
    for path, name in (
        ("generate", "gemini-3.5-flash-lite"),
        ("interactions", preferred),
        ("generate", "gemini-3.1-flash-lite"),
    ):
        if name in _failed:
            continue
        if (path, name) not in attempts:
            attempts.append((path, name))

    for path, name in attempts[:4]:
        if path == "interactions":
            result = _try_interactions(api_key, name, prompt, system)
        else:
            result = _try_generate_content(api_key, name, prompt, system)
        if result.get("ok"):
            _working["path"] = path
            _working["model"] = name
            return {"ok": True, "text": result["text"], "model": name, "error": None}
        last_error = result.get("error") or last_error
        logger.warning("Gemini call failed: %s", last_error)
        if "HTTP 401" in last_error or "HTTP 403" in last_error:
            break
        if "HTTP 404" in last_error or "HTTP 400" in last_error:
            _failed.add(name)

    return {"ok": False, "text": "", "model": None, "error": last_error}


def answer_any(question: str, api_key: str, model: str = "",
               extra_context: Optional[str] = None) -> Dict:
    return generate(question, api_key, model=model, extra_context=extra_context)
