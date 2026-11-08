"""Optional FastAPI sidecar for Advanced Features AI calls.

The Flask app already serves /api/advanced/chat and /api/chatbot/ask
so this process is not required to use the UI.

    cd ai_service
    pip install -r requirements.txt
    uvicorn main:app --host 127.0.0.1 --port 8001
"""
import os
import sys

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
load_dotenv(os.path.join(BACKEND, ".env"))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from ai.chatbot.gemini_client import answer_any

app = FastAPI(title="Cloud Security Advanced AI Service", version="1.1.0")


class ChatRequest(BaseModel):
    question: str
    project_id: str | None = None
    context: dict | None = None


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "advanced-ai",
        "gemini": bool(os.getenv("GEMINI_API_KEY")),
        "model": os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
    }


@app.post("/chat")
def chat(body: ChatRequest):
    key = (os.getenv("GEMINI_API_KEY") or "").strip()
    if not key:
        raise HTTPException(503, "GEMINI_API_KEY is not configured")
    if not body.question.strip():
        raise HTTPException(400, "Question is required")
    extra = None
    if body.context:
        extra = str(body.context)[:8000]
    result = answer_any(
        body.question.strip(),
        key,
        model=os.getenv("GEMINI_MODEL", "gemini-3.8-flash"),
        extra_context=extra,
    )
    if not result.get("ok"):
        raise HTTPException(502, result.get("error") or "Gemini request failed")
    return {
        "answer": result["text"],
        "source": "gemini",
        "model": result.get("model"),
        "project_id": body.project_id,
    }
