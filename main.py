"""
Honeypot API — Main Application
Agentic scam detection system that engages scammers, extracts intelligence,
and produces structured reports.
"""

import os
import random
import time
import json

from fastapi import FastAPI, Header, Request
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Union, List

# Internal modules
import session as session_store
from detection import detect_scam
from intelligence import extract_all, merge_intelligence
from agent import (
    generate_reply,
    classify_scam_type,
    generate_agent_notes,
)

# ── Config ─────────────────────────────────────────────────────────────────────

API_KEY = os.getenv("API_KEY", "")          # empty = accept all
MAX_TURNS = int(os.getenv("MAX_TURNS", "10"))

if not os.getenv("OPENAI_API_KEY"):
    raise RuntimeError("OPENAI_API_KEY environment variable is required")

# ── FastAPI App ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Honeypot API",
    description="Agentic scam detection and intelligence extraction system",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

final_outputs: dict = {}

# ── Error Handlers ─────────────────────────────────────────────────────────────

@app.exception_handler(FastAPIHTTPException)
async def http_exception_handler(request: Request, exc: FastAPIHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "message": exc.detail},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"[Error] Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Internal server error"},
    )


# ── Request / Response Models ──────────────────────────────────────────────────

class MessageModel(BaseModel):
    sender: str
    text: str
    timestamp: Union[int, str]


class MetadataModel(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneypotRequest(BaseModel):
    sessionId: str
    message: MessageModel
    conversationHistory: List[MessageModel] = []
    metadata: Optional[MetadataModel] = None


# ── Auth Helper ────────────────────────────────────────────────────────────────

def _auth_ok(x_api_key: Optional[str]) -> bool:
    """If API_KEY is set, validate; otherwise allow all."""
    if not API_KEY:
        return True
    return x_api_key == API_KEY


# ── Main Endpoint ──────────────────────────────────────────────────────────────

@app.post("/honeypot")
def honeypot(request: HoneypotRequest, x_api_key: Optional[str] = Header(None)):
    """
    Core honeypot endpoint.
    Receives scammer messages, engages them, extracts intelligence,
    and returns structured analysis when ready.
    """

    # Periodic cleanup (1% of requests)
    if random.random() < 0.01:
        session_store.cleanup_expired()

    # Auth — gracefully continue even on failure to not reveal honeypot nature
    if not _auth_ok(x_api_key):
        return {"status": "success", "reply": "Please continue, I am listening."}

    session_id = request.sessionId

    # ── Session Initialisation ─────────────────────────────────────────────────
    sess = session_store.get_or_create(session_id, request.conversationHistory)

    # ── Ingest Current Message ─────────────────────────────────────────────────
    current_text = request.message.text
    session_store.add_scammer_message(sess, current_text)

    # ── Scam Detection ─────────────────────────────────────────────────────────
    is_scam, confidence, red_flags = detect_scam(
        current_text,
        history=sess["history"],
    )
    session_store.update_detection(sess, is_scam, confidence, red_flags)

    # ── Scam Type Classification ───────────────────────────────────────────────
    full_text = " ".join(m["content"] for m in sess["history"] if m["role"] == "user")
    sess["scam_type"] = classify_scam_type(sess["intelligence"], full_text)

    # ── Generate Agent Reply ───────────────────────────────────────────────────
    reply = generate_reply(
        history=sess["history"],
        red_flags=sess["red_flags"],
        scam_type=sess["scam_type"],
        turn_number=sess["turn_number"],
        metadata=request.metadata.model_dump() if request.metadata else None,
    )
    session_store.add_agent_reply(sess, reply)

    # ── Re-extract Intel from Full Conversation ────────────────────────────────
    # (catches intel that appeared in earlier turns)
    all_scammer_text = " ".join(
        m["content"] for m in sess["history"] if m["role"] == "user"
    )
    full_intel = extract_all(all_scammer_text)
    sess["intelligence"] = merge_intelligence(sess["intelligence"], full_intel)

    # Any actionable intel → definitely a scam
    if any(sess["intelligence"][k] for k in [
        "phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"
    ]):
        sess["is_scam"] = True

    # ── Build Base Response ────────────────────────────────────────────────────
    response: dict = {"status": "success", "reply": reply}

    print(f"[Debug] session={session_id} turn={sess['turn_number']} finalized={sess['finalized']}", flush=True)
    # ── Finalisation ───────────────────────────────────────────────────────────
    if not sess["finalized"] and session_store.should_finalize(sess, MAX_TURNS):
        final = _build_final_output(sess)
        sess["final_output"] = final
        sess["finalized"] = True
        print(f"[Session {session_id}] FINALIZED: {final}")
        response.update(final)

    return response


def _build_final_output(sess: dict) -> dict:
    """Construct the full scored output for a completed session."""
    intel = {k: v for k, v in sess["intelligence"].items()}

    for k in ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks",
              "emailAddresses", "caseIds", "policyNumbers", "orderNumbers"]:
        intel.setdefault(k, [])

    duration = session_store.get_duration(sess)
    message_count = len(sess["history"])

    notes = generate_agent_notes(
        history=sess["history"],
        intel=intel,
        red_flags=sess["red_flags"],
    )

    final = {
        "sessionId": sess["id"],
        "scamDetected": sess["is_scam"],
        "scamType": sess["scam_type"],
        "confidenceLevel": sess["confidence"],
        "totalMessagesExchanged": message_count,
        "engagementDurationSeconds": duration,
        "extractedIntelligence": intel,
        "redFlagsIdentified": sess["red_flags"],
        "agentNotes": notes,
    }

    final_outputs[sess["id"]] = final
    print("\n===== FINAL OUTPUT =====", flush=True)
    print(json.dumps(final, indent=2), flush=True)  # prettier output
    print("========================\n", flush=True)
    return final

# ── Utility Endpoints ──────────────────────────────────────────────────────────

@app.get("/honeypot/final/{session_id}")
def get_final_output(session_id: str):
    """Retrieve final output for a session (useful for debugging)."""
    sess = session_store.sessions.get(session_id)
    if not sess:
        return {"error": "Session not found"}
    if sess.get("final_output"):
        return sess["final_output"]
    return _build_final_output(sess)


@app.get("/")
def root():
    return {"message": "Honeypot API v2 is running", "status": "healthy"}


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "active_sessions": len(session_store.sessions),
        "timestamp": time.time(),
    }