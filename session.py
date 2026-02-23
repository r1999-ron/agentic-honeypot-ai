"""
Session Management Module
Handles per-session state: memory, intelligence accumulation, finalization.
"""
from __future__ import annotations

import time
from collections import defaultdict
from intelligence import extract_all, merge_intelligence

SESSION_TIMEOUT = 3600  # 1 hour

# ── In-Memory Store ────────────────────────────────────────────────────────────

sessions: dict[str, dict] = {}


def _empty_session(session_id: str) -> dict:
    return {
        "id": session_id,
        "history": [],           # full conversation history [{role, content}]
        "intelligence": {        # cumulative extracted intel
            "phoneNumbers": [],
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "emailAddresses": [],
            "caseIds": [],
            "policyNumbers": [],
            "orderNumbers": [],
        },
        "is_scam": False,
        "confidence": 0.0,
        "red_flags": [],
        "scam_type": "unknown",
        "turn_number": 0,
        "start_time": time.time(),
        "finalized": False,
        "final_output": None,
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def get_or_create(session_id: str, initial_history: list | None = None) -> dict:
    """Retrieve existing session or create a fresh one."""
    if session_id not in sessions:
        sess = _empty_session(session_id)
        # Hydrate from provided conversation history (if evaluator sends prior turns)
        if initial_history:
            for msg in initial_history:
                role = "user" if msg.sender == "scammer" else "assistant"
                sess["history"].append({"role": role, "content": msg.text})
                # Extract intel from historical messages too
                if role == "user":
                    intel = extract_all(msg.text)
                    sess["intelligence"] = merge_intelligence(sess["intelligence"], intel)
        sessions[session_id] = sess
    return sessions[session_id]


def add_scammer_message(sess: dict, text: str) -> None:
    """Add a scammer message and extract intelligence from it."""
    sess["history"].append({"role": "user", "content": text})
    sess["turn_number"] += 1

    # Extract intelligence from every scammer message
    intel = extract_all(text)
    sess["intelligence"] = merge_intelligence(sess["intelligence"], intel)

    # Mark scam if actionable intel found
    if any(sess["intelligence"][k] for k in [
        "phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"
    ]):
        sess["is_scam"] = True


def add_agent_reply(sess: dict, reply: str) -> None:
    """Record the agent's reply."""
    sess["history"].append({"role": "assistant", "content": reply})


def update_detection(sess: dict, is_scam: bool, confidence: float, red_flags: list) -> None:
    """Update scam detection state."""
    if is_scam:
        sess["is_scam"] = True
    sess["confidence"] = max(sess["confidence"], confidence)
    # Accumulate unique red flags
    for flag in red_flags:
        if flag not in sess["red_flags"]:
            sess["red_flags"].append(flag)


def should_finalize(sess: dict, max_turns: int = 10) -> bool:
    turn = sess["turn_number"]
    duration = time.time() - sess["start_time"]

    # Only finalize on turn count or time — never on intel alone
    return (
        turn >= max_turns       # Hit the limit
        or duration > 300       # 5 min hard cap (safety net)
        or (sess["is_scam"] and turn >= 5)  # 🔥 add this
    )


def get_duration(sess: dict) -> int:
    return int(time.time() - sess["start_time"])


def cleanup_expired():
    """Remove sessions older than SESSION_TIMEOUT."""
    now = time.time()
    expired = [sid for sid, s in sessions.items()
               if now - s["start_time"] > SESSION_TIMEOUT]
    for sid in expired:
        del sessions[sid]
    if expired:
        print(f"[Session] Cleaned {len(expired)} expired sessions")