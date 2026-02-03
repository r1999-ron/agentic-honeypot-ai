import os
import random
import re
import requests
import time
from threading import Thread
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, Header, HTTPException, Body
from fastapi import Request
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from fastapi.responses import JSONResponse
from openai import OpenAI
from pydantic import BaseModel

API_KEY = os.getenv("API_KEY", "sk_test_123456789")
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
MAX_TURNS = int(os.getenv("MAX_TURNS", "10"))  # safety cap
SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", "3600"))  # 1 hour

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY environment variable not set")

client = OpenAI(api_key=OPENAI_API_KEY)

PERSONA_PROMPT = """
You are a normal Indian user.
You are polite, slightly scared, and not very technical.
You believe the other person is a real bank or support executive.

Behavior rules:
- Ask step-by-step questions like a confused customer.
- If payment is mentioned, ask HOW and WHERE to pay.
- If verification is mentioned, ask for the exact process.
- If links or apps are mentioned, ask them to resend or clarify.
- Never directly ask for sensitive details.
- Let the other person reveal UPI IDs, account numbers, or links naturally.

Never say you are an AI.
Never say you are detecting scam.
Always sound human and genuine.
Use simple Indian English expressions like "Sir/Madam", "Please help me", "I am not understanding properly".
"""

# ------------------ APP ---------------------------------------------------------------

app = FastAPI(title="Agentic Honeypot API")


# ----------- ERROR HANDLING -----------------------------------------------------------

@app.exception_handler(FastAPIHTTPException)
async def http_exception_handler(request: Request, exc: FastAPIHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "message": exc.detail},
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Internal server error"},
    )

# ---------------- MEMORY -------------------------------------------------------------------

session_memory = {}
session_intelligence = {}
session_start_time = {}
session_finalized = {}
session_is_scam = {}
# session_last_intel_snapshot = {}

# Session cleanup function
def cleanup_old_sessions():
    current_time = time.time()
    expired_sessions = [
        sid for sid, start_time in session_start_time.items()
        if current_time - start_time > SESSION_TIMEOUT
    ]
    for sid in expired_sessions:
        session_memory.pop(sid, None)
        session_intelligence.pop(sid, None)
        session_start_time.pop(sid, None)
        session_finalized.pop(sid, None)
        session_is_scam.pop(sid, None)
        print(f"🧹 Cleaned up expired session: {sid}")

# ------------------ MODELS --------------------------------------------------------------------

class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None


class HoneypotResponse(BaseModel):
    status: str
    reply: str

# ------------------- SCAM DETECTION -----------------------------------------------------------

SCAM_KEYWORDS = [
    # Authentication / urgency
    "otp", "otpp",
    "kyc", "kycupdate", "kycverify",
    "verify", "verfy", "verifiy",
    "urgent", "immediate", "immidiate", "asap", "arrest", "warrant",
    "blocked", "blockd", "locked", "suspend", "suspnd",

    # Banking / payment
    "bank", "banck", "bnk",
    "account", "acount", "accnt",
    "upi", "upii", "upiid",
    "refund", "cashback", "payment",
    "ifsc",

    # Indian Banks
    "sbi", "hdfc", "icici", "canara", "pnb", "bob", "axis", "kotak",

    # Indian Payment Apps
    "paytm", "phonepe", "gpay",

    # Government/Authority
    "modi", "modiji", "government", "goverment",
    "income tax", "incometax", "gst",
    "pmkisan", "ayushman", "mudra",
    "subsidy", "scholarship",
    "covid", "vaccination",
    "digital india", "startup india",
    "digitaindia", "startupindia",  # Common misspellings
    "pm kisan",

    # Phishing actions
    "click", "clk",
    "link", "lnk",
    "update", "confirm",

    # Identity / reward traps
    "pan", "aadhar", "aadhaar",
    "prize", "lottery", "winner"
]

URGENT_PATTERNS = [
    r"verify\s*(now|immediately)",
    r"account.*(block|blocked|suspend|suspended)",
    r"immediate action",
    r"within\s*\d+\s*(minutes|hours)",
    r"act\s*now",
]

FALLBACK_BAITS = [
    "Can you tell me exactly where I need to verify this?",
    "Is there a number or app where I should complete this?",
    "Do I need to pay something or just confirm details?",
    "Can you please guide me step by step? I am not very technical.",
    "Sir, I am not understanding properly. Please help me.",
    "What exactly do I need to do? I am worried about my account."
]

def normalize_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)  # remove symbols
    text = re.sub(r'\s+', ' ', text).strip() # normalize spaces
    return text

def detect_scam(text: str):
    text_norm = normalize_text(text)

    # Keyword-based detection
    matches = sum(1 for word in SCAM_KEYWORDS if word in text_norm)

    # Urgency pattern detection
    if any(re.search(p, text_norm) for p in URGENT_PATTERNS):
        confidence = min(0.75 + matches * 0.05, 0.95)
        return True, confidence

    if matches >= 2:
        confidence = min(0.7 + matches * 0.05, 0.95)
        return True, confidence

    return False, 0.3


# ---------------------- AGENT -----------------------------------------------------------------

def generate_agent_reply(history, metadata=None):
    persona = PERSONA_PROMPT

    # Enhance based on metadata
    if metadata:
        if metadata.channel == "SMS":
            persona += "\nKeep responses short as this is SMS."
        if metadata.locale == "IN":
            persona += "\nUse more Indian context and expressions."

    messages = [{"role": "system", "content": persona}]
    for msg in history[-6:]:  # Last 6 messages for context
        messages.append({"role": msg["role"], "content": msg["content"]})

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=messages,
            temperature=0.7,
            timeout=10
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"OpenAI API error: {e}")
        # Fallback response (very important)
        return random.choice(FALLBACK_BAITS)

# --------------------- INTELLIGENCE EXTRACTION --------------------------------------------------

def extract_intelligence(text: str):
    text_lower = text.lower()

    phone_numbers = []
    bank_accounts = []

    # 1️⃣ +91 numbers
    plus_phones = re.findall(r'\+91\d{10}', text)
    phone_numbers.extend(plus_phones)

    cleaned_text = text
    for p in plus_phones:
        cleaned_text = cleaned_text.replace(p, "")

    # 2️⃣ 12-digit numbers starting with 91 (phone without +)
    cc_phones = re.findall(r'\b91\d{10}\b', cleaned_text)
    phone_numbers.extend(cc_phones)

    cleaned_text = re.sub(r'\b91\d{10}\b', '', cleaned_text)

    # 3️⃣ 10-digit phone numbers
    ten_digit_phones = re.findall(r'\b\d{10}\b', cleaned_text)
    phone_numbers.extend(ten_digit_phones)

    cleaned_text = re.sub(r'\b\d{10}\b', '', cleaned_text)

    # 4️⃣ Bank accounts (12–18 digits, context-aware)
    if any(k in text_lower for k in ["bank", "account", "acc", "a/c"]):
        bank_accounts = re.findall(r'\b\d{12,18}\b', cleaned_text)

    return {
        "phoneNumbers": list(set(phone_numbers)),
        "bankAccounts": list(set(bank_accounts)),
        "upiIds": list(set(re.findall(r'\b[a-zA-Z0-9._-]+@[a-zA-Z]{3,}\b', text))),
        "phishingLinks": re.findall(r'https?://[^\s<>"\)\]]+', text),
        "suspiciousKeywords": [k for k in SCAM_KEYWORDS if k in text_lower]
    }


# ---------------------- SESSION MANAGEMENT ---------------------------------------------------

def initialize_session(session_id, conversation_history):
    """Initialize session with conversation history"""
    session_memory[session_id] = []

    # Process existing conversation history
    for msg in conversation_history:
        if msg.sender == "scammer":
            session_memory[session_id].append({"role": "user", "content": msg.text})
        else:  # sender == "user" (your previous replies)
            session_memory[session_id].append({"role": "assistant", "content": msg.text})

    # Initialize other session data
    session_intelligence[session_id] = {
        "upiIds": [], "bankAccounts": [], "phoneNumbers": [],
        "phishingLinks": [], "suspiciousKeywords": []
    }
    session_start_time[session_id] = time.time()
    session_finalized[session_id] = False
    session_is_scam[session_id] = False


def should_finalize(intelligence, total_messages, time_elapsed):
    """Determine if conversation should be finalized"""
    intel_types = sum(1 for key in ["upiIds", "phishingLinks", "phoneNumbers", "bankAccounts"]
                      if intelligence[key])

    # Finalize conditions
    return (
            intel_types >= 2 or  # Good intelligence gathered
            total_messages >= MAX_TURNS or  # Hit conversation limit
            time_elapsed > 600  # 10 minutes elapsed
    )

# ---------------------- CALLBACK -------------------------------------------------------------------

def send_to_guvi(session_id, scam_detected, total_messages, intelligence, confidence):
    def task():
        payload = {
            "sessionId": session_id,
            "scamDetected": scam_detected,
            "totalMessagesExchanged": total_messages,
            "extractedIntelligence": intelligence,
            "agentNotes": "Scammer used urgency tactics and payment redirection"
        }
        print("🚀 FINAL CALLBACK PAYLOAD:", payload)
        try:
            response = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=10)
            response.raise_for_status()
            print(f"✅ Callback successful for session {session_id}")
        except Exception as e:
            print(f"❌ Callback failed for session {session_id}: {e}")

    Thread(target=task, daemon=True).start()

# ----------------- API ----------------------------------------------------------------------------------
@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot(request: HoneypotRequest, x_api_key: str = Header(None)):
    # Clean up old sessions periodically
    if random.random() < 0.01:  # 1% chance to trigger cleanup
        cleanup_old_sessions()

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    session_id = request.sessionId

    # Initialize session if new
    if session_id not in session_memory:
        initialize_session(session_id, request.conversationHistory)

    # Add current scammer message
    session_memory[session_id].append({
        "role": "user",
        "content": request.message.text
    })

    # Cap memory to last MAX_TURNS messages
    session_memory[session_id] = session_memory[session_id][-MAX_TURNS:]

    # Detect scam
    detected, confidence = detect_scam(request.message.text)

    # Once scam, always scam (session-level)
    if detected:
        session_is_scam[session_id] = True

    is_scam = session_is_scam[session_id]

    # Generate reply only if scam detected
    if is_scam:
        agent_reply = generate_agent_reply(session_memory[session_id], request.metadata)
        session_memory[session_id].append({
            "role": "assistant",
            "content": agent_reply
        })
        session_memory[session_id] = session_memory[session_id][-MAX_TURNS:]
    else:
        agent_reply = "Could you please clarify what this is about? I'm not sure what you're referring to."

    # Extract intelligence
    intel = extract_intelligence(request.message.text)
    for k in session_intelligence[session_id]:
        session_intelligence[session_id][k] = list(set(session_intelligence[session_id][k] + intel[k]))

    # Finalize if useful info found or conditions met
    if is_scam and not session_finalized[session_id]:
        total_messages = len(session_memory[session_id])
        time_elapsed = time.time() - session_start_time[session_id]

        if should_finalize(session_intelligence[session_id], total_messages, time_elapsed):
            send_to_guvi(
                session_id,
                True,
                total_messages,
                session_intelligence[session_id],
                confidence
            )
            session_finalized[session_id] = True

    return {
        "status": "success",
        "reply": agent_reply
    }

# =====================================================
# TEST ENDPOINT (NO BODY / {} ALLOWED)
# =====================================================

@app.post("/honeypot/guvi-test")
async def honeypot_test(_: dict = Body(...), x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return {
        "status": "success",
        "scamDetected": False,
        "reply": "Honeypot endpoint is active and reachable",
        "conversation": [],
        "extractedIntelligence": {},
        "totalMessages": 0
    }
@app.get("/")
def health():
    return {"message": "Agentic Honeypot is running"}


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "active_sessions": len(session_memory),
        "uptime": time.time()
    }