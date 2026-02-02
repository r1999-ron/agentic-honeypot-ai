import os
import random
import re
import requests
import time
from threading import Thread
from typing import List, Optional

from fastapi import FastAPI, Header, HTTPException, Body
from fastapi import Request
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from fastapi.responses import JSONResponse
from openai import OpenAI
from pydantic import BaseModel

API_KEY = "sk_test_123456789"
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
OPENAI_MODEL = "gpt-4o-mini"
MAX_TURNS = 10  # safety cap

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
session_last_intel_snapshot = {}

# ------------------ MODELS --------------------------------------------------------------------

class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class Metadata(BaseModel):
    channel: Optional[str]
    language: Optional[str]
    locale: Optional[str]


class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata]


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
    "Can you please guide me step by step? I am not very technical."
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

def generate_agent_reply(history):
    messages = [{"role": "system", "content": PERSONA_PROMPT}]
    for msg in history[-6:]:
        messages.append({"role": msg["role"], "content": msg["content"]})
    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=messages,
            temperature=0.7,
            timeout=5
        )
        return response.choices[0].message.content
    except Exception:
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
        "upiIds": list(set(re.findall(r'\b[a-z0-9.\-_]{2,}@[a-z]{2,}\b', text))),
        "phishingLinks": re.findall(r'https?://[^\s<>"\)\]]+', text),
        "suspiciousKeywords": [k for k in SCAM_KEYWORDS if k in text_lower]
    }

# ---------------------- CALLBACK -------------------------------------------------------------------

def send_to_guvi(session_id, scam_detected, total_messages, intelligence, confidence):
    def task():
        payload = {
            "sessionId": session_id,
            "scamDetected": scam_detected,
            "totalMessagesExchanged": total_messages,
            "extractedIntelligence": intelligence,
            "agentNotes": f"Scammer used urgency tactics and payment redirection. Detection confidence: {confidence}"
        }
        print("🚀 FINAL CALLBACK PAYLOAD:", payload)
        try:
            requests.post(GUVI_CALLBACK_URL, json=payload, timeout=3)
        except Exception as e:
            print("Callback failed:", e)

    Thread(target=task, daemon=True).start()

# ----------------- API ----------------------------------------------------------------------------------

@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot(request: HoneypotRequest, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    session_id = request.sessionId

    if session_id not in session_memory:
        session_memory[session_id] = [
            {
                "role": "assistant" if m.sender == "user" else "user",
                "content": m.text
            }
            for m in request.conversationHistory
        ]
        session_intelligence[session_id] = {
            "upiIds": [], "bankAccounts": [], "phoneNumbers": [],
            "phishingLinks": [], "suspiciousKeywords": []
        }
        session_start_time[session_id] = time.time()
        session_finalized[session_id] = False
        session_is_scam[session_id] = False
        session_last_intel_snapshot[session_id] = set()

    # Add scammer message
    session_memory[session_id].append({
        "role" : "user",
        "content": request.message.text
    })

    # Cap memory to last 10 messages
    session_memory[session_id] = session_memory[session_id][-MAX_TURNS:]

    detected, confidence = detect_scam(request.message.text)

    # Once scam, always scam (session-level)
    if detected:
        session_is_scam[session_id] = True

    is_scam = session_is_scam[session_id]

    # Agent reply
    if is_scam:
        agent_reply = generate_agent_reply(session_memory[session_id])
        session_memory[session_id].append({
            "role": "assistant",
            "content": agent_reply
        })
        session_memory[session_id] = session_memory[session_id][-MAX_TURNS:]
    else:
        agent_reply = "Okay, noted."

    # Extract intelligence
    intel = extract_intelligence(request.message.text)
    for k in session_intelligence[session_id]:
        session_intelligence[session_id][k] = list(set(session_intelligence[session_id][k] + intel[k]))

    # detect intel stability
    snapshot = set()

    for k in ["upiIds", "phishingLinks", "phoneNumbers", "bankAccounts"]:
        for v in session_intelligence[session_id][k]:
            snapshot.add(f"{k}:{v}")

    new_intel = snapshot != session_last_intel_snapshot[session_id]
    session_last_intel_snapshot[session_id] = snapshot

    # Finalize if useful info found
    if is_scam and not session_finalized[session_id]:
        score = sum(bool(session_intelligence[session_id][k]) for k in ["upiIds","phishingLinks","phoneNumbers","bankAccounts"])
        total = len(session_memory[session_id])

        if (score >= 2 and not new_intel) or total >= MAX_TURNS:
            send_to_guvi(
                session_id,
                True,
                total,
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

# API test point
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
    return {"message" : "Agentic Honeypot is running"}