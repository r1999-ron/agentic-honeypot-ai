from threading import Thread
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import time, os, re, requests
from openai import OpenAI
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from fastapi import Request

API_KEY = "sk_test_123456789"
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
OPENAI_MODEL = "gpt-4o-mini"

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

# ------------------APP--------------------------------

app = FastAPI(title="Agentic Honeypot API")


# ----------- ERROR HANDLING --------------------------

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

# ----------------MEMORY----------------------------------

session_memory = {}
session_intelligence = {}
session_start_time = {}
session_finalized = {}

# ------------------MODELS--------------------------------------

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
    conversationHistory: List[Message]
    metadata: Optional[Metadata]


class HoneypotResponse(BaseModel):
    status: str
    scamDetected: bool
    reply: str
    conversation: list
    extractedIntelligence: dict
    totalMessages: int

# -------------------SCAM DETECTION -----------------------------------------

SCAM_KEYWORDS = [
    # Authentication / urgency
    "otp", "otpp",
    "kyc", "kycupdate", "kycverify",
    "verify", "verfy", "verifiy",
    "urgent", "immediate", "immidiate", "asap",
    "blocked", "blockd", "locked", "suspend", "suspnd",

    # Banking / payment
    "bank", "banck", "bnk",
    "account", "acount", "accnt",
    "upi", "upii", "upiid",
    "refund", "cashback",

    # Phishing actions
    "click", "clk",
    "link", "lnk",
    "update", "confirm",

    # Identity / reward traps
    "pan", "aadhar", "aadhaar",
    "prize", "lottery", "winner"
]

def normalize_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)  # remove symbols
    text = re.sub(r'\s+', ' ', text).strip() # normalize spaces
    return text

def detect_scam(text: str):
    text_norm = normalize_text(text)

    matches = sum(1 for word in SCAM_KEYWORDS if word in text_norm)

    if matches >= 2:
        confidence = min(0.7 + matches * 0.05, 0.95)
        return True, confidence

    return False, 0.3


# ---------------------- AGENT---------------------------------------------------

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
        return "I am a bit confused. Can you please explain once again?"

# --------------------- INTELLIGENCE EXTRACTION ----------------------------------------

def extract_intelligence(text):
    return{
        "upiIds": re.findall(r'[\w\.-]+@[\w]+', text),
        "bankAccounts": re.findall(r'\b\d{9,18}\b', text),
        "phoneNumbers": re.findall(r'\+?\d{10,13}', text),
        "phishingLinks": re.findall(r'https?://\S+', text),
        "suspiciousKeywords": [k for k in SCAM_KEYWORDS if k in normalize_text(text)]
    }

# ---------------------- CALLBACK -------------------------------------------------------

def send_to_guvi(session_id, scam_detected, total_messages, intelligence):
    def task():
        payload = {
            "sessionId": session_id,
            "scamDetected": scam_detected,
            "totalMessagesExchanged": total_messages,
            "extractedIntelligence": intelligence,
            "agentNotes": "Scammer used urgency and payment redirection tactics."
        }
        try:
            requests.post(GUVI_CALLBACK_URL, json=payload, timeout=3)
        except Exception as e:
            print("Callback failed:", e)

    Thread(target=task, daemon=True).start()

# ----------------- API -----------------

@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot(request: HoneypotRequest, x_api_key: str = Header(None)):

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if request is None or request.message is None:
        return {
            "status": "success",
            "scamDetected": False,
            "reply": "Honeypot endpoint is active",
            "conversation": [],
            "extractedIntelligence": {},
            "totalMessages": 0
        }

    session_id = request.sessionId

    if session_id not in session_memory:
        session_memory[session_id] = [{"role": "user", "content": m.text}
        for m in request.conversationHistory]
        session_intelligence[session_id] = {
            "upiIds": [], "bankAccounts": [], "phoneNumbers": [],
            "phishingLinks": [], "suspiciousKeywords": []
        }
        session_start_time[session_id] = time.time()
        session_finalized[session_id] = False

    # Add scammer message
    session_memory[session_id].append({
        "role" : "user",
        "content": request.message.text
    })

    # Cap memory to last 10 messages
    session_memory[session_id] = session_memory[session_id][-10:]

    is_scam , _ = detect_scam(request.message.text)

    # Agent reply
    if is_scam:
        agent_reply = generate_agent_reply(session_memory[session_id])
        session_memory[session_id].append({
            "role": "assistant",
            "content": agent_reply
        })
        session_memory[session_id] = session_memory[session_id][-10:]
    else:
        agent_reply = "Okay, noted."

    # Extract intelligence
    new_intel = extract_intelligence(request.message.text)
    for key in session_intelligence[session_id]:
        session_intelligence[session_id][key].extend(new_intel[key])
        session_intelligence[session_id][key] = list(set(session_intelligence[session_id][key]))

    # Finalize if useful info found
    if (is_scam and not session_finalized[session_id] and (session_intelligence[session_id]["upiIds"] or session_intelligence[session_id]["phishingLinks"])):
        total_messages = len(session_memory[session_id])
        send_to_guvi(
            session_id,
            is_scam,
            total_messages,
            session_intelligence[session_id]
        )
        session_finalized[session_id] = True

    return {
        "status": "success",
        "scamDetected": is_scam,
        "reply": agent_reply,
        "conversation": session_memory[session_id],
        "extractedIntelligence": session_intelligence[session_id],
        "totalMessages": len(session_memory[session_id])
    }

@app.get("/")
def health():
    return {"message" : "Agentic Honeypot is running"}