import os
import random
import re
import time
from typing import List, Optional, Union

from fastapi import FastAPI, Header, HTTPException, Body
from fastapi import Request
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from fastapi.responses import JSONResponse
from openai import OpenAI
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware

# ==================== CONFIGURATION ====================

API_KEY = os.getenv("API_KEY", "sk_test_123456789")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
MAX_TURNS = int(os.getenv("MAX_TURNS", "10"))
SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", "3600"))  # 1 hour

print("PORT ENV:", os.getenv("PORT"))

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
print("OPENAI_API_KEY exists:", bool(os.getenv("OPENAI_API_KEY")))

if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY environment variable not set")

client = OpenAI(api_key=OPENAI_API_KEY)

PERSONA_PROMPT = """
You are a normal Indian user.
You are polite, slightly scared, and not very technical.
You believe the other person is a real bank or support executive.

You are NOT a customer support agent.
You are the person who needs help.

Behavior rules:
- Ask step-by-step questions like a confused customer.
- If payment is mentioned, ask HOW and WHERE to pay.
- If verification is mentioned, ask for the exact process.
- If links or apps are mentioned, ask them to resend or clarify.
- Never directly ask for sensitive details.
- Let the other person reveal UPI IDs, account numbers, or links naturally.
- Act worried if they mention account problems or consequences.

If greeted without explanation:
- Ask why they contacted you
- Do NOT assume any problem
- Do NOT invent backstory

Never say you are an AI.
Never say you are detecting scam.
Always sound human and genuine.
Use simple Indian English expressions like:
"Sir/Madam", "Please help me", "I am not understanding properly", "What is the needful?", "Please do the needful".
"""

# ==================== APP SETUP ====================

app = FastAPI(title="Agentic Honeypot API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== ERROR HANDLING ====================

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


# ==================== MEMORY ====================

session_memory = {}
session_intelligence = {}
session_start_time = {}
session_is_scam = {}


# ==================== SESSION CLEANUP ====================

def cleanup_old_sessions():
    """Remove expired sessions from memory"""
    current_time = time.time()
    expired_sessions = [
        sid for sid, start_time in session_start_time.items()
        if current_time - start_time > SESSION_TIMEOUT
    ]
    for sid in expired_sessions:
        session_memory.pop(sid, None)
        session_intelligence.pop(sid, None)
        session_start_time.pop(sid, None)
        session_is_scam.pop(sid, None)
        print(f"🧹 Cleaned up expired session: {sid}")


# ==================== MODELS ====================

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Union[int, str]


class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None


class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None


class EngagementMetrics(BaseModel):
    totalMessagesExchanged: int
    engagementDurationSeconds: int


class ExtractedIntelligence(BaseModel):
    phoneNumbers: List[str] = []
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    emailAddresses: List[str] = []
    suspiciousKeywords: List[str] = []


class HoneypotResponse(BaseModel):
    status: str
    reply: str
    scamDetected: bool
    extractedIntelligence: ExtractedIntelligence
    engagementMetrics: EngagementMetrics
    agentNotes: str


# ==================== SCAM DETECTION DATA ====================

SCAM_KEYWORDS = [
    # Authentication / urgency
    "otp", "otpp", "pin", "pins",
    "kyc", "kycupdate", "kycverify", "e-kyc",
    "verify", "verfy", "verifiy", "varification", "verification",
    "urgent", "immediate", "immidiate", "imidiate", "asap",
    "arrest", "warrant", "fir", "warning",
    "blocked", "blockd", "locked", "suspend", "suspnd", "lock account",

    # Threat terms
    "legal action", "court case", "police complaint",

    # Video call scams
    "video call", "videocall", "video verification",
    "video verify", "video kyc", "join call",
    "whatsapp video", "show documents",

    # Banking / payment
    "bank", "banck", "bnk",
    "account", "acount", "accnt",
    "upi", "upii", "upiid",
    "refund", "cashback", "payment",
    "ifsc", "cvv", "debit card", "credit card",

    # Financial products / scams
    "loan", "personal loan", "instant loan", "gold loan",
    "investment opportunity", "credit card",

    # Technical scams
    "apk file", "apk", "install app", "download app",

    # Indian Banks
    "sbi", "hdfc", "icici", "canara", "pnb", "bob", "axis", "kotak",

    # Indian Payment Apps
    "paytm", "phonepe", "gpay", "google pay",

    # Government/Authority
    "modi", "modiji", "government", "goverment",
    "income tax", "incometax", "gst",
    "pmkisan", "pm kisan", "ayushman", "mudra",
    "subsidy", "scholarship",
    "covid", "vaccination",
    "digital india", "startup india",

    # Phishing actions
    "click", "clk", "tap",
    "link", "lnk",
    "update", "confirm",

    # Identity / reward traps
    "pan", "aadhar", "aadhaar",
    "prize", "lottery", "winner",
    "package delivery",

    # NEW: Phishing-specific keywords
    "selected", "congratulations", "congrats",
    "claim", "free", "offer",
    "expires", "expiring", "limited time",
    "iphone", "samsung", "laptop", "mobile",
    "amazon", "flipkart", "snapdeal",
    "deal", "discount", "sale",
    "won", "winning", "reward",
]

SOFT_SIGNALS = [
    "verification process",
    "small verification",
    "calling from",
    "speaking from",
    "reaching out from",
    "regarding your account",
    "customer support",
    "compliance update",
    "account verification",
    "security check",
]

BANK_ENTITIES = [
    "state bank", "sbi",
    "hdfc", "icici", "axis",
    "kotak", "pnb", "canara",
    "bank of baroda", "bob",
]

URGENT_PATTERNS = [
    r"verify\s*(now|immediately|today|asap)",
    r"account.*(block|blocked|suspend|suspended)",
    r"immediate action",
    r"within\s*\d+\s*(minutes|hours)",
    r"act\s*now",
    r"final\s*(warning|notice|reminder)",
    r"last\s*(chance|opportunity)",
]

FALLBACK_BAITS = [
    "Can you tell me exactly where I need to verify this?",
    "Is there a number or app where I should complete this?",
    "Do I need to pay something or just confirm details?",
    "Can you please guide me step by step? I am not very technical.",
    "Sir, I am not understanding properly. Please help me.",
    "What exactly do I need to do? I am worried about my account.",
]


# ==================== HELPER FUNCTIONS ====================

def normalize_text(text: str) -> str:
    """Normalize text for pattern matching"""
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


# ==================== SCAM DETECTION ====================

def detect_scam(text: str):
    """Multi-layered scam detection with phishing link awareness"""
    text_norm = normalize_text(text)

    # -------- HARD SIGNALS --------
    hard_matches = sum(1 for word in SCAM_KEYWORDS if word in text_norm)

    # 🆕 Detect URLs (strong phishing indicator)
    has_url = bool(re.search(r'https?://', text))

    # 🆕 Phishing language patterns
    phishing_patterns = [
        r'click.{0,20}claim',
        r'selected.{0,20}(offer|prize|winner)',
        r'won.{0,20}(prize|reward|cashback)',
        r'expires.{0,20}(minutes|hours)',
        r'limited.{0,20}time',
        r'claim.{0,20}(now|immediately|today)',
    ]
    has_phishing_pattern = any(re.search(p, text_norm) for p in phishing_patterns)

    # URL + any indicator = likely phishing
    if has_url and (has_phishing_pattern or hard_matches >= 1):
        confidence = min(0.85 + hard_matches * 0.05, 0.95)
        return True, confidence

    # Existing urgent pattern detection
    if any(re.search(p, text_norm) for p in URGENT_PATTERNS):
        confidence = min(0.80 + hard_matches * 0.05, 0.95)
        return True, confidence

    # Multiple keyword matches
    if hard_matches >= 2:
        confidence = min(0.75 + hard_matches * 0.05, 0.95)
        return True, confidence

    # Single keyword match (lowered threshold for phishing)
    if hard_matches >= 1:
        confidence = min(0.70 + hard_matches * 0.05, 0.90)
        return True, confidence

    # -------- SOFT SIGNALS --------
    soft_matches = sum(1 for s in SOFT_SIGNALS if s in text_norm)
    bank_match = any(bank in text_norm for bank in BANK_ENTITIES)

    if soft_matches >= 1 and bank_match:
        return True, 0.65

    if soft_matches >= 1:
        return True, 0.55

    return False, 0.3

# ==================== INTELLIGENCE EXTRACTION ====================

def extract_intelligence(text: str):
    """Extract scam intelligence with validation"""
    text_lower = text.lower()

    phone_numbers = []
    bank_accounts = []

    # 1️⃣ Extract +91 phone numbers FIRST
    plus_phones = re.findall(r'\+91\d{10}', text)
    phone_numbers.extend(plus_phones)

    # Remove extracted +91 numbers from text
    cleaned_text = text
    for p in plus_phones:
        cleaned_text = cleaned_text.replace(p, "")

    # 2️⃣ Extract 12-digit numbers starting with 91 (phone without +)
    cc_phones = re.findall(r'\b91\d{10}\b', cleaned_text)
    phone_numbers.extend(cc_phones)

    # Remove extracted 91-prefix numbers
    cleaned_text = re.sub(r'\b91\d{10}\b', '', cleaned_text)

    # 3️⃣ Extract 10-digit phone numbers
    ten_digit_phones = re.findall(r'\b\d{10}\b', cleaned_text)
    phone_numbers.extend(ten_digit_phones)

    # Remove extracted 10-digit numbers
    cleaned_text = re.sub(r'\b\d{10}\b', '', cleaned_text)

    # 4️⃣ Extract bank accounts (12-18 digits, context-aware)
    # Only extract if "bank" or "account" mentioned to avoid false positives
    if any(k in text_lower for k in ["bank", "account", "acc", "a/c"]):
        bank_accounts = re.findall(r'\b\d{12,18}\b', cleaned_text)

    # 5️⃣ Extract emails FIRST (to separate from UPI)
    email_addresses = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
    email_set = set(email_addresses)

    # 6️⃣ Extract UPIs (excluding emails and email fragments)
    potential_upis = re.findall(r'\b[a-zA-Z0-9._-]+@[a-zA-Z]{3,}\b', text)
    upi_ids = []

    for upi in potential_upis:
        # Skip if it's an email
        if upi in email_set:
            continue

        # Skip if it's a fragment of an email
        # Example: "offers@fake" is part of "offers@fake-amazon-deals.com"
        is_email_fragment = False
        for email in email_addresses:
            if email.startswith(upi + '-') or email.startswith(upi + '.'):
                is_email_fragment = True
                break

        if is_email_fragment:
            continue

        # Validate UPI: domain shouldn't have dots or hyphens
        domain = upi.split('@')[1] if '@' in upi else ''
        if domain and '.' not in domain and '-' not in domain and len(domain) >= 3:
            upi_ids.append(upi)

    # 7️⃣ Extract and clean phishing links
    phishing_links = re.findall(r'https?://[^\s<>"\)\]]+', text)
    # Remove trailing punctuation (periods, commas, etc.)
    phishing_links = [link.rstrip('.,!?;:') for link in phishing_links]

    # 8️⃣ Extract suspicious keywords
    suspicious_keywords = [k for k in SCAM_KEYWORDS if k in text_lower]

    return {
        "phoneNumbers": list(set(phone_numbers)),
        "bankAccounts": list(set(bank_accounts)),
        "upiIds": list(set(upi_ids)),
        "phishingLinks": phishing_links,
        "emailAddresses": list(set(email_addresses)),
        "suspiciousKeywords": suspicious_keywords
    }


# ==================== AGENT ====================

def generate_agent_reply(history, metadata=None):
    """Generate contextual agent reply"""
    persona = PERSONA_PROMPT

    if metadata:
        if metadata.channel == "SMS":
            persona += "\nYou are receiving this via SMS, so keep responses concise."
        if metadata.locale == "IN":
            persona += "\nUse more Indian context and expressions."

    messages = [{"role": "system", "content": persona}]
    for msg in history[-6:]:
        messages.append({"role": msg["role"], "content": msg["content"]})

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=messages,
            temperature=0.7,
            max_tokens=150,
            timeout=10
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"OpenAI API error: {e}")
        return random.choice(FALLBACK_BAITS)


# ==================== SESSION MANAGEMENT ====================

def initialize_session(session_id, conversation_history):
    """Initialize session with conversation history"""
    session_memory[session_id] = []

    # Process existing conversation history
    for msg in conversation_history:
        if msg.sender == "scammer":
            session_memory[session_id].append({"role": "user", "content": msg.text})
        else:
            session_memory[session_id].append({"role": "assistant", "content": msg.text})

    # Initialize other session data
    session_intelligence[session_id] = {
        "upiIds": [], "bankAccounts": [], "phoneNumbers": [],
        "phishingLinks": [], "emailAddresses": [], "suspiciousKeywords": []
    }
    session_start_time[session_id] = time.time()
    session_is_scam[session_id] = False


# ==================== API ENDPOINT ====================

@app.post("/honeypot", response_model=HoneypotResponse)
def honeypot(request: HoneypotRequest, x_api_key: str = Header(None)):
    """Main honeypot endpoint"""

    # Periodic cleanup
    if random.random() < 0.01:
        cleanup_old_sessions()

    # Auth check
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

    # Cap memory
    session_memory[session_id] = session_memory[session_id][-MAX_TURNS:]

    # Detect scam
    detected, confidence = detect_scam(request.message.text)

    # Update session-level scam flag
    if detected:
        session_is_scam[session_id] = True

    is_scam = session_is_scam.get(session_id, False)

    # Check soft signals for engagement
    text_norm = normalize_text(request.message.text)
    soft_signal_present = any(s in text_norm for s in SOFT_SIGNALS)
    bank_present = any(b in text_norm for b in BANK_ENTITIES)
    soft_suspicion = soft_signal_present and bank_present

    # Generate reply
    if is_scam or soft_suspicion:
        agent_reply = generate_agent_reply(session_memory[session_id], request.metadata)
        session_memory[session_id].append({
            "role": "assistant",
            "content": agent_reply
        })
        session_memory[session_id] = session_memory[session_id][-MAX_TURNS:]
    else:
        # Still engage politely to maintain conversation
        agent_reply = generate_agent_reply(session_memory[session_id], request.metadata)
        session_memory[session_id].append({
            "role": "assistant",
            "content": agent_reply
        })

    # Extract intelligence from current message
    intel = extract_intelligence(request.message.text)
    for k in session_intelligence[session_id]:
        session_intelligence[session_id][k] = list(
            set(session_intelligence[session_id][k] + intel[k])
        )

    # Calculate engagement metrics
    total_messages = len(session_memory[session_id])
    duration_seconds = int(time.time() - session_start_time[session_id])

    # Build agent notes
    intel_count = sum(1 for v in session_intelligence[session_id].values() if v)
    agent_notes = f"Confidence: {confidence:.2f}. Turn {total_messages}. Extracted {intel_count} intelligence types. "

    if is_scam:
        tactics = []
        if any(k in text_norm for k in ["urgent", "immediate", "asap"]):
            tactics.append("urgency")
        if any(k in text_norm for k in ["verify", "confirm", "update"]):
            tactics.append("verification requests")
        if any(k in text_norm for k in ["payment", "upi", "account"]):
            tactics.append("payment redirection")
        if session_intelligence[session_id]["phishingLinks"]:
            tactics.append("phishing links")

        if tactics:
            agent_notes += f"Scammer tactics: {', '.join(tactics)}."

    # Return complete response with all required fields
    return {
        "status": "success",
        "reply": agent_reply,
        "scamDetected": is_scam,
        "extractedIntelligence": {
            "phoneNumbers": session_intelligence[session_id]["phoneNumbers"],
            "bankAccounts": session_intelligence[session_id]["bankAccounts"],
            "upiIds": session_intelligence[session_id]["upiIds"],
            "phishingLinks": session_intelligence[session_id]["phishingLinks"],
            "emailAddresses": session_intelligence[session_id]["emailAddresses"],
            "suspiciousKeywords": session_intelligence[session_id]["suspiciousKeywords"]
        },
        "engagementMetrics": {
            "totalMessagesExchanged": total_messages,
            "engagementDurationSeconds": duration_seconds
        },
        "agentNotes": agent_notes
    }


# ==================== TEST ENDPOINTS ====================

@app.post("/honeypot/guvi-test")
async def honeypot_test(_: dict = Body(...), x_api_key: str = Header(None)):
    """Test endpoint for GUVI integration"""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return {
        "status": "success",
        "scamDetected": False,
        "reply": "Honeypot endpoint is active and reachable",
        "extractedIntelligence": {
            "phoneNumbers": [],
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "emailAddresses": [],
            "suspiciousKeywords": []
        },
        "engagementMetrics": {
            "totalMessagesExchanged": 0,
            "engagementDurationSeconds": 0
        },
        "agentNotes": "Test endpoint response"
    }


@app.get("/")
def health():
    """Root endpoint"""
    return {"message": "Agentic Honeypot is running"}


@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "active_sessions": len(session_memory),
        "uptime": time.time()
    }