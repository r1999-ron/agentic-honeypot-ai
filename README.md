# 🍯 Honeypot API v2

An agentic scam detection and intelligence extraction system that engages scammers in realistic conversation, extracts contact intelligence, and produces structured fraud reports.

## Strategy

The honeypot acts as a confused, worried Indian user who:
1. **Keeps scammers engaged** with turn-by-turn questioning tactics (8–10 turns)
2. **Identifies red flags** in real time (urgency, OTP requests, impersonation, phishing links)
3. **Elicits intelligence** by asking for employee IDs, UPI IDs, callback numbers, and case references
4. **Classifies scam type** (bank fraud, UPI fraud, phishing, tax scam, lottery, etc.)

## Architecture

```
src/
├── main.py          # FastAPI app — routes, auth, orchestration
├── detection.py     # Multi-signal scam detection engine
├── intelligence.py  # Regex-based entity extraction (phone, UPI, links, etc.)
├── agent.py         # LLM-powered persona and conversation generation
└── session.py       # Per-session state management
```

### Why Modular?

Each concern is isolated and independently testable:
- **`detection.py`**: Scam scoring with hard keywords, soft signals, urgent patterns, phishing patterns — returns `(is_scam, confidence, red_flags)`
- **`intelligence.py`**: Extracts 8 intelligence types: phone numbers, bank accounts, UPI IDs, links, emails, case IDs, policy numbers, order numbers
- **`agent.py`**: LLM agent with turn-aware tactics, red-flag-informed replies, and professional analyst note generation
- **`session.py`**: Clean session lifecycle, intelligence accumulation, finalization logic

## Tech Stack

- **Runtime**: Python 3.11+
- **Framework**: FastAPI + Uvicorn
- **LLM**: OpenAI GPT-4o-mini (via `openai` SDK)
- **Detection**: Multi-pattern regex + keyword scoring (no ML dependency)
- **State**: In-memory (per-process)

## Setup

```bash
# 1. Clone and enter
git clone https://github.com/YOUR_USERNAME/honeypot-api
cd honeypot-api

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env and set OPENAI_API_KEY

# 4. Run
cd src
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## API Endpoint

**POST** `/honeypot`

**Headers:**
```
Content-Type: application/json
x-api-key: your-api-key  (optional)
```

**Request:**
```json
{
  "sessionId": "abc-123",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your SBI account will be blocked. Share OTP immediately.",
    "timestamp": "2025-01-01T10:00:00Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response (mid-conversation):**
```json
{
  "status": "success",
  "reply": "Sir I am very worried now. You are saying OTP but my bank always says never share OTP with anyone, even bank staff. Can you tell me your official employee ID so I can verify? And what is your official callback number?"
}
```

**Response (final output, appended when session completes):**
```json
{
  "status": "success",
  "reply": "...",
  "sessionId": "abc-123",
  "scamDetected": true,
  "scamType": "bank_fraud",
  "confidenceLevel": 0.87,
  "totalMessagesExchanged": 16,
  "engagementDurationSeconds": 142,
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": ["123456789012"],
    "upiIds": ["fraud@oksbi"],
    "phishingLinks": ["http://fake-sbi-kyc.xyz/update"],
    "emailAddresses": ["support@fake-sbi.com"],
    "caseIds": ["SBI-90123"],
    "policyNumbers": [],
    "orderNumbers": []
  },
  "redFlagsIdentified": [
    "Requesting OTP/PIN/password — definitive scam signal",
    "Urgency/pressure tactics detected",
    "Government/authority impersonation"
  ],
  "agentNotes": "This is a bank impersonation scam where the caller falsely claimed to be from SBI fraud department..."
}
```

## Scam Detection Logic

Detection uses three layers:

| Layer | Signal | Score Contribution |
|-------|--------|-------------------|
| Hard keywords | OTP, KYC, arrest, warrant, prize | +0.15 per hit (max 4) |
| Soft keywords | bank, UPI, verify, refund | +0.10 per 2+ hits |
| Urgent patterns | "account will be blocked", "act now" | +0.25 |
| Phishing patterns | URLs, lookalike brands, shorteners | +0.30–0.40 |
| OTP/PIN request | "share OTP", "send PIN" | +0.40 (definitive) |
| Authority impersonation | RBI, police, income tax | +0.20 |

## Intelligence Extraction

Extracts using targeted regex per type:

| Type | Example |
|------|---------|
| Phone Numbers | `+91-9876543210`, `9876543210` |
| Bank Accounts | 9–18 digit account numbers |
| UPI IDs | `fraud@oksbi`, `scam@ybl`, `abc@paytm` |
| Phishing Links | `https://...`, suspicious TLD domains |
| Email Addresses | Standard email format |
| Case IDs | `CASE-12345`, `SBI-90123`, `REF-001` |
| Policy Numbers | `POL123456`, `LIC-789012` |
| Order Numbers | `ORD-ABC123`, Amazon `123-4567890-1234567` |

## Conversation Strategy

Turn-by-turn question tactics ensure maximum engagement and scoring:

| Turn | Focus |
|------|-------|
| 1–2 | Identity verification (employee ID, department) |
| 3–4 | Callback number, official website |
| 5–6 | Case reference number, supervisor name |
| 7–8 | Payment details (UPI ID, account), ask to resend link |
| 9–10 | Branch address, written confirmation request |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | ✅ Yes | — | OpenAI API key |
| `API_KEY` | No | `""` (open) | Honeypot authentication key |
| `OPENAI_MODEL` | No | `gpt-4o-mini` | Model to use |
| `MAX_TURNS` | No | `10` | Max conversation turns |
| `PORT` | No | `8000` | Server port |

## Security Notes

- API keys loaded from environment variables only
- `.env` is in `.gitignore` — never commit secrets
- Authentication fails gracefully without revealing honeypot nature