# agentic-honeypot-ai

# 🕵️‍♂️ Agentic Honeypot for Scam Detection & Intelligence Extraction

An AI-powered agentic honeypot system that detects scam intent, autonomously engages scammers in realistic multi-turn conversations, extracts actionable fraud intelligence, and reports final results to the GUVI evaluation endpoint.

# 🚀 Problem Overview

Online scams (UPI fraud, bank impersonation, phishing, fake offers) are increasingly adaptive.
Static rule-based detection systems fail because scammers change tactics dynamically.

This project implements an Agentic Honeypot that:

Detects scam intent early

Engages scammers autonomously using a believable human persona

Handles multi-turn conversations

Extracts intelligence such as:

UPI IDs

Phone numbers

Bank account numbers

Phishing links

Sends a mandatory final callback to GUVI once engagement completes

# 🧠 Core Design Principles
1️⃣ Session-Level Scam Detection

Scam intent is tracked per session, not per message.

Once a message is flagged as scam:

The entire conversation is treated as scam-related

The agent remains active for all subsequent turns

Prevents false passive responses mid-conversation

2️⃣ Agentic Engagement

The system activates an AI agent that:

Behaves like a normal Indian user

Is polite, slightly confused, and non-technical

Never reveals detection

Uses realistic follow-ups to bait intelligence

Self-corrects when needed

3️⃣ Incremental Intelligence Extraction

Each incoming message is analyzed to extract:

upiIds

phoneNumbers

bankAccounts

phishingLinks

suspiciousKeywords

Intelligence is accumulated across turns.

4️⃣ Intelligent Finalization Logic

The conversation ends only when:

At least 2 high-value intelligence types are collected AND

No new intelligence appears
OR

A safe maximum turn limit is reached

This ensures:

Maximum intelligence extraction

No infinite conversations

Fair and stable evaluation

# 🏗️ System Architecture (High Level)
Incoming Message
      ↓
Scam Detection (keywords + urgency patterns)
      ↓
Session-Level Scam Tracking
      ↓
Agentic AI Engagement
      ↓
Incremental Intelligence Extraction
      ↓
Stability Check / Safety Cap
      ↓
Final Callback to GUVI

# 🔐 API Authentication

All endpoints require an API key:

x-api-key: sk_test_123456789

# 📡 API Endpoints
POST /honeypot

Handles one incoming message in a conversation.

Request Body
{
  "sessionId": "session-1001",
  "message": {
    "sender": "scammer",
    "text": "Verify immediately or your account will be blocked",
    "timestamp": "2026-01-21T10:15:30Z"
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}

Response
{
  "status": "success",
  "reply": "Can you please guide me on how to verify this?"
}

POST /honeypot/test

Health test endpoint.

GET /

Basic service health check.

# 🧠 Scam Detection Strategy

Scam detection uses a hybrid approach:

✔ Keyword Matching

Detects common scam indicators:

bank, account, upi, verify, blocked, payment, etc.

✔ Urgency Pattern Detection

Triggers early detection for phrases like:

“verify immediately”

“account will be blocked”

“within 10 minutes”

“act now”

✔ Confidence Scoring

Each detection returns:

isScam → true / false

confidence → 0.3 – 0.95

# 🧪 End-to-End Testing (Swagger)

Run the server:

uvicorn main:app --reload


Open:

http://127.0.0.1:8000/docs


Simulate a real scam flow:

Urgency message

UPI payment request

Phishing link

Phone number

Bank account (optional)

Final filler message

Observe:

Agent replies naturally

Intelligence accumulates

Final callback fires once

# 📤 Mandatory GUVI Final Callback

Once engagement completes, the system sends:

{
  "sessionId": "session-1001",
  "scamDetected": true,
  "totalMessagesExchanged": 8,
  "extractedIntelligence": {
    "upiIds": ["bankhelp@upi"],
    "phoneNumbers": ["+919876543210"],
    "phishingLinks": ["https://secure-bank-verify.example/login"],
    "bankAccounts": ["123456789012"],
    "suspiciousKeywords": ["verify", "blocked", "urgent"]
  },
  "agentNotes": "Scammer used urgency tactics and payment redirection"
}


📌 This callback is sent exactly once per session, as required.

# 🛡️ Safety & Ethics

❌ No impersonation of real individuals

❌ No illegal instructions

❌ No harassment

✅ Responsible data handling

✅ Conversation limits enforced

⚙️ Configuration
MAX_TURNS = 10  # Safety cap
OPENAI_MODEL = "gpt-4o-mini"

🏁 Final Summary

This project demonstrates an AI-powered agentic honeypot capable of detecting scam intent, engaging scammers in realistic conversations, extracting high-value fraud intelligence, and reporting results reliably and ethically.
