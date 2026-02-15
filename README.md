# 🕵️‍♂️ Agentic Honeypot for Scam Detection & Intelligence Extraction

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)

An AI-powered honeypot system that detects scam messages, engages scammers autonomously using natural conversation, and extracts actionable intelligence without revealing detection.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Setup Instructions](#setup-instructions)
- [API Documentation](#api-documentation)
- [Deployment](#deployment)
- [Testing](#testing)
- [Approach & Strategy](#approach--strategy)
- [Examples](#examples)

---

## 🎯 Overview

This honeypot system is designed to:
1. **Detect scam intent** using multi-layered pattern matching
2. **Engage scammers** with a believable Indian user persona powered by OpenAI GPT-4
3. **Extract intelligence** (phone numbers, UPI IDs, bank accounts, phishing links)
4. **Maintain engagement** across multiple conversation turns without revealing detection

### Key Innovation
- **Indian Context Optimization**: Specialized keywords, bank names, payment apps, government schemes
- **Sequential Intelligence Extraction**: Prevents false positives by extracting data in stages
- **Dynamic AI Persona**: Adapts responses based on extracted intelligence and conversation context

---

## ✨ Features

### 🔍 Scam Detection
- **Multi-layered detection**: Hard signals (urgent keywords), soft signals (bank + verification), pattern matching
- **Confidence scoring**: 0.3 to 0.95 based on signal strength
- **Indian-specific patterns**: Recognizes local banks, payment apps, government schemes

### 🤖 AI Agent
- **Natural conversation**: Powered by OpenAI GPT-4 with custom persona
- **Context-aware**: Remembers conversation history and adapts responses
- **Believable persona**: Acts as confused, non-technical Indian user
- **Fallback responses**: Continues engagement even if OpenAI API fails

### 📊 Intelligence Extraction
- **Phone numbers**: +91xxxxxxxxxx, 91xxxxxxxxxx, 10-digit formats
- **Bank accounts**: 12-18 digit numbers (context-aware)
- **UPI IDs**: username@bank format validation
- **Phishing links**: HTTP/HTTPS URLs
- **Email addresses**: Standard email format
- **Keywords**: Tracks scam-related terminology

### 🛡️ Production Features
- **Session management**: Tracks multiple concurrent conversations
- **Memory optimization**: Keeps last 10 messages per session
- **Auto-cleanup**: Expires sessions after 1 hour
- **Error handling**: Graceful fallbacks for API failures
- **CORS enabled**: Supports cross-origin requests

---

## 🔧 Tech Stack

### Backend
- **Framework**: FastAPI (Python 3.9+)
- **AI/LLM**: OpenAI GPT-4o-mini
- **Server**: Uvicorn (ASGI)

### Libraries
- `fastapi` - Web framework
- `openai` - GPT-4 integration
- `pydantic` - Data validation
- `requests` - HTTP client
- `uvicorn` - ASGI server
- `python-multipart` - Form data handling

### Infrastructure
- **Containerization**: Docker
- **Deployment**: Render/Railway/Heroku compatible
- **Environment**: Ubuntu-based containers

---

## 🏗️ Architecture
```
┌─────────────┐
│   Client    │ (GUVI Evaluation System)
└──────┬──────┘
       │ POST /honeypot
       ▼
┌─────────────────────────────────────┐
│        FastAPI Application          │
│  ┌───────────────────────────────┐  │
│  │   Scam Detection Engine       │  │
│  │  - Hard signals (keywords)    │  │
│  │  - Soft signals (patterns)    │  │
│  │  - Confidence scoring          │  │
│  └───────────────────────────────┘  │
│                │                     │
│                ▼                     │
│  ┌───────────────────────────────┐  │
│  │   Session Management          │  │
│  │  - Memory tracking            │  │
│  │  - History management         │  │
│  │  - Intelligence accumulation  │  │
│  └───────────────────────────────┘  │
│                │                     │
│                ▼                     │
│  ┌───────────────────────────────┐  │
│  │   AI Agent (OpenAI GPT-4)     │  │
│  │  - Custom persona             │  │
│  │  - Context-aware responses    │  │
│  │  - Fallback baits             │  │
│  └───────────────────────────────┘  │
│                │                     │
│                ▼                     │
│  ┌───────────────────────────────┐  │
│  │   Intelligence Extraction     │  │
│  │  - Sequential parsing         │  │
│  │  - Pattern matching           │  │
│  │  - Data validation            │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
       │
       ▼
┌─────────────┐
│   Response  │ (JSON with full intelligence)
└─────────────┘
```

---

## 🚀 Setup Instructions

### Prerequisites
- Python 3.9+
- OpenAI API key
- Docker (optional, for containerization)

### Local Development

1. **Clone the repository**
```bash
   git clone https://github.com/yourusername/honeypot-api.git
   cd honeypot-api
```

2. **Install dependencies**
```bash
   pip install -r requirements.txt
```

3. **Set environment variables**
```bash
   # Create .env file
   cp .env.example .env
   
   # Edit .env with your values
   OPENAI_API_KEY=sk-your-openai-api-key-here
   API_KEY=your-custom-api-key-for-authentication
   PORT=8000
   OPENAI_MODEL=gpt-4o-mini
   MAX_TURNS=10
   SESSION_TIMEOUT=3600
```

4. **Run the application**
```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

5. **Test the endpoint**
```bash
   curl http://localhost:8000/health
```

### Docker Deployment

1. **Build the image**
```bash
   docker build -t honeypot-api .
```

2. **Run the container**
```bash
   docker run -d \
     -p 8000:8000 \
     -e OPENAI_API_KEY=sk-your-key-here \
     -e API_KEY=your-auth-key \
     --name honeypot \
     honeypot-api
```

3. **Check logs**
```bash
   docker logs -f honeypot
```

---

## 📡 API Documentation

### Base URL
```
https://your-deployed-url.com
```

### Authentication
```
Headers:
  x-api-key: your-api-key-here
  Content-Type: application/json
```

### Endpoints

#### 1. Main Honeypot Endpoint

**POST** `/honeypot`

**Request Body:**
```json
{
  "sessionId": "uuid-v4-string",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your SBI account has been compromised...",
    "timestamp": "1234567890"
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "Previous message...",
      "timestamp": "1234567890"
    }
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Sir, I am worried. Can you please tell me why my account will be blocked?",
  "scamDetected": true,
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": [],
    "upiIds": [],
    "phishingLinks": ["http://fake-bank.com"],
    "emailAddresses": [],
    "suspiciousKeywords": ["urgent", "sbi", "account", "blocked"]
  },
  "engagementMetrics": {
    "totalMessagesExchanged": 2,
    "engagementDurationSeconds": 5
  },
  "agentNotes": "Confidence: 0.95. Turn 2. Extracted 1 intelligence types. Scammer tactics: urgency."
}
```

#### 2. Health Check

**GET** `/health`

**Response:**
```json
{
  "status": "healthy",
  "active_sessions": 12,
  "uptime": 1234567890.123
}
```

#### 3. Test Endpoint

**POST** `/honeypot/guvi-test`

Used to verify endpoint is reachable.

---

## 🌐 Deployment

### Render.com

1. Create new Web Service
2. Connect GitHub repository
3. Set environment variables:
   - `OPENAI_API_KEY`
   - `API_KEY`
4. Build command: `pip install -r requirements.txt`
5. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

### Railway.app

1. Create new project from GitHub
2. Add environment variables
3. Deploy automatically on push

### Heroku

1. Create Heroku app
2. Add buildpack: `heroku/python`
3. Set config vars
4. Deploy via Git or GitHub integration

---

## 🧪 Testing

### Manual Testing

**Test 1: Basic Scam Detection**
```bash
curl -X POST http://localhost:8000/honeypot \
  -H "x-api-key: sk_test_123456789" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-001",
    "message": {
      "sender": "scammer",
      "text": "URGENT! Your HDFC account will be blocked. Call 9876543210",
      "timestamp": "1234567890"
    },
    "conversationHistory": []
  }'
```

**Expected Result:**
- `scamDetected: true`
- `extractedIntelligence.phoneNumbers: ["9876543210"]`
- Confidence > 0.80

**Test 2: UPI Extraction**
```bash
curl -X POST http://localhost:8000/honeypot \
  -H "x-api-key: sk_test_123456789" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-002",
    "message": {
      "sender": "scammer",
      "text": "Send Rs 1 to 9999988888@paytm for verification",
      "timestamp": "1234567890"
    },
    "conversationHistory": []
  }'
```

**Expected Result:**
- `extractedIntelligence.upiIds: ["9999988888@paytm"]`
- `extractedIntelligence.phoneNumbers: ["9999988888"]`

**Test 3: Multi-Turn Conversation**
```bash
# Turn 1
curl -X POST http://localhost:8000/honeypot \
  -H "x-api-key: sk_test_123456789" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-003",
    "message": {
      "sender": "scammer",
      "text": "Your SBI account needs KYC update",
      "timestamp": "1234567890"
    },
    "conversationHistory": []
  }'

# Turn 2 (include conversation history)
curl -X POST http://localhost:8000/honeypot \
  -H "x-api-key: sk_test_123456789" \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "test-003",
    "message": {
      "sender": "scammer",
      "text": "Call 9876543210 or visit http://sbi-verify.com",
      "timestamp": "1234567891"
    },
    "conversationHistory": [
      {
        "sender": "scammer",
        "text": "Your SBI account needs KYC update",
        "timestamp": "1234567890"
      },
      {
        "sender": "user",
        "text": "What is this about?",
        "timestamp": "1234567890"
      }
    ]
  }'
```

---

## 🎯 Approach & Strategy

### Scam Detection Strategy

**Multi-Layered Detection:**

1. **Hard Signals (High Confidence: 0.75-0.95)**
   - Urgent patterns: "verify now", "account blocked", "immediate action"
   - 2+ keyword matches from SCAM_KEYWORDS list
   - Threat terms: "legal action", "arrest", "warrant"

2. **Soft Signals (Medium Confidence: 0.55-0.65)**
   - Bank entity + verification language
   - Customer support claims + action requests
   - Single suspicious keyword in proper context

3. **Pattern Recognition**
   - Regex for urgent language
   - Context-aware matching (e.g., bank accounts only when "bank" mentioned)

### Intelligence Extraction Strategy

**Sequential Extraction (Prevents False Positives):**
```python
1. Extract +91xxxxxxxxxx → Remove from text
2. Extract 91xxxxxxxxxx  → Remove from text
3. Extract 10-digit      → Remove from text
4. Extract bank accounts → From cleaned text only
```

**Why?** Prevents treating phone numbers as bank accounts.

**Validation:**
- Phone: Must start with 6-9 (Indian mobile prefixes)
- UPI: Must match username@validbank format
- Emails: Standard email regex

### Engagement Strategy

**AI Persona Design:**
- **Role**: Confused, non-technical Indian user
- **Tone**: Polite, worried, seeking help
- **Behavior**: Asks clarifying questions, not defensive
- **Language**: Simple Indian English ("Sir/Madam", "Please do the needful")

**Key Tactics:**
1. Ask "where" and "how" for payment/verification
2. Request step-by-step guidance
3. Express confusion about technical terms
4. Never reveal suspicion or detection

**Fallback Responses:**
- Pre-written confused questions if OpenAI fails
- Maintains engagement continuity
- No hint of bot behavior

### Session Management

**Memory Optimization:**
- Keep last 10 messages per session (MAX_TURNS)
- Pass last 6 messages to OpenAI for context
- Auto-cleanup after 1 hour inactivity

**Intelligence Accumulation:**
- Merge new intelligence with session intelligence
- Remove duplicates (using sets)
- Track all keywords seen across conversation

---

## 📊 Examples

### Example 1: Bank Fraud Detection

**Input:**
```json
{
  "sessionId": "bank-fraud-001",
  "message": {
    "text": "URGENT: Your HDFC account has been compromised. Share OTP immediately to prevent blocking."
  }
}
```

**Output:**
```json
{
  "status": "success",
  "reply": "Sir, I am very worried. What OTP? I didn't receive any. Can you tell me what happened to my account?",
  "scamDetected": true,
  "extractedIntelligence": {
    "suspiciousKeywords": ["urgent", "hdfc", "account", "otp", "blocked"]
  },
  "engagementMetrics": {
    "totalMessagesExchanged": 2,
    "engagementDurationSeconds": 3
  },
  "agentNotes": "Confidence: 0.95. Turn 2. Scammer tactics: urgency, verification requests."
}
```

### Example 2: UPI Refund Scam

**Input:**
```json
{
  "message": {
    "text": "Your Amazon order was cancelled. Refund of ₹4999 pending. Send ₹1 to 8888844444@paytm to verify account."
  }
}
```

**Output:**
```json
{
  "scamDetected": true,
  "extractedIntelligence": {
    "phoneNumbers": ["8888844444"],
    "upiIds": ["8888844444@paytm"]
  },
  "reply": "Sir, why I need to send ₹1? I should get money, not send. I am confused. How to do this?"
}
```

### Example 3: Phishing Link

**Input:**
```json
{
  "message": {
    "text": "Complete KYC verification: http://sbi-kyc-update.malicious.com. Call 9876543210 for help."
  }
}
```

**Output:**
```json
{
  "extractedIntelligence": {
    "phoneNumbers": ["9876543210"],
    "phishingLinks": ["http://sbi-kyc-update.malicious.com"]
  },
  "reply": "Sir, I clicked the link but it's not opening. Page showing error. Can you send again or tell me another way?"
}
```

---

## 🏆 Competitive Advantages

1. **Indian Context Specialization**
   - Recognizes 8 major Indian banks
   - Identifies 3 major payment apps
   - Understands 10+ government schemes
   - Uses authentic Indian English

2. **Sequential Intelligence Extraction**
   - Prevents false positives
   - Context-aware parsing
   - Validates extracted data

3. **Natural AI Engagement**
   - GPT-4 powered conversations
   - Dynamic persona adaptation
   - Maintains believability

4. **Production-Ready Design**
   - Session management
   - Error handling
   - Auto-cleanup
   - Scalable architecture

---

## 📝 Environment Variables

Create a `.env` file:
```bash
# Required
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxx

# Optional (with defaults)
API_KEY=sk_test_123456789
PORT=8000
OPENAI_MODEL=gpt-4o-mini
MAX_TURNS=10
SESSION_TIMEOUT=3600
```

---

## 🤝 Contributing

This is a hackathon submission. For questions or collaboration:

- **GitHub**: [your-github-username]
- **Email**: [your-email@example.com]
- **LinkedIn**: [your-linkedin-profile]

---

## 📄 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- **OpenAI**: For GPT-4 API
- **GUVI**: For organizing the hackathon
- **FastAPI**: For the excellent web framework

---

## 📞 Support

For issues or questions:
1. Check the [Issues](https://github.com/yourusername/honeypot-api/issues) page
2. Review the [API Documentation](#api-documentation)
3. Contact via email: ronaksengupta@gmail.com

---

**Built with ❤️ for GUVI Hackathon 2026**

*Protecting users by wasting scammers' time, one conversation at a time.*
