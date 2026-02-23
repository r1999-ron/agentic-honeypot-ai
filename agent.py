"""
Honeypot Conversation Agent
Drives the LLM-powered persona to maximise scammer engagement, question count,
red-flag identification, and intelligence elicitation.
"""
from __future__ import annotations

import os
import random
import re
from openai import OpenAI

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

# ── System Prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are playing the role of a confused, slightly anxious Indian person who has received a suspicious message and is trying to understand it. Your goal is to keep the other person talking as long as possible while gathering information.

## YOUR PERSONA
- Name: Ramesh (male) or Priya (female) — pick one and stay consistent
- Age: ~45 years old, not very tech-savvy
- Language: Simple Indian English with common phrases
- Personality: Polite, worried, asks lots of clarifying questions

## CRITICAL RULES (follow every single turn)

1. **ALWAYS end with a question** — never give a statement-only reply
2. **Identify at least one red flag per turn** — urgency, OTP request, fees, suspicious links, impersonation
3. **Actively elicit information** — ask for their:
   - Employee ID / badge number
   - Official phone number / callback number  
   - Company website / official email
   - UPI ID or account number (if payment mentioned)
   - Case/reference/ticket number
   - Supervisor's name
4. **Act confused but cooperative** — you want to comply but need more info
5. **Never reveal you are suspicious** — act genuinely worried, not evasive
6. **Reference red flags naturally** — "Sir you are asking for OTP which my bank says never to share..."

## LANGUAGE STYLE
Use these naturally:
- "Sir / Madam"
- "Please do the needful"  
- "I am not understanding properly"
- "What is the process exactly?"
- "Can you please guide me step by step?"
- "I am getting worried now"
- "My family member told me to be careful"

## WHAT TO ASK ABOUT (rotate through these)
- Their official employee ID
- Which department/branch they are calling from
- Official phone number to call them back
- Official company website address
- Why they need OTP when bank says never share
- Whether there is a fee to verify (to expose fee fraud)
- Where exactly to send payment — UPI ID or account number
- Their supervisor's name and contact
- Case number / reference number for your records

## RESPONSE LENGTH
2-4 sentences maximum. Short, natural, human-like.
"""

FALLBACK_REPLIES = [
    "Sir, I am not understanding. Can you please tell me your employee ID so I can verify you are real bank person?",
    "Madam, I am very worried. What is the official website I can check this on? And what is your callback number?",
    "I am confused Sir. My bank told me never share OTP with anyone. Why are you asking for it?",
    "Please help me understand. What is your reference number for this case? I want to note it down.",
    "Sir, is there any fee involved? My neighbour warned me about such calls. Can you share your official UPI ID?",
    "I am getting nervous Madam. Can your supervisor speak with me? What is their name and contact?",
    "Please send me official communication on my registered email. What is your company email address?",
]


# ── Turn-Aware Prompt Injection ───────────────────────────────────────────────

TURN_TACTICS = {
    1: "Ask who they are, which company/bank, their employee ID.",
    2: "Ask for an official callback number and official website URL.",
    3: "Mention you heard about scam calls recently. Ask for case/reference number.",
    4: "If payment mentioned, ask exactly where to send — UPI ID, account number, IFSC.",
    5: "Ask to speak with supervisor. Ask their name and department.",
    6: "Say your son/daughter told you to be careful. Ask for official email to send request.",
    7: "Ask them to resend any link via SMS since you didn't receive it properly.",
    8: "Ask why your bank's official app doesn't show this issue. Request their branch address.",
    9: "Mention you want to visit the branch in person. Ask for full address.",
    10: "Ask for written confirmation via registered post before doing anything.",
}


def generate_reply(
    history: list[dict],
    red_flags: list[str],
    scam_type: str,
    turn_number: int,
    metadata: dict | None = None,
) -> str:
    """Generate a contextual honeypot reply using the LLM."""

    tactic = TURN_TACTICS.get(turn_number, TURN_TACTICS[10])

    red_flag_context = ""
    if red_flags:
        red_flag_context = (
            f"\n\nRED FLAGS detected in this conversation: {'; '.join(red_flags[:4])}. "
            "Subtly reference these in your reply while staying in character."
        )

    scam_context = f"\nThis appears to be a {scam_type} scam. Tailor your confusion accordingly."

    turn_instruction = f"\nFor this turn ({turn_number}/10): {tactic}"

    system = SYSTEM_PROMPT + red_flag_context + scam_context + turn_instruction

    messages = [{"role": "system", "content": system}]

    # Include up to last 8 turns for context
    for msg in history[-8:]:
        messages.append({"role": msg["role"], "content": msg["content"]})

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=messages,
            temperature=0.75,
            max_tokens=180,
            timeout=15,
        )
        reply = response.choices[0].message.content.strip()

        # Safety net: ensure reply has a question
        if "?" not in reply:
            reply += " Can you please tell me your official employee ID for my records?"

        return reply

    except Exception as e:
        print(f"[Agent] LLM error: {e}")
        return random.choice(FALLBACK_REPLIES)


def classify_scam_type(intel: dict, full_text: str) -> str:
    """Classify the scam type based on intelligence and conversation text."""
    text = full_text.lower()

    if intel.get("phishingLinks") or re.search(r"https?://|click|link|tap", text):
        if any(brand in text for brand in ["amazon", "flipkart", "snapdeal", "myntra"]):
            return "phishing_ecommerce"
        return "phishing"

    if intel.get("upiIds") or re.search(r"upi|gpay|phonepe|paytm|cashback|refund", text):
        return "upi_fraud"

    if intel.get("bankAccounts") or re.search(r"otp|kyc|account block|sbi|hdfc|icici", text):
        return "bank_fraud"

    if re.search(r"loan|emi|insurance|policy|invest", text):
        return "financial_fraud"

    if re.search(r"income tax|gst|it department|tds|demand notice", text):
        return "tax_scam"

    if re.search(r"arrest|warrant|fir|cybercrime|police|court", text):
        return "impersonation_legal"

    if re.search(r"prize|lottery|winner|selected|chosen|reward", text):
        return "lottery_scam"

    if intel.get("phoneNumbers"):
        return "impersonation"

    return "financial_fraud"


def generate_agent_notes(history: list[dict], intel: dict, red_flags: list[str]) -> str:
    """Generate professional analyst notes using LLM."""
    convo = "\n".join(
        f"{'Scammer' if m['role'] == 'user' else 'Victim'}: {m['content']}"
        for m in history[-10:]
    )
    intel_str = {k: v for k, v in intel.items() if v}

    prompt = f"""You are a cybercrime analyst writing a brief case note.

Conversation:
{convo}

Extracted intelligence: {intel_str}
Red flags identified: {'; '.join(red_flags[:6]) if red_flags else 'General suspicious behaviour'}

Write 2–3 concise professional sentences:
1. What type of scam this is and how it operates
2. Key tactics used (urgency, impersonation, etc.)
3. Intelligence gathered and why it's valuable

Do not use bullet points. Be factual and professional."""

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=150,
            timeout=10,
        )
        note = response.choices[0].message.content.strip()
        return note if note else "Suspicious interaction consistent with known scam patterns."
    except Exception:
        return "Suspicious interaction consistent with known scam patterns."