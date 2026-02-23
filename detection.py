"""
Scam Detection Module
Multi-signal detection engine covering bank fraud, UPI scams, phishing, and more.
"""
from __future__ import annotations

import re
from typing import Tuple

# ── Keyword Banks ─────────────────────────────────────────────────────────────

HARD_KEYWORDS = {
    # Authentication pressure
    "otp", "pin", "cvv", "password", "kyc", "e-kyc",
    # Urgency
    "urgent", "immediately", "asap", "expire", "block", "suspend", "freeze",
    "last chance", "final notice", "final warning", "24 hours", "48 hours",
    # Threats
    "arrest", "warrant", "fir", "legal action", "police", "court",
    # Financial triggers
    "refund", "cashback", "prize", "lottery", "winner", "reward",
    "free iphone", "free samsung", "gift", "congratulations",
    # Actions
    "click", "tap", "install", "download", "apk",
    # Identity
    "aadhar", "aadhaar", "pan card", "pan number",
}

SOFT_KEYWORDS = {
    "verify", "verification", "confirm", "update", "account",
    "bank", "payment", "upi", "neft", "imps", "transfer",
    "customer care", "helpline", "support", "executive",
    "sbi", "hdfc", "icici", "axis", "kotak", "paytm", "phonepe", "gpay",
    "income tax", "gst", "government", "subsidy", "scheme",
    "loan", "emi", "insurance", "policy",
    "delivery", "package", "parcel", "amazon", "flipkart",
    "selected", "offer", "deal", "discount",
}

URGENT_PATTERNS = [
    r"verif\w+\s+(now|immediately|today|asap|urgently)",
    r"account\s+(?:will\s+be\s+)?(?:blocked?|suspend\w+|frozen?|close[d]?)",
    r"within\s*\d+\s*(?:minutes?|hours?|days?)",
    r"act\s+(?:now|immediately|fast|quickly)",
    r"final\s+(?:warning|notice|reminder|opportunity|chance)",
    r"last\s+(?:chance|opportunity|warning|notice|reminder)",
    r"(?:your\s+)?(?:kyc|account|card)\s+(?:is\s+)?(?:expired?|expiring|invalid)",
    r"send\s+(?:otp|pin|password)",
    r"share\s+(?:otp|pin|password|cvv|account)",
    r"do\s+not\s+share.{0,30}(?:otp|pin|password)",  # "do not share" = scam
    r"calling\s+from\s+(?:sbi|hdfc|icici|rbi|bank|insurance|income tax)",
    r"you\s+(?:have\s+)?(?:won|selected|chosen|eligible)",
]

PHISHING_PATTERNS = [
    r"https?://\S+",                          # any URL
    r"bit\.ly|tinyurl|goo\.gl|t\.co",        # URL shorteners
    r"(?:click|tap|visit|open)\s+(?:this|the)\s+(?:link|url|website)",
    r"\.xyz|\.top|\.click|\.loan|\.tk|\.ml", # suspicious TLDs
    r"amaz[o0]n|flipk[a@]rt|ph[o0]nepe",    # lookalike brand names
]

# ── Detection Engine ──────────────────────────────────────────────────────────

def normalize(text: str) -> str:
    return re.sub(r'\s+', ' ', text.lower()).strip()


def detect_scam(text: str, history: list[dict] | None = None) -> Tuple[bool, float, list[str]]:
    """
    Returns (is_scam, confidence, red_flags_list)
    Analyses current message + optionally cumulative history.
    """
    combined = text
    if history:
        combined = " ".join(
            m["content"] for m in history if m.get("role") == "user"
        ) + " " + text

    norm = normalize(combined)
    red_flags = []
    score = 0.0

    # Hard keyword hits
    hard_hits = [kw for kw in HARD_KEYWORDS if kw in norm]
    if hard_hits:
        score += 0.15 * min(len(hard_hits), 4)
        red_flags.append(f"Suspicious keywords: {', '.join(hard_hits[:5])}")

    # Soft keyword hits
    soft_hits = [kw for kw in SOFT_KEYWORDS if kw in norm]
    if len(soft_hits) >= 2:
        score += 0.10 * min(len(soft_hits), 3)
        red_flags.append(f"Financial/authority context: {', '.join(soft_hits[:4])}")

    # Urgent patterns
    urgent_hits = [p for p in URGENT_PATTERNS if re.search(p, norm)]
    if urgent_hits:
        score += 0.25
        red_flags.append(f"Urgency/pressure tactics detected ({len(urgent_hits)} pattern(s))")

    # Phishing patterns
    phish_hits = [p for p in PHISHING_PATTERNS if re.search(p, norm)]
    if phish_hits:
        score += 0.30
        red_flags.append("Phishing link or lookalike brand detected")
        # URL alone is strong signal
        if re.search(r"https?://\S+", norm):
            score += 0.10

    # Reward/prize scam
    if re.search(r"(won|win|winner|prize|lottery|lucky|selected|chosen).{0,50}(claim|collect|verify|click)", norm):
        score += 0.30
        red_flags.append("Prize/lottery/reward scam pattern")

    # OTP/PIN sharing request
    if re.search(r"(share|send|give|tell|enter|provide).{0,30}(otp|pin|password|cvv)", norm):
        score += 0.40
        red_flags.append("Requesting OTP/PIN/password — definitive scam signal")

    # Impersonation of authorities
    if re.search(r"(rbi|sebi|income\s*tax|cybercrime|cbi|police|court|government|modi|pm\s)", norm):
        score += 0.20
        red_flags.append("Government/authority impersonation")

    confidence = min(score, 0.97)
    is_scam = confidence >= 0.30 or len(hard_hits) >= 1 or bool(urgent_hits)

    return is_scam, round(confidence, 2), red_flags