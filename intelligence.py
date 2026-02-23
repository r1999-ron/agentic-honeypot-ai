"""
Intelligence Extraction Module
Extracts all identifiable scammer artefacts from conversation text.
"""

import re
from typing import Any

# Known UPI VPA handles (Virtual Payment Addresses)
KNOWN_UPI_HANDLES = {
    "oksbi", "okaxis", "okicici", "okhdfcbank",
    "ybl", "ibl", "axl", "apl",
    "paytm", "freecharge", "airtel", "jio",
    "hdfcbank", "icici", "sbi", "axisbank",
    "rbl", "indus", "kotak", "federal",
    "fbl", "uboi", "barodampay", "upi",
    "okbizaxis", "timecosmos", "pingpay",
    "naviaxis", "cmsidfc",
}

# TLDs that appear in UPI domains but NOT email domains
UPI_SPECIFIC_HANDLES = {
    "oksbi", "okaxis", "ybl", "ibl", "axl", "apl",
    "hdfcbank", "icici", "sbi", "axisbank",
}


def extract_all(text: str) -> dict[str, list]:
    """Master extractor — returns all intelligence types from a block of text."""
    return {
        "phoneNumbers":   _phones(text),
        "bankAccounts":   _bank_accounts(text),
        "upiIds":         _upi_ids(text),
        "phishingLinks":  _links(text),
        "emailAddresses": _emails(text),
        "caseIds":        _case_ids(text),
        "policyNumbers":  _policy_numbers(text),
        "orderNumbers":   _order_numbers(text),
        "requestedSensitiveData": _sensitive_requests(text)
    }

def _sensitive_requests(text: str) -> list[str]:
    findings = []
    lower = text.lower()

    patterns = {
        "otp": r"\botp\b",
        "bank_account_number": r"account number",
        "cvv": r"\bcvv\b",
        "upi_pin": r"upi pin",
        "card_number": r"card number",
        "atm_pin": r"\batm pin\b",
    }

    for label, pattern in patterns.items():
        matches = re.findall(pattern, lower)
        if matches:
            # add once per occurrence
            for _ in matches:
                findings.append(label)

    return findings


def merge_intelligence(base: dict, new: dict) -> dict:
    """Merge two intelligence dicts, deduplicating lists."""
    merged = {}
    for key in set(base) | set(new):
        merged[key] = list(set(base.get(key, []) + new.get(key, [])))
    return merged


# ── Extractors ─────────────────────────────────────────────────────────────────

def _phones(text: str) -> list[str]:
    found = set()

    # +91-XXXXXXXXXX or +91 XXXXXXXXXX
    for m in re.finditer(r'\+91[-\s]?(\d{10})', text):
        found.add(f"+91-{m.group(1)}")

    # 91XXXXXXXXXX (12 digits starting with 91)
    for m in re.finditer(r'\b91([6-9]\d{9})\b', text):
        found.add(f"+91-{m.group(1)}")

    # Standalone 10-digit mobile (starts 6-9)
    for m in re.finditer(r'\b([6-9]\d{9})\b', text):
        found.add(f"+91-{m.group(1)}")

    return sorted(found)


def _bank_accounts(text: str) -> list[str]:
    # Indian bank accounts: 9–18 digits, not a phone number
    candidates = re.findall(r'\b(\d{9,18})\b', text)
    results = []
    for c in candidates:
        # exclude obvious phone patterns
        if re.match(r'^[6-9]\d{9}$', c):
            continue
        if re.match(r'^91[6-9]\d{9}$', c):
            continue
        results.append(c)
    return list(set(results))


def _upi_ids(text: str) -> list[str]:
    emails = set(_emails(text))
    candidates = re.findall(r'\b([a-zA-Z0-9._+-]+@[a-zA-Z]{3,20})\b', text)
    upi_ids = []
    for c in candidates:
        # Skip if it's a full email or starts with a known email prefix
        if any(c.lower() == e.lower() or e.lower().startswith(c.lower()) for e in emails):
            continue
        domain = c.split('@')[1].lower()
        if domain in KNOWN_UPI_HANDLES or ('.' not in domain and len(domain) >= 3):
            upi_ids.append(c)
    return list(set(upi_ids))


def _links(text: str) -> list[str]:
    # Only extract full URLs with http/https — don't guess bare domains
    raw = re.findall(r'https?://[^\s<>")\]]+', text)
    cleaned = [r.rstrip('.,!?;:\')"') for r in raw]
    return list(set(cleaned))


def _emails(text: str) -> list[str]:
    return list(set(
        re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', text)
    ))


def _case_ids(text: str) -> list[str]:
    patterns = [
        r'\b(?:CASE|REF|TKT|SR|INC|COMP|CRM|CAS)[-#/]?\s*\d{4,12}\b',
        r'\b(?:SBI|HDFC|ICICI|AXIS|RBI|TRAI|DOT)[-/]?\d{4,12}\b',
        r'\b(?:case|ticket|reference|complaint)\s*(?:no\.?|number|id)?\s*:?\s*\d{4,12}\b',
    ]
    results = []
    for p in patterns:
        results.extend(re.findall(p, text, re.IGNORECASE))
    return list(set(results))


def _policy_numbers(text: str) -> list[str]:
    patterns = [
        r'\b(?:POL|POLICY|LIC|INS)[-/]?\d{6,15}\b',
        r'\bpolicy\s*(?:no\.?|number)?\s*:?\s*\d{6,15}\b',
    ]
    results = []
    for p in patterns:
        results.extend(re.findall(p, text, re.IGNORECASE))
    return list(set(results))


def _order_numbers(text: str) -> list[str]:
    patterns = [
        r'\b(?:ORD|ORDER|OD|AMZ|FK)[-/]?[A-Z0-9]{6,20}\b',
        r'\border\s*(?:no\.?|number|id)?\s*:?\s*[A-Z0-9]{6,20}\b',
        r'\b\d{3}-\d{7}-\d{7}\b',   # Amazon order format
        #r'[?&](?:id|order|ref|txn|transaction)=([A-Za-z0-9-]{3,20})'
    ]
    results = []
    for p in patterns:
        results.extend(re.findall(p, text, re.IGNORECASE))
    return list(set(results))