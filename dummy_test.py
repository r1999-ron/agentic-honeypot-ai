#!/usr/bin/env python3
"""
Dummy Test File for Honeypot API
This file tests your deployed Railway API with various scenarios
"""

import requests
import json
import time
import uuid

# Configuration - UPDATE THESE WITH YOUR DEPLOYED VALUES
DEPLOYED_API_URL = "https://agentic-honeypot-ai-production.up.railway.app"  # Change this to your Railway URL
API_KEY = "sk_test_123456789"  # Your API key

HEADERS = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}


def test_api_health():
    """Test if API is running"""
    print("🏥 Testing API Health...")
    try:
        response = requests.get(f"{DEPLOYED_API_URL}/health")
        if response.status_code == 200:
            print("✅ API is healthy:", response.json())
            return True
        else:
            print("❌ API health check failed:", response.status_code)
            return False
    except Exception as e:
        print("💥 Health check error:", e)
        return False


def send_test_message(session_id, message_text, conversation_history=None):
    """Send a test message to the honeypot API"""

    if conversation_history is None:
        conversation_history = []

    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": message_text,
            "timestamp": str(int(time.time() * 1000))
        },
        "conversationHistory": conversation_history,
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }

    print(f"\n📤 SENDING: {message_text}")

    try:
        response = requests.post(
            f"{DEPLOYED_API_URL}/honeypot",
            headers=HEADERS,
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            print(f"✅ Response: {result['reply']}")
            return result
        else:
            print(f"❌ Error {response.status_code}: {response.text}")
            return None

    except Exception as e:
        print(f"💥 Request failed: {e}")
        return None


def test_video_call_scam():
    """Test video call scam detection"""
    print("\n" + "=" * 60)
    print("📹 TESTING VIDEO CALL SCAM DETECTION")
    print("=" * 60)

    session_id = f"video-test-{uuid.uuid4()}"
    conversation_history = []

    messages = [
        "Your account needs verification. Join video call immediately.",
        "Sir, video call is mandatory for KYC update",
        "Please show your documents on WhatsApp video call",
        "Video verification required to avoid account blocking"
    ]

    for msg in messages:
        result = send_test_message(session_id, msg, conversation_history)
        if result:
            # Update conversation history
            conversation_history.append({
                "sender": "scammer",
                "text": msg,
                "timestamp": str(int(time.time() * 1000))
            })
            conversation_history.append({
                "sender": "user",
                "text": result['reply'],
                "timestamp": str(int(time.time() * 1000))
            })
        time.sleep(2)


def test_classic_bank_fraud():
    """Test classic bank fraud scenario"""
    print("\n" + "=" * 60)
    print("🏦 TESTING CLASSIC BANK FRAUD")
    print("=" * 60)

    session_id = f"bank-test-{uuid.uuid4()}"
    conversation_history = []

    messages = [
        "Your SBI account will be blocked today. Urgent action required.",
        "Complete KYC verification by sending money to test@paytm",
        "Also provide bank account number: 1234567890123456",
        "Call this number for help: +919876543210"
    ]

    for msg in messages:
        result = send_test_message(session_id, msg, conversation_history)
        if result:
            conversation_history.append({
                "sender": "scammer",
                "text": msg,
                "timestamp": str(int(time.time() * 1000))
            })
            conversation_history.append({
                "sender": "user",
                "text": result['reply'],
                "timestamp": str(int(time.time() * 1000))
            })
        time.sleep(2)


def test_phishing_links():
    """Test phishing link detection"""
    print("\n" + "=" * 60)
    print("🎣 TESTING PHISHING LINKS")
    print("=" * 60)

    session_id = f"phish-test-{uuid.uuid4()}"

    messages = [
        "Congratulations! Click here to claim prize: https://fake-lottery.com/claim",
        "Update your bank details at: http://secure-bank-login.net",
        "Urgent KYC update required: https://kyc-update-portal.com"
    ]

    for msg in messages:
        result = send_test_message(session_id, msg)
        time.sleep(2)


def test_legitimate_message():
    """Test non-scam message handling"""
    print("\n" + "=" * 60)
    print("✅ TESTING LEGITIMATE MESSAGES")
    print("=" * 60)

    session_id = f"legit-test-{uuid.uuid4()}"

    messages = [
        "Hello, how are you?",
        "What's the weather like today?",
        "Can you help me with directions to the mall?"
    ]

    for msg in messages:
        result = send_test_message(session_id, msg)
        time.sleep(2)


def test_government_scheme_scam():
    """Test government scheme scam"""
    print("\n" + "=" * 60)
    print("🏛️ TESTING GOVERNMENT SCHEME SCAM")
    print("=" * 60)

    session_id = f"govt-test-{uuid.uuid4()}"

    messages = [
        "PM Modi announced new subsidy. Verify Aadhaar immediately.",
        "COVID vaccination certificate update required urgently",
        "Digital India startup fund available. Click link to apply."
    ]

    for msg in messages:
        result = send_test_message(session_id, msg)
        time.sleep(2)


def test_guvi_endpoint():
    """Test GUVI test endpoint"""
    print("\n" + "=" * 60)
    print("🧪 TESTING GUVI TEST ENDPOINT")
    print("=" * 60)

    try:
        response = requests.post(
            f"{DEPLOYED_API_URL}/honeypot/guvi-test",
            headers=HEADERS,
            json={},
            timeout=10
        )

        if response.status_code == 200:
            print("✅ GUVI test endpoint working:", response.json())
        else:
            print("❌ GUVI test failed:", response.status_code, response.text)

    except Exception as e:
        print("💥 GUVI test error:", e)


def main():
    """Run all tests"""
    print("🤖 DUMMY API TESTING SCRIPT")
    print("=" * 60)
    print(f"🎯 Target API: {DEPLOYED_API_URL}")
    print(f"🔑 API Key: {API_KEY}")

    # Check if API is running
    if not test_api_health():
        print("💥 API is not accessible. Check your URL and deployment.")
        return

    # Test GUVI endpoint
    test_guvi_endpoint()

    # Test various scam scenarios
    test_video_call_scam()
    test_classic_bank_fraud()
    test_phishing_links()
    test_government_scheme_scam()
    test_legitimate_message()

    print("\n" + "=" * 60)
    print("🏁 ALL DUMMY TESTS COMPLETED")
    print("=" * 60)
    print("\n💡 Things to check:")
    print("- Agent responses are natural and Indian-context appropriate")
    print("- Scam messages get engaged responses")
    print("- Legitimate messages get dismissive responses")
    print("- API responds quickly (under 3 seconds)")
    print("- No errors or crashes")


if __name__ == "__main__":
    main()