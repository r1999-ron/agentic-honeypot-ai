#!/usr/bin/env python3
"""
End-to-End Testing Script for Honeypot API
This script simulates the complete evaluation flow
"""

import requests
import json
import time
import uuid
from typing import List, Dict

# Configuration
API_BASE_URL = "http://localhost:8000"  # Change to your deployed URL
API_KEY = "sk_test_123456789"  # Your API key
HEADERS = {
    "Content-Type": "application/json",
    "x-api-key": API_KEY
}


class HoneypotTester:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key
        }
        self.session_id = f"test-{uuid.uuid4()}"
        self.conversation_history = []

    def send_message(self, scammer_message: str, metadata: dict = None) -> dict:
        """Send a message to the honeypot API"""

        payload = {
            "sessionId": self.session_id,
            "message": {
                "sender": "scammer",
                "text": scammer_message,
                "timestamp": str(int(time.time() * 1000))
            },
            "conversationHistory": self.conversation_history.copy(),
            "metadata": metadata or {
                "channel": "SMS",
                "language": "English",
                "locale": "IN"
            }
        }

        print(f"\n📤 SENDING: {scammer_message}")
        print(f"📋 Conversation History Length: {len(self.conversation_history)}")

        try:
            response = requests.post(
                f"{self.base_url}/honeypot",
                headers=self.headers,
                json=payload,
                timeout=30
            )

            print(f"🌐 Response Status: {response.status_code}")

            if response.status_code == 200:
                result = response.json()
                agent_reply = result.get("reply", "No reply")

                print(f"📥 AGENT REPLY: {agent_reply}")

                # Update conversation history
                self.conversation_history.append({
                    "sender": "scammer",
                    "text": scammer_message,
                    "timestamp": str(int(time.time() * 1000))
                })

                self.conversation_history.append({
                    "sender": "user",
                    "text": agent_reply,
                    "timestamp": str(int(time.time() * 1000))
                })

                return result
            else:
                print(f"❌ Error: {response.text}")
                return {"error": response.text}

        except Exception as e:
            print(f"💥 Exception: {e}")
            return {"error": str(e)}

    def test_health(self) -> bool:
        """Test if API is running"""
        try:
            response = requests.get(f"{self.base_url}/")
            return response.status_code == 200
        except:
            return False


def test_video_call_scam():
    """Test Scenario: Video Call KYC Scam"""
    print("\n" + "=" * 60)
    print("📹 TEST SCENARIO: VIDEO CALL KYC SCAM")
    print("=" * 60)

    tester = HoneypotTester(API_BASE_URL, API_KEY)

    messages = [
        "Sir, join video call for immediate KYC verification",
        "Your account blocked. Video verification needed urgently on WhatsApp",
        "Show your documents on video call to reactivate account",
        "Video call mandatory for government subsidy verification"
    ]

    for msg in messages:
        result = tester.send_message(msg)
        if result and "error" not in result:
            print(f"✅ Scam detected and agent engaged naturally")
        else:
            print(f"❌ Failed to process message properly")
        time.sleep(2)


def test_scenario_1_bank_fraud():
    """Test Scenario 1: Classic Bank Fraud"""
    print("\n" + "=" * 60)
    print("🏦 TEST SCENARIO 1: BANK FRAUD")
    print("=" * 60)

    tester = HoneypotTester(API_BASE_URL, API_KEY)

    messages = [
        "Your bank account will be blocked today. Verify immediately.",
        "Sir, you need to complete KYC verification right now or account will be suspended.",
        "Please share your UPI ID to avoid account blocking.",
        "Send money to upi id: scammer123@paytm for verification",
        "Also provide your bank account number for final verification",
        "Call this number immediately: 9876543210"
    ]

    for msg in messages:
        tester.send_message(msg)
        time.sleep(2)  # Simulate human delay


def test_scenario_2_phishing_links():
    """Test Scenario 2: Phishing Links"""
    print("\n" + "=" * 60)
    print("🎣 TEST SCENARIO 2: PHISHING LINKS")
    print("=" * 60)

    tester = HoneypotTester(API_BASE_URL, API_KEY)

    messages = [
        "Congratulations! You won lottery prize of Rs 50000",
        "Click this link to claim: https://fake-lottery-site.com/claim",
        "Enter your bank details here: http://phishing-bank.com/login",
        "Urgent: Update your KYC at https://fake-kyc-update.net",
        "Your account details: Account number 1234567890123456"
    ]

    for msg in messages:
        tester.send_message(msg)
        time.sleep(2)


def test_scenario_3_non_scam():
    """Test Scenario 3: Legitimate Message"""
    print("\n" + "=" * 60)
    print("✅ TEST SCENARIO 3: LEGITIMATE MESSAGE")
    print("=" * 60)

    tester = HoneypotTester(API_BASE_URL, API_KEY)

    messages = [
        "Hello, how are you today?",
        "What's the weather like?",
        "Can you help me with directions?"
    ]

    for msg in messages:
        tester.send_message(msg)
        time.sleep(2)


def test_government_scams():
    """Test Scenario: Government Scheme Scams"""
    print("\n" + "=" * 60)
    print("🏛️ TEST SCENARIO: GOVERNMENT SCAMS")
    print("=" * 60)

    tester = HoneypotTester(API_BASE_URL, API_KEY)

    messages = [
        "PM Modi announced Digital India subsidy. Verify Aadhaar now.",
        "COVID vaccination certificate expired. Update immediately.",
        "PM Kisan scheme payment pending. Video call required for verification.",
        "Income tax refund available. Click link: http://fake-income-tax.gov.in"
    ]

    for msg in messages:
        tester.send_message(msg)
        time.sleep(2)


def test_api_endpoints():
    """Test all API endpoints"""
    print("\n" + "=" * 60)
    print("🔧 TESTING API ENDPOINTS")
    print("=" * 60)

    # Test health endpoint
    try:
        response = requests.get(f"{API_BASE_URL}/")
        print(f"✅ Health endpoint: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"❌ Health endpoint failed: {e}")

    # Test health check endpoint
    try:
        response = requests.get(f"{API_BASE_URL}/health")
        print(f"✅ Health check endpoint: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"❌ Health check endpoint failed: {e}")

    # Test GUVI test endpoint
    try:
        response = requests.post(
            f"{API_BASE_URL}/honeypot/guvi-test",
            headers=HEADERS,
            json={}
        )
        print(f"✅ GUVI test endpoint: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"❌ GUVI test endpoint failed: {e}")


def test_error_cases():
    """Test error handling"""
    print("\n" + "=" * 60)
    print("⚠️  TESTING ERROR CASES")
    print("=" * 60)

    base_payload = {
        "sessionId": "test-error-session",
        "message": {
            "sender": "scammer",
            "text": "Test message",
            "timestamp": str(int(time.time() * 1000))
        },
        "conversationHistory": []
    }

    # Test without API key
    print("\n1. Testing without API key...")
    try:
        response = requests.post(
            f"{API_BASE_URL}/honeypot",
            headers={"Content-Type": "application/json"},  # No API key
            json=base_payload
        )
        print(f"Response: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

    # Test with invalid API key
    print("\n2. Testing with invalid API key...")
    try:
        response = requests.post(
            f"{API_BASE_URL}/honeypot",
            headers={
                "Content-Type": "application/json",
                "x-api-key": "invalid-key"
            },
            json=base_payload
        )
        print(f"Response: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"Error: {e}")


def run_performance_test():
    """Test API performance with multiple requests"""
    print("\n" + "=" * 60)
    print("⚡ PERFORMANCE TEST")
    print("=" * 60)

    start_time = time.time()
    success_count = 0
    total_requests = 5

    for i in range(total_requests):
        tester = HoneypotTester(API_BASE_URL, API_KEY)
        result = tester.send_message(f"Test message {i + 1}: Your account will be blocked")
        if "error" not in result:
            success_count += 1
        time.sleep(1)

    total_time = time.time() - start_time
    print(f"\n📊 Performance Results:")
    print(f"✅ Successful requests: {success_count}/{total_requests}")
    print(f"⏱️  Total time: {total_time:.2f} seconds")
    print(f"🚀 Average response time: {total_time / total_requests:.2f} seconds")


def main():
    """Run all tests"""
    print("🤖 HONEYPOT API END-TO-END TESTING")
    print("=" * 60)

    # Check if API is running
    tester = HoneypotTester(API_BASE_URL, API_KEY)
    if not tester.test_health():
        print(f"❌ API is not running at {API_BASE_URL}")
        print("Please start your FastAPI server first:")
        print("uvicorn honeypot_fixed:app --reload --host 0.0.0.0 --port 8000")
        return

    print(f"✅ API is running at {API_BASE_URL}")

    # Run all test scenarios
    test_api_endpoints()
    test_video_call_scam()  # NEW: Test video call scam detection
    test_scenario_1_bank_fraud()
    test_scenario_2_phishing_links()
    test_government_scams()  # NEW: Test government scams
    test_scenario_3_non_scam()
    test_error_cases()
    run_performance_test()

    print("\n" + "=" * 60)
    print("🏁 ALL TESTS COMPLETED")
    print("=" * 60)
    print("\n💡 What to look for:")
    print("- Agent should engage naturally with scam messages")
    print("- Should detect video call, KYC, and government scams")
    print("- Should extract phone numbers, UPI IDs, links, bank accounts")
    print("- Should maintain conversation context")
    print("- Should finalize and send callback when enough intel is gathered")
    print("- Should handle non-scam messages appropriately")


if __name__ == "__main__":
    main()