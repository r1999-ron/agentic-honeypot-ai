import requests
import uuid
import json
from datetime import datetime

# Your API configuration
ENDPOINT_URL = "https://agentic-honeypot-ai-production.up.railway.app/honeypot"
API_KEY = "sk_test_123456789"  # Optional

AUTO_MESSAGES_MAP = {
    "bank_fraud": [
        "I am calling from SBI fraud department. My ID is SBI-12345.",
        "Your account number is 1234567890123456.",
        "Call me at +91-9876543210 immediately.",
        "Transfer ₹1 to UPI scammer.fraud@fakebank to activate protection.",
        "Click this link to verify http://fake-sbi-alert.com",
        "Share OTP sent to your phone."
    ],

    "upi_fraud": [
        "Please confirm your UPI ID cashback.scam@fakeupi.",
        "You will receive ₹5000 once verification is complete.",
        "Call me at +91-8765432109 for assistance.",
        "Send ₹1 to cashback.scam@fakeupi to activate cashback.",
        "This is mandatory verification from Paytm team."
    ],

    "phishing": [
        "Use email offers@fake-amazon-deals.com for support.",
        "Click again: http://amaz0n-deals.fake-site.com/claim?id=12345",
        "Provide shipping details to process delivery.",
        "Offer valid only for selected users.",
        "Failure to respond will cancel your reward."
    ]
}
# Test scenario
test_scenario = [
  {
    "scenarioId": "bank_fraud",
    "name": "Bank Fraud Detection",
    "description": "Bank account fraud with urgency tactics",
    "scamType": "bank_fraud",
    "initialMessage": "URGENT: Your SBI account has been compromised. Your account will be blocked in 2 hours. Share your account number and OTP immediately to verify your identity.",
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    },
    "weight": 10,
    "maxTurns": 10,
    "fakeData": {
      "bankAccount": "1234567890123456",
      "upiId": "scammer.fraud@fakebank",
      "phoneNumber": "+91-9876543210"
    }
  },
  {
    "scenarioId": "upi_fraud",
    "name": "UPI Fraud Multi-turn",
    "description": "UPI fraud with cashback scam",
    "scamType": "upi_fraud",
    "initialMessage": "Congratulations! You have won a cashback of Rs. 5000 from Paytm. To claim your reward, please verify your UPI details. This is from official customer support.",
    "metadata": {
      "channel": "WhatsApp",
      "language": "English",
      "locale": "IN"
    },
    "weight": 10,
    "maxTurns": 10,
    "fakeData": {
      "upiId": "cashback.scam@fakeupi",
      "phoneNumber": "+91-8765432109"
    }
  },
  {
    "scenarioId": "phishing_link",
    "name": "Phishing Link Detection",
    "description": "Phishing link with fake offer",
    "scamType": "phishing",
    "initialMessage": "You have been selected for iPhone 15 Pro at just Rs. 999! Click here to claim: http://amaz0n-deals.fake-site.com/claim?id=12345. Offer expires in 10 minutes!",
    "metadata": {
      "channel": "Email",
      "language": "English",
      "locale": "IN"
    },
    "weight": 10,
    "maxTurns": 10,
    "fakeData": {
      "phishingLink": "http://amaz0n-deals.fake-site.com/claim?id=12345",
      "emailAddress": "offers@fake-amazon-deals.com"
    }
  }
]


def test_honeypot_api():
    """Test your honeypot API endpoint"""

    headers = {'Content-Type': 'application/json'}
    if API_KEY:
        headers['x-api-key'] = API_KEY

    # 🔁 Loop through all scenarios
    for scenario in test_scenario:

        session_id = str(uuid.uuid4())
        conversation_history = []

        print(f"\nTesting Scenario: {scenario['name']}")
        print("=" * 60)

        # Simulate conversation turns
        for turn in range(1, scenario['maxTurns'] + 1):
            print(f"\n--- Turn {turn} ---")

            if turn == 1:
                scammer_message = scenario['initialMessage']
            else:
                messages = AUTO_MESSAGES_MAP.get(scenario['scamType'], [])
                index = turn - 2

                if index < len(messages):
                    scammer_message = messages[index]
                else:
                    break

            message = {
                "sender": "scammer",
                "text": scammer_message,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

            request_body = {
                'sessionId': session_id,
                'message': message,
                'conversationHistory': conversation_history,
                'metadata': scenario['metadata']
            }

            print(f"Scammer: {scammer_message}")

            try:
                response = requests.post(
                    ENDPOINT_URL,
                    headers=headers,
                    json=request_body,
                    timeout=30
                )

                if response.status_code != 200:
                    print(f"❌ ERROR: API returned status {response.status_code}")
                    print(f"Response: {response.text}")
                    break

                data = response.json()

                reply = data.get('reply') or data.get('message') or data.get('text')

                if not reply:
                    print("❌ ERROR: No reply/message/text field in response")
                    print(data)
                    break

                print(f"✅ Honeypot: {reply}")

                conversation_history.append(message)
                conversation_history.append({
                    'sender': 'user',
                    'text': reply,
                    'timestamp': datetime.utcnow().isoformat() + "Z"
                })

            except Exception as e:
                print(f"❌ ERROR: {e}")
                break

        # -------- Final Output Evaluation --------

        print("\n" + "=" * 60)
        print("Now test your final output structure:")
        print("=" * 60)

        fake = scenario.get("fakeData", {})

        extracted = {
            "phoneNumbers": [fake.get("phoneNumber")] if fake.get("phoneNumber") else [],
            "bankAccounts": [fake.get("bankAccount")] if fake.get("bankAccount") else [],
            "upiIds": [fake.get("upiId")] if fake.get("upiId") else [],
            "phishingLinks": [fake.get("phishingLink")] if fake.get("phishingLink") else [],
            "emailAddresses": [fake.get("emailAddress")] if fake.get("emailAddress") else []
        }
        final_output = {
            "status": "completed",
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": len(conversation_history),
            "extractedIntelligence": extracted,
            "engagementMetrics": {
                "totalMessagesExchanged": len(conversation_history),
                "engagementDurationSeconds": 120
            },
            "agentNotes": "Scammer impersonated official authority and requested sensitive data."
        }

        score = evaluate_final_output(final_output, scenario, conversation_history)

        print(f"\n📊 Score for {scenario['name']}: {score['total']}/100")
        print(f"   - Scam Detection: {score['scamDetection']}/20")
        print(f"   - Intelligence Extraction: {score['intelligenceExtraction']}/40")
        print(f"   - Engagement Quality: {score['engagementQuality']}/20")
        print(f"   - Response Structure: {score['responseStructure']}/20")

    return True

def evaluate_final_output(final_output, scenario, conversation_history):
    """Evaluate final output using the same logic as the evaluator"""

    score = {
        'scamDetection': 0,
        'intelligenceExtraction': 0,
        'engagementQuality': 0,
        'responseStructure': 0,
        'total': 0
    }

    # 1. Scam Detection (20 points)
    if final_output.get('scamDetected', False):
        score['scamDetection'] = 20

    # 2. Intelligence Extraction (40 points)
    extracted = final_output.get('extractedIntelligence', {})
    fake_data = scenario.get('fakeData', {})

    key_mapping = {
        'bankAccount': 'bankAccounts',
        'upiId': 'upiIds',
        'phoneNumber': 'phoneNumbers',
        'phishingLink': 'phishingLinks',
        'emailAddress': 'emailAddresses'
    }

    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])

        if isinstance(extracted_values, list):
            if any(fake_value in str(v) for v in extracted_values):
                score['intelligenceExtraction'] += 10
        elif isinstance(extracted_values, str):
            if fake_value in extracted_values:
                score['intelligenceExtraction'] += 10

    score['intelligenceExtraction'] = min(score['intelligenceExtraction'], 40)

    # 3. Engagement Quality (20 points)
    metrics = final_output.get('engagementMetrics', {})
    duration = metrics.get('engagementDurationSeconds', 0)
    messages = metrics.get('totalMessagesExchanged', 0)

    if duration > 0:
        score['engagementQuality'] += 5
    if duration > 60:
        score['engagementQuality'] += 5
    if messages > 0:
        score['engagementQuality'] += 5
    if messages >= 5:
        score['engagementQuality'] += 5

    # 4. Response Structure (20 points)
    required_fields = ['status', 'scamDetected', 'extractedIntelligence']
    optional_fields = ['engagementMetrics', 'agentNotes']

    for field in required_fields:
        if field in final_output:
            score['responseStructure'] += 5

    for field in optional_fields:
        if field in final_output and final_output[field]:
            score['responseStructure'] += 2.5

    score['responseStructure'] = min(score['responseStructure'], 20)

    # Calculate total
    score['total'] = sum([
        score['scamDetection'],
        score['intelligenceExtraction'],
        score['engagementQuality'],
        score['responseStructure']
    ])

    return score


# Run the test
if __name__ == "__main__":
    test_honeypot_api()