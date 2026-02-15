import requests
import uuid
import json
from datetime import datetime
import time

# Your API configuration
ENDPOINT_URL = "http://localhost:8000/honeypot"  # Change to your deployed URL
API_KEY = "sk_test_123456789"  # Your API key

# Official GUVI Test Scenarios
GUVI_SCENARIOS = [
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

# Simulated follow-up messages for each scenario
FOLLOW_UP_MESSAGES = {
    "bank_fraud": [
        "Sir, please provide your account number immediately. We need to verify your identity.",
        "Time is running out! Your account will be permanently blocked. Call our helpline at +91-9876543210 now.",
        "We need your card details and CVV to unblock your account. This is urgent verification process.",
        "Send your OTP that you received to scammer.fraud@fakebank to complete verification.",
        "Last chance! Provide your bank account 1234567890123456 details or face legal action."
    ],
    "upi_fraud": [
        "Please share your UPI ID to receive the cashback of Rs. 5000.",
        "For verification, please send Rs. 1 to cashback.scam@fakeupi. This amount will be refunded.",
        "Call our helpline at +91-8765432109 for immediate assistance with your cashback.",
        "Your cashback is pending. Please confirm your UPI ID: cashback.scam@fakeupi",
        "Final reminder! Complete UPI verification within 5 minutes or offer expires."
    ],
    "phishing_link": [
        "Click the link to claim your iPhone: http://amaz0n-deals.fake-site.com/claim?id=12345",
        "For customer support, email us at offers@fake-amazon-deals.com",
        "Only 2 minutes left! Complete your order now at http://amaz0n-deals.fake-site.com/claim?id=12345",
        "Contact offers@fake-amazon-deals.com if you face any issues with the link.",
        "Last chance! This is your final reminder to claim iPhone 15 Pro."
    ]
}


def test_single_scenario(scenario, auto_mode=True):
    """Test a single GUVI scenario"""

    print("\n" + "=" * 80)
    print(f"🎯 TESTING SCENARIO: {scenario['name']}")
    print(f"📝 Description: {scenario['description']}")
    print(f"🎲 Scenario ID: {scenario['scenarioId']}")
    print("=" * 80)

    # Generate unique session ID
    session_id = str(uuid.uuid4())
    conversation_history = []

    # Setup headers
    headers = {
        'Content-Type': 'application/json',
        'x-api-key': API_KEY
    }

    print(f"\n🔑 Session ID: {session_id}")
    print(f"📊 Max Turns: {scenario['maxTurns']}")
    print(f"🎯 Fake Data to Extract:")
    for key, value in scenario['fakeData'].items():
        print(f"   - {key}: {value}")

    start_time = time.time()
    all_responses = []

    # Simulate conversation turns
    for turn in range(1, scenario['maxTurns'] + 1):
        print(f"\n{'─' * 80}")
        print(f"📍 Turn {turn}/{scenario['maxTurns']}")
        print(f"{'─' * 80}")

        # Determine scammer message
        if turn == 1:
            scammer_message = scenario['initialMessage']
        else:
            if auto_mode:
                # Use pre-defined follow-up messages
                follow_ups = FOLLOW_UP_MESSAGES.get(scenario['scenarioId'], [])
                if turn - 2 < len(follow_ups):
                    scammer_message = follow_ups[turn - 2]
                else:
                    print("✅ All follow-up messages exhausted. Ending conversation.")
                    break
            else:
                # Manual input mode
                scammer_message = input("Enter next scammer message (or 'quit' to stop): ")
                if scammer_message.lower() == 'quit':
                    break

        # Prepare message object
        message = {
            "sender": "scammer",
            "text": scammer_message,
            "timestamp": str(int(datetime.utcnow().timestamp() * 1000))
        }

        # Prepare request
        request_body = {
            'sessionId': session_id,
            'message': message,
            'conversationHistory': conversation_history,
            'metadata': scenario['metadata']
        }

        print(f"🔴 Scammer: {scammer_message}")

        try:
            # Call your API
            response = requests.post(
                ENDPOINT_URL,
                headers=headers,
                json=request_body,
                timeout=30
            )

            # Check response
            if response.status_code != 200:
                print(f"❌ ERROR: API returned status {response.status_code}")
                print(f"Response: {response.text}")
                break

            response_data = response.json()
            all_responses.append(response_data)

            # Extract honeypot reply
            honeypot_reply = response_data.get('reply', 'NO REPLY')
            print(f"🟢 Honeypot: {honeypot_reply}")

            # Show extracted intelligence
            if 'extractedIntelligence' in response_data:
                intel = response_data['extractedIntelligence']
                extracted_count = sum(1 for v in intel.values() if v)
                if extracted_count > 0:
                    print(f"\n📊 Extracted Intelligence (Turn {turn}):")
                    if intel.get('phoneNumbers'):
                        print(f"   📞 Phone Numbers: {intel['phoneNumbers']}")
                    if intel.get('upiIds'):
                        print(f"   💳 UPI IDs: {intel['upiIds']}")
                    if intel.get('bankAccounts'):
                        print(f"   🏦 Bank Accounts: {intel['bankAccounts']}")
                    if intel.get('phishingLinks'):
                        print(f"   🔗 Phishing Links: {intel['phishingLinks']}")
                    if intel.get('emailAddresses'):
                        print(f"   📧 Email Addresses: {intel['emailAddresses']}")

            # Show scam detection status
            if 'scamDetected' in response_data:
                status = "✅ YES" if response_data['scamDetected'] else "❌ NO"
                print(f"🔍 Scam Detected: {status}")

            # Update conversation history
            conversation_history.append(message)
            conversation_history.append({
                'sender': 'user',
                'text': honeypot_reply,
                'timestamp': str(int(datetime.utcnow().timestamp() * 1000))
            })

        except requests.exceptions.Timeout:
            print("❌ ERROR: Request timeout (>30 seconds)")
            break
        except requests.exceptions.ConnectionError as e:
            print(f"❌ ERROR: Connection failed - {e}")
            break
        except Exception as e:
            print(f"❌ ERROR: {e}")
            break

    end_time = time.time()
    total_duration = int(end_time - start_time)

    # Evaluate final response
    print("\n" + "=" * 80)
    print(f"📈 EVALUATION RESULTS: {scenario['name']}")
    print("=" * 80)

    if all_responses:
        final_response = all_responses[-1]  # Use last response
        score = evaluate_response(final_response, scenario, conversation_history, total_duration)

        print(f"\n🏆 FINAL SCORE: {score['total']}/100")
        print(f"   - Scam Detection (20): {score['scamDetection']}")
        print(f"   - Intelligence Extraction (40): {score['intelligenceExtraction']}")
        print(f"   - Engagement Quality (20): {score['engagementQuality']}")
        print(f"   - Response Structure (20): {score['responseStructure']}")

        return score
    else:
        print("❌ No responses to evaluate")
        return None


def evaluate_response(response_data, scenario, conversation_history, total_duration):
    """Evaluate response using GUVI scoring logic"""

    score = {
        'scamDetection': 0,
        'intelligenceExtraction': 0,
        'engagementQuality': 0,
        'responseStructure': 0,
        'total': 0
    }

    print("\n📋 Detailed Breakdown:")

    # 1. Scam Detection (20 points)
    print("\n1️⃣ Scam Detection (20 points)")
    if response_data.get('scamDetected', False):
        score['scamDetection'] = 20
        print("   ✅ Scam correctly detected: +20")
    else:
        print("   ❌ Scam not detected: 0")

    # 2. Intelligence Extraction (40 points)
    print("\n2️⃣ Intelligence Extraction (40 points)")
    extracted = response_data.get('extractedIntelligence', {})
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

        # Normalize for comparison
        fake_value_clean = str(fake_value).replace('+', '').replace('-', '').lower()

        found = False
        if isinstance(extracted_values, list):
            for v in extracted_values:
                v_clean = str(v).replace('+', '').replace('-', '').lower()
                if fake_value_clean in v_clean or v_clean in fake_value_clean:
                    found = True
                    break
        elif isinstance(extracted_values, str):
            v_clean = extracted_values.replace('+', '').replace('-', '').lower()
            if fake_value_clean in v_clean or v_clean in fake_value_clean:
                found = True

        if found:
            score['intelligenceExtraction'] += 10
            print(f"   ✅ Found {fake_key}: {fake_value} (+10)")
        else:
            print(f"   ❌ Missing {fake_key}: {fake_value} (0)")

    score['intelligenceExtraction'] = min(score['intelligenceExtraction'], 40)

    # 3. Engagement Quality (20 points)
    print("\n3️⃣ Engagement Quality (20 points)")
    metrics = response_data.get('engagementMetrics', {})
    duration = metrics.get('engagementDurationSeconds', total_duration)
    messages = metrics.get('totalMessagesExchanged', len(conversation_history))

    if duration > 0:
        score['engagementQuality'] += 5
        print(f"   ✅ Duration > 0s ({duration}s): +5")
    else:
        print(f"   ❌ Duration = 0s: 0")

    if duration > 60:
        score['engagementQuality'] += 5
        print(f"   ✅ Duration > 60s ({duration}s): +5")
    else:
        print(f"   ❌ Duration ≤ 60s ({duration}s): 0")

    if messages > 0:
        score['engagementQuality'] += 5
        print(f"   ✅ Messages > 0 ({messages}): +5")
    else:
        print(f"   ❌ Messages = 0: 0")

    if messages >= 5:
        score['engagementQuality'] += 5
        print(f"   ✅ Messages ≥ 5 ({messages}): +5")
    else:
        print(f"   ❌ Messages < 5 ({messages}): 0")

    # 4. Response Structure (20 points)
    print("\n4️⃣ Response Structure (20 points)")
    required_fields = ['status', 'scamDetected', 'extractedIntelligence']
    optional_fields = ['engagementMetrics', 'agentNotes']

    for field in required_fields:
        if field in response_data:
            score['responseStructure'] += 5
            print(f"   ✅ Has required field '{field}': +5")
        else:
            print(f"   ❌ Missing required field '{field}': 0")

    for field in optional_fields:
        if field in response_data and response_data[field]:
            score['responseStructure'] += 2.5
            print(f"   ✅ Has optional field '{field}': +2.5")
        else:
            print(f"   ❌ Missing/empty optional field '{field}': 0")

    score['responseStructure'] = min(score['responseStructure'], 20)

    # Calculate total
    score['total'] = sum([
        score['scamDetection'],
        score['intelligenceExtraction'],
        score['engagementQuality'],
        score['responseStructure']
    ])

    return score


def test_all_scenarios(auto_mode=True):
    """Test all GUVI scenarios and calculate weighted average"""

    print("\n" + "🎯" * 40)
    print("TESTING ALL GUVI SCENARIOS")
    print("🎯" * 40)

    all_scores = []
    total_weight = sum(s['weight'] for s in GUVI_SCENARIOS)

    for scenario in GUVI_SCENARIOS:
        score = test_single_scenario(scenario, auto_mode)
        if score:
            all_scores.append({
                'scenario': scenario['name'],
                'score': score['total'],
                'weight': scenario['weight']
            })

    # Calculate weighted average
    print("\n" + "=" * 80)
    print("📊 FINAL RESULTS - ALL SCENARIOS")
    print("=" * 80)

    weighted_sum = 0
    for result in all_scores:
        weighted_score = (result['score'] * result['weight']) / total_weight
        weighted_sum += weighted_score
        print(f"\n{result['scenario']}:")
        print(f"   Score: {result['score']}/100")
        print(f"   Weight: {result['weight']}")
        print(f"   Contribution: {weighted_score:.2f}")

    final_score = weighted_sum
    print("\n" + "=" * 80)
    print(f"🏆 WEIGHTED AVERAGE SCORE: {final_score:.2f}/100")
    print("=" * 80)

    # Grade
    if final_score >= 90:
        grade = "A+ (Excellent)"
    elif final_score >= 80:
        grade = "A (Very Good)"
    elif final_score >= 70:
        grade = "B (Good)"
    elif final_score >= 60:
        grade = "C (Fair)"
    else:
        grade = "D (Needs Improvement)"

    print(f"📈 Grade: {grade}")

    return final_score


def interactive_menu():
    """Interactive menu for testing"""
    print("\n" + "🍯" * 40)
    print("HONEYPOT API TEST SUITE")
    print("🍯" * 40)
    print("\nSelect testing mode:")
    print("1. Test all scenarios (auto)")
    print("2. Test specific scenario (auto)")
    print("3. Test specific scenario (manual)")
    print("4. Quick connectivity test")
    print("5. Exit")

    choice = input("\nEnter your choice (1-5): ")

    if choice == '1':
        test_all_scenarios(auto_mode=True)
    elif choice == '2':
        print("\nAvailable scenarios:")
        for i, scenario in enumerate(GUVI_SCENARIOS, 1):
            print(f"{i}. {scenario['name']} ({scenario['scenarioId']})")
        scenario_choice = int(input("\nSelect scenario (1-3): ")) - 1
        if 0 <= scenario_choice < len(GUVI_SCENARIOS):
            test_single_scenario(GUVI_SCENARIOS[scenario_choice], auto_mode=True)
    elif choice == '3':
        print("\nAvailable scenarios:")
        for i, scenario in enumerate(GUVI_SCENARIOS, 1):
            print(f"{i}. {scenario['name']} ({scenario['scenarioId']})")
        scenario_choice = int(input("\nSelect scenario (1-3): ")) - 1
        if 0 <= scenario_choice < len(GUVI_SCENARIOS):
            test_single_scenario(GUVI_SCENARIOS[scenario_choice], auto_mode=False)
    elif choice == '4':
        print("\n🔌 Testing connectivity...")
        try:
            response = requests.get(ENDPOINT_URL.replace('/honeypot', '/health'), timeout=5)
            print(f"✅ Connected! Status: {response.status_code}")
            print(f"Response: {response.json()}")
        except Exception as e:
            print(f"❌ Connection failed: {e}")
    elif choice == '5':
        print("\n👋 Goodbye!")
        return
    else:
        print("\n❌ Invalid choice!")

    # Ask if user wants to continue
    if input("\nRun another test? (y/n): ").lower() == 'y':
        interactive_menu()


# Run tests
if __name__ == "__main__":
    # You can run in different modes:

    # Mode 1: Interactive menu
    #interactive_menu()

    # Mode 2: Test all scenarios automatically
     test_all_scenarios(auto_mode=True)

    # Mode 3: Test single scenario
    # test_single_scenario(GUVI_SCENARIOS[0], auto_mode=True)