import httpx
import json
import asyncio
import time
from typing import List, Dict, Any

# Competition Configuration
API_URL = "https://incepta.onrender.com/api/honeypot"
API_KEY = "honeypot-secure-key-2026"

# Test Dataset
TEST_CASES = [
    {
        "name": "Classic UPI Scam",
        "message": "URGENT: Your SBI account is compromised. To avoid permanent block, pay Rs 500 verification fee to UPI: security.sbi@ybl now!",
        "expected_scam": True,
        "expected_type": "bank_impersonation",
        "must_extract": ["security.sbi@ybl"]
    },
    {
        "name": "Work From Home Scam",
        "message": "Earn Rs 5000 daily by simple Like/Follow tasks on YouTube. No experience needed. Contact HR Priya on WhatsApp: 9876543210 to join.",
        "expected_scam": True,
        "expected_type": "job_scam",
        "must_extract": ["9876543210"]
    },
    {
        "name": "Lottery Fraud",
        "message": "CONGRATULATIONS! You have won Rs 25,00,000 in KBC Lucky Draw. To claim your prize, call Mr. Kumar at 9123456789. Ref: KBC-2024-X.",
        "expected_scam": True,
        "expected_type": "lottery_fraud",
        "must_extract": ["9123456789"]
    },
    {
        "name": "KYC Phishing",
        "message": "Dear customer, your PAN card is not updated with your account. Your account will be suspended. Update at http://sbi-kyc-verify.xyz/login immediately.",
        "expected_scam": True,
        "expected_type": "phishing",
        "must_extract": ["http://sbi-kyc-verify.xyz/login"]
    },
    {
        "name": "Hindi/Hinglish Scam",
        "message": "Badhai ho! Aapka number ₹25,00,000 lottery ke liye select hua hai. Turant contact karein WhatsApp par: 9988776655. Sirf 2 ghante bache hain!",
        "expected_scam": True,
        "expected_type": "lottery_fraud",
        "must_extract": ["9988776655"]
    },
    {
        "name": "Sarkari/Police Threat (Hinglish)",
        "message": "Cyber Crime Cell se bol raha hoon. Aapke account se illegal drugs transaction hui hai. Case No CBI-998. Arrest warrant se bachne ke liye Inspector Ko call karein: 9112233445",
        "expected_scam": True,
        "expected_type": "government_impersonation",
        "must_extract": ["9112233445"]
    },
    {
        "name": "False Positive Case (Legit OTP)",
        "message": "123456 is your secret OTP for transaction at Amazon. Do not share this with anyone. SBI Bank.",
        "expected_scam": False,
        "expected_type": None,
        "must_extract": []
    },
    {
        "name": "False Positive Case (Legit Request)",
        "message": "Hey Rahul, this is mom. Can you send 1000 rupees to my UPI mom@ybl for groceries? Local shop doesn't take cash.",
        "expected_scam": False,
        "expected_type": None,
        "must_extract": []
    }
]

async def run_test(client: httpx.AsyncClient, test_case: Dict[str, Any]) -> Dict[str, Any]:
    print(f"Running Test: {test_case['name']}...")
    
    start_time = time.time()
    try:
        response = await client.post(
            API_URL,
            headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            json={"message": test_case["message"]},
            timeout=30.0
        )
        duration = (time.time() - start_time) * 1000
        
        if response.status_code != 200:
            return {"name": test_case["name"], "success": False, "error": f"Status {response.status_code}", "time": duration}
        
        data = response.json()
        
        # Validation Logic
        detection_match = data["is_scam"] == test_case["expected_scam"]
        
        # Check extraction
        intelligence = data["intelligence"]
        extracted_text = json.dumps(intelligence)
        extraction_success = True
        for item in test_case["must_extract"]:
            if item not in extracted_text:
                extraction_success = False
                break
        
        # Persona check
        persona_active = "persona_used" in data["engagement_metrics"]
        
        success = detection_match and extraction_success
        
        return {
            "name": test_case["name"],
            "success": success,
            "detection_correct": detection_match,
            "extraction_correct": extraction_success,
            "type_found": data.get("scam_type"),
            "confidence": data.get("confidence"),
            "latency": duration,
            "response_text": data.get("response")[:50] + "..."
        }
    except Exception as e:
        return {"name": test_case["name"], "success": False, "error": str(e), "time": 0}

async def main():
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*[run_test(client, tc) for tc in TEST_CASES])
    
    print("\n" + "="*50)
    print("INCEPTA HONEYPOT BENCHMARK RESULTS")
    print("="*50)
    
    passed = 0
    total_latency = 0
    
    for r in results:
        status = "✅ PASS" if r.get("success") else "❌ FAIL"
        if r.get("success"): passed += 1
        total_latency += r.get("latency", 0)
        
        print(f"[{status}] {r['name']}")
        print(f"   - Latency: {r.get('latency', 0):.2f}ms")
        print(f"   - Confidence: {r.get('confidence', 0)*100:.1f}%")
        print(f"   - Response: {r.get('response_text')}")
        if not r.get("success"):
            print(f"   - Detection Correct: {r.get('detection_correct')}")
            print(f"   - Extraction Correct: {r.get('extraction_correct')}")
    
    print("="*50)
    print(f"OVERALL SCORE: {passed}/{len(TEST_CASES)} ({(passed/len(TEST_CASES))*100:.1f}%)")
    print(f"AVG LATENCY: {total_latency/len(TEST_CASES):.2f}ms")
    print("="*50)

if __name__ == "__main__":
    asyncio.run(main())
