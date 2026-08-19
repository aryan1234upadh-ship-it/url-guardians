import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def suggest_payloads(url: str, attack_plan: dict) -> dict:
    prompt = f"""
You are an expert penetration tester. Based on this URL and attack plan,
suggest safe test payloads for each vulnerability.

URL: {url}
Attack Plan: {json.dumps(attack_plan)}

Return ONLY a JSON object with exactly these fields:
{{
    "payloads": [
        {{
            "vulnerability": "vulnerability name",
            "severity": "Critical | High | Medium | Low",
            "test_payloads": [
                {{
                    "payload": "actual test payload string",
                    "description": "what this payload tests",
                    "expected_result": "what happens if vulnerable"
                }}
            ]
        }}
    ],
    "total_payloads": "total number of payloads generated",
    "disclaimer": "These payloads are for authorized testing only"
}}

Only return the JSON. No explanation. No markdown. No backticks.
"""
    try:
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
        )
        raw = response.choices[0].message.content.strip()

        if raw.startswith("```"):
            raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]

        result = json.loads(raw)
        return {"status": "success", "data": result}

    except json.JSONDecodeError:
        return {
            "status": "success",
            "data": {
                "payloads": [],
                "total_payloads": "0",
                "disclaimer": raw
            }
        }
    except Exception as e:
        return {"status": "error", "data": {"error": str(e)}}