import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def plan_attack(url: str, classification: dict) -> dict:
    prompt = f"""
You are a senior penetration tester. Based on this URL and its classification,
create a detailed attack plan.

URL: {url}
Classification Data: {json.dumps(classification)}

Return ONLY a JSON object with exactly these fields:
{{
    "vulnerabilities": [
        {{
            "name": "vulnerability name e.g. SQL Injection",
            "severity": "Critical | High | Medium | Low",
            "description": "1-2 sentences explaining the vulnerability",
            "attack_vector": "exactly how an attacker would exploit this",
            "affected_parameter": "which part of the URL is vulnerable"
        }}
    ],
    "priority_order": ["list vulnerabilities in order to test first"],
    "estimated_risk_score": "number from 1-10",
    "summary": "2-3 sentence overall attack plan summary"
}}

Only return the JSON. No explanation. No markdown. No backticks.
"""
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
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
                "vulnerabilities": [],
                "priority_order": [],
                "estimated_risk_score": "5",
                "summary": raw
            }
        }
    except Exception as e:
        return {"status": "error", "data": {"error": str(e)}}