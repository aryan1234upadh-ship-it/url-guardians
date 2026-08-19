import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def classify_url(url: str) -> dict:
    prompt = f"""
You are a senior cybersecurity expert. Analyze this URL and classify it.

URL: {url}

Return ONLY a JSON object with exactly these fields:
{{
  "endpoint_type": "login | api | admin | public | payment | upload | other",
  "risk_level": "High | Medium | Low",
  "likely_tech_stack": ["e.g. Django", "MySQL"],
  "interesting_parameters": ["any query params or path variables worth testing"],
  "initial_observations": "2-3 sentences about what looks interesting or suspicious",
  "recommended_tests": ["IDOR", "SQLi", "XSS", "SSRF", "Auth Bypass"]
}}

Only return the JSON. No explanation. No markdown. No backticks.
"""
    try:
        response = client.chat.completions.create(
            model="llama3-8b-8192",
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
                "endpoint_type": "unknown",
                "risk_level": "Medium",
                "likely_tech_stack": [],
                "interesting_parameters": [],
                "initial_observations": raw,
                "recommended_tests": []
            }
        }
    except Exception as e:
        return {"status": "error", "data": {"error": str(e)}}