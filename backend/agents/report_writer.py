import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def write_report(url: str, classification: dict, attack_plan: dict, payloads: dict) -> dict:
    prompt = f"""
You are a senior cybersecurity report writer. Based on the full analysis,
write a professional security audit report.

URL: {url}
Classification: {json.dumps(classification)}
Attack Plan: {json.dumps(attack_plan)}
Payloads: {json.dumps(payloads)}

Return ONLY a JSON object with exactly these fields:
{{
    "report_title": "Security Audit Report for [URL]",
    "executive_summary": "3-4 sentence summary for non-technical readers",
    "risk_rating": "Critical | High | Medium | Low",
    "total_vulnerabilities": "number of vulnerabilities found",
    "findings": [
        {{
            "title": "vulnerability title",
            "severity": "Critical | High | Medium | Low",
            "description": "detailed description",
            "recommendation": "how to fix this vulnerability"
        }}
    ],
    "recommendations": ["list of overall security recommendations"],
    "conclusion": "2-3 sentence conclusion",
    "disclaimer": "This report is for authorized security testing only"
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
                "report_title": f"Security Report for {url}",
                "executive_summary": raw,
                "risk_rating": "Medium",
                "total_vulnerabilities": "0",
                "findings": [],
                "recommendations": [],
                "conclusion": "Report generation incomplete",
                "disclaimer": "This report is for authorized security testing only"
            }
        }
    except Exception as e:
        return {"status": "error", "data": {"error": str(e)}}