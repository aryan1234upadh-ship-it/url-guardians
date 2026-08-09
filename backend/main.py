import os
import json
from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
from dotenv import load_dotenv
from agents.classifier import classify_url
from agents.attack_planner import plan_attack
from agents.payload_suggester import suggest_payloads
from agents.report_writer import write_report
from pdf_generator import generate_pdf_report
from auth import login_user, register_user, verify_token
from database import init_db

load_dotenv()
init_db()

app = FastAPI(
    title="URL Guardians API",
    description="AI-powered URL Security Auditor — MCKV Institute of Engineering",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Models ────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class URLAnalyzeRequest(BaseModel):
    url: str
    mode: Optional[str] = "normal"

class AgentResult(BaseModel):
    agent_name: str
    status: str
    output: dict

class AnalyzeResponse(BaseModel):
    url: str
    status: str
    classification: Optional[AgentResult] = None
    attack_plan: Optional[AgentResult] = None
    payloads: Optional[AgentResult] = None
    report: Optional[AgentResult] = None
    attacker_brain: Optional[str] = None

# ── Root Routes ───────────────────────────────────────────

@app.get("/")
def root():
    return {
        "project": "URL Guardians",
        "team": "BTECH/IT-1/25 | MCKV Institute of Engineering",
        "status": "API is running ✅",
        "docs": "/docs"
    }

@app.get("/health")
def health_check():
    gemini_key_loaded = bool(os.getenv("GEMINI_API_KEY"))
    groq_key_loaded = bool(os.getenv("GROQ_API_KEY"))
    return {
        "status": "ok",
        "gemini_api_key_loaded": gemini_key_loaded,
        "groq_api_key_loaded": groq_key_loaded,
        "message": "All good!" if groq_key_loaded else "Set GROQ_API_KEY in your .env file"
    }

# ── Auth Routes ───────────────────────────────────────────

@app.post("/auth/register")
def register(req: RegisterRequest):
    result = register_user(req.username, req.email, req.password)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.post("/auth/login")
def login(req: LoginRequest):
    result = login_user(req.username, req.password)
    if not result["success"]:
        raise HTTPException(status_code=401, detail=result["message"])
    return result

@app.get("/auth/verify")
def verify(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated!")
    token = authorization.split(" ")[1]
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Token expired or invalid!")
    return {"valid": True, "username": username}

# ── Analyze Routes ────────────────────────────────────────

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(req: URLAnalyzeRequest):
    if not req.url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    # Agent 1 — URL Classifier
    classifier_output = classify_url(req.url)
    classification_result = AgentResult(
        agent_name="URL Classifier",
        status=classifier_output["status"],
        output=classifier_output["data"]
    )

    # Agent 2 — Attack Planner
    attack_output = plan_attack(req.url, classifier_output["data"])
    attack_result = AgentResult(
        agent_name="Attack Planner",
        status=attack_output["status"],
        output=attack_output["data"]
    )

    # Agent 3 — Payload Suggester
    payload_output = suggest_payloads(req.url, attack_output["data"])
    payload_result = AgentResult(
        agent_name="Payload Suggester",
        status=payload_output["status"],
        output=payload_output["data"]
    )

    # Agent 4 — Report Writer
    report_output = write_report(
        req.url,
        classifier_output["data"],
        attack_output["data"],
        payload_output["data"]
    )
    report_result = AgentResult(
        agent_name="Report Writer",
        status=report_output["status"],
        output=report_output["data"]
    )

    return AnalyzeResponse(
        url=req.url,
        status="success",
        classification=classification_result,
        attack_plan=attack_result,
        payloads=payload_result,
        report=report_result,
    )

@app.post("/export-pdf")
async def export_pdf(req: URLAnalyzeRequest):
    classifier_output = classify_url(req.url)
    attack_output = plan_attack(req.url, classifier_output["data"])
    payload_output = suggest_payloads(req.url, attack_output["data"])
    report_output = write_report(
        req.url,
        classifier_output["data"],
        attack_output["data"],
        payload_output["data"]
    )

    scan_data = {
        "url": req.url,
        "status": "success",
        "classification": {"output": classifier_output["data"]},
        "attack_plan": {"output": attack_output["data"]},
        "payloads": {"output": payload_output["data"]},
        "report": {"output": report_output["data"]},
    }

    pdf_path = generate_pdf_report(scan_data)
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename="url_guardians_report.pdf"
    )

@app.get("/history")
def get_scan_history():
    return {"scans": [], "message": "Scan history coming soon!"}