import os
import json
from fastapi import FastAPI, UploadFile, File, HTTPException, Header , Depends
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
from database import make_admin


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
class ScanLog(BaseModel):
    username: str
    url: str
    risk_level: str = "Unknown"

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
    from database import log_scan
    log_scan("anonymous", req.url, classifier_output["data"].get("risk_level", "Unknown"))
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

# ── Admin Routes ──────────────────────────────────────────

def require_admin(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated!")
    token = authorization.split(" ")[1]
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Token expired or invalid!")

    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_admin FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user or not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admin access required!")
    return username

@app.get("/admin/users")
def admin_get_users(admin: str = Depends(require_admin)):
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, created_at, is_active, is_admin FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"users": users}

@app.get("/admin/scans")
def admin_get_scans(admin: str = Depends(require_admin)):
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 100")
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"scans": scans}

@app.delete("/admin/users/{username}")
def admin_delete_user(username: str, admin: str = Depends(require_admin)):
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_active=0 WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return {"success": True, "message": f"User {username} banned!"}

@app.get("/admin/stats")
def admin_get_stats(admin: str = Depends(require_admin)):
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total FROM users")
    total_users = cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(*) as total FROM scans")
    total_scans = cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(*) as total FROM users WHERE is_active=1")
    active_users = cursor.fetchone()["total"]
    conn.close()
    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "active_users": active_users
    }