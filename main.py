from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import re
import uuid
from datetime import datetime

app = FastAPI(title="DataGuard AI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── PII Patterns ──────────────────────────────────────────────────────────────
PATTERNS = [
    {"name": "Email Address",       "regex": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",          "severity": "HIGH"},
    {"name": "Phone Number (IN)",   "regex": r"(\+91[\-\s]?)?[6-9]\d{9}",                                  "severity": "HIGH"},
    {"name": "Aadhaar Number",      "regex": r"[2-9]\d{3}[\s\-]\d{4}[\s\-]\d{4}",                         "severity": "CRITICAL"},
    {"name": "PAN Card",            "regex": r"[A-Z]{5}[0-9]{4}[A-Z]",                                     "severity": "CRITICAL"},
    {"name": "Credit Card",         "regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "severity": "CRITICAL"},
    {"name": "API Key / Token",     "regex": r"(?:api[_\-]?key|token|secret)\s*[:=]\s*\S+",               "severity": "CRITICAL"},
    {"name": "Password Exposed",    "regex": r"password\s*[:=]\s*\S+",                                     "severity": "CRITICAL"},
    {"name": "IP Address",          "regex": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",                  "severity": "MEDIUM"},
    {"name": "SSN (US)",            "regex": r"\b\d{3}-\d{2}-\d{4}\b",                                    "severity": "CRITICAL"},
    {"name": "Confidential Label",  "regex": r"\b(confidential|top secret|internal only|restricted|classified)\b", "severity": "MEDIUM"},
]

def mask_value(val: str) -> str:
    if len(val) <= 4:
        return "****"
    return val[:2] + "*" * min(len(val) - 4, 8) + val[-2:]

def get_risk_level(findings: list) -> str:
    severities = [f["severity"] for f in findings]
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    if findings:
        return "LOW"
    return "SAFE"

# ── Models ────────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    text: str
    source: Optional[str] = "Manual Input"

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"message": "DataGuard AI API is running", "version": "1.0.0"}

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.post("/scan")
def scan_text(req: ScanRequest):
    findings = []
    for pat in PATTERNS:
        matches = re.findall(pat["regex"], req.text, re.IGNORECASE)
        for match in matches:
            raw = match if isinstance(match, str) else match[0]
            findings.append({
                "id": str(uuid.uuid4())[:8],
                "type": pat["name"],
                "severity": pat["severity"],
                "masked_value": mask_value(raw),
            })

    risk = get_risk_level(findings)
    return {
        "scan_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "source": req.source,
        "risk_level": risk,
        "total_findings": len(findings),
        "safe": len(findings) == 0,
        "findings": findings,
    }

@app.get("/patterns")
def get_patterns():
    return {"patterns": [{"name": p["name"], "severity": p["severity"]} for p in PATTERNS]}
