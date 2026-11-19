from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from app.config import settings
from app.models.schemas import AnalyzeLogRequest, IncidentReport
from app.parsers.syslog_parser import LogParser
from app.detector.statistical import AnomalyDetector
from app.detector.correlator import ThreatCorrelator
from app.playbooks.generator import PlaybookGenerator
from app.scenarios import DEMO_SCENARIOS

app = FastAPI(
    title=settings.app_name,
    description="SentinelAI Threat Intelligence & SIEM Log Anomaly Detection Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def root():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "SentinelAI SIEM Analysis Service is active."}


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.app_name,
        "environment": settings.environment
    }


@app.get("/api/scenarios")
async def get_demo_scenarios():
    return DEMO_SCENARIOS


@app.post("/api/logs/analyze", response_model=IncidentReport)
async def analyze_security_logs(request: AnalyzeLogRequest):
    try:
        # Step 1: Parse logs into standardized events
        events = LogParser.parse_stream(request.raw_logs)
        if not events:
            raise HTTPException(status_code=400, detail="Unable to extract valid log events from provided input.")

        # Step 2: Detect individual anomalies & exploits
        alerts = AnomalyDetector.detect_anomalies(events)

        # Step 3: Correlate multi-stage incident & MITRE tactics
        report = ThreatCorrelator.correlate_incident(events, alerts)

        # Step 4: Generate incident response playbook
        report.playbook = PlaybookGenerator.generate_playbook(report)

        return report
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")

