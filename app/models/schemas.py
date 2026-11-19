from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime


class LogEvent(BaseModel):
    id: str
    timestamp: str
    raw_log: str
    log_format: str  # syslog, cef, json, apache
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None  # SUCCESS, FAILURE, ERROR, BLOCKED
    service: Optional[str] = None
    payload: Optional[str] = None


class MitreTechnique(BaseModel):
    technique_id: str  # e.g., T1110, T1078, T1059
    tactic: str        # Initial Access, Credential Access, etc.
    name: str
    description: str


class AnomalyAlert(BaseModel):
    alert_id: str
    severity: str      # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    evidence_events: List[str]  # Event IDs
    source_ip: Optional[str] = None
    targeted_user: Optional[str] = None
    mitre_technique: Optional[MitreTechnique] = None
    confidence: float


class PlaybookStep(BaseModel):
    step_number: int
    action_type: str   # FIREWALL_BLOCK, ACCOUNT_LOCK, TOKEN_REVOKE, FORENSIC_DUMP
    command: str
    description: str
    automated: bool = True


class SOCPlaybook(BaseModel):
    incident_id: str
    incident_type: str
    severity: str
    remediation_steps: List[PlaybookStep]
    estimated_containment_time_minutes: int


class IncidentReport(BaseModel):
    incident_id: str
    total_logs_analyzed: int
    anomalies_detected: int
    attack_detected: bool
    overall_severity: str
    attack_summary: str
    alerts: List[AnomalyAlert]
    mitre_tactics_observed: List[str]
    playbook: Optional[SOCPlaybook] = None
    analyzed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class AnalyzeLogRequest(BaseModel):
    raw_logs: str = Field(..., min_length=10, description="Raw multi-line log string or JSON array")
    scenario_name: Optional[str] = None

