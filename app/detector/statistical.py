import re
from typing import List, Dict
from collections import defaultdict
from app.models.schemas import LogEvent, AnomalyAlert
from app.mitre.matrix import MitreMapper
from app.config import settings


class AnomalyDetector:
    EXPLOIT_PATTERNS = [
        (r"\$\{jndi:(?:ldap|rmi|dns)://", "T1190", "Log4Shell (CVE-2021-44228) JNDI Injection Attempt", "CRITICAL"),
        (r"(?:UNION\s+SELECT|'\s*OR\s*'1'='1|WAITFOR\s+DELAY)", "T1190", "SQL Injection Web Exploitation Attempt", "HIGH"),
        (r"(?:\.\./\.\./|/etc/passwd|/windows/win\.ini)", "T1190", "Path Traversal / Local File Inclusion (LFI)", "HIGH"),
        (r"(?:powershell(?:\.exe)?\s+-(?:enc|encodedcommand)|curl\s+[^\s]+\s+\|\s+bash)", "T1059", "Suspicious Shell Command Execution Download Pipeline", "CRITICAL")
    ]

    @classmethod
    def detect_anomalies(cls, events: List[LogEvent]) -> List[AnomalyAlert]:
        alerts: List[AnomalyAlert] = []
        
        # 1. Signature / Exploit Payload Scanning
        for evt in events:
            text_to_scan = f"{evt.raw_log} {evt.payload or ''}"
            for pattern, tech_id, title, sev in cls.EXPLOIT_PATTERNS:
                if re.search(pattern, text_to_scan, re.IGNORECASE):
                    alerts.append(AnomalyAlert(
                        alert_id=f"ALT-EXPLOIT-{evt.id}",
                        severity=sev,
                        title=title,
                        description=f"Suspicious payload matching signature '{pattern}' detected from {evt.source_ip or 'unknown IP'}.",
                        evidence_events=[evt.id],
                        source_ip=evt.source_ip,
                        targeted_user=evt.user,
                        mitre_technique=MitreMapper.get_technique(tech_id),
                        confidence=0.98
                    ))

        # 2. Authentication Failure & Brute Force Analysis
        ip_failures = defaultdict(list)
        for evt in events:
            if evt.status == "FAILURE" and evt.source_ip:
                ip_failures[evt.source_ip].append(evt)

        for ip, fail_evts in ip_failures.items():
            if len(fail_evts) >= settings.brute_force_threshold:
                users_targeted = list(set([e.user for e in fail_evts if e.user]))
                alerts.append(AnomalyAlert(
                    alert_id=f"ALT-BRUTE-{ip.replace('.', '_')}",
                    severity="HIGH",
                    title="Distributed / High-Frequency Brute Force Authentication",
                    description=(
                        f"Detected {len(fail_evts)} consecutive failed authentication attempts from IP {ip} "
                        f"targeting accounts: {', '.join(users_targeted) or 'multiple users'}."
                    ),
                    evidence_events=[e.id for e in fail_evts],
                    source_ip=ip,
                    targeted_user=users_targeted[0] if users_targeted else None,
                    mitre_technique=MitreMapper.get_technique("T1110"),
                    confidence=0.95
                ))

        # 3. Port Scan / Network Reconnaissance
        ip_web_actions = defaultdict(list)
        for evt in events:
            if evt.log_format in ("web_access", "cef") and evt.source_ip:
                ip_web_actions[evt.source_ip].append(evt)

        for ip, act_evts in ip_web_actions.items():
            distinct_endpoints = set([e.payload for e in act_evts if e.payload])
            if len(distinct_endpoints) >= 8:
                alerts.append(AnomalyAlert(
                    alert_id=f"ALT-SCAN-{ip.replace('.', '_')}",
                    severity="MEDIUM",
                    title="Automated Web Reconnaissance / Vulnerability Directory Scan",
                    description=f"Host {ip} sequentially probed {len(distinct_endpoints)} distinct application endpoints.",
                    evidence_events=[e.id for e in act_evts],
                    source_ip=ip,
                    targeted_user=None,
                    mitre_technique=MitreMapper.get_technique("T1046"),
                    confidence=0.90
                ))

        return alerts

