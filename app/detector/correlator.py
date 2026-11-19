import uuid
from typing import List, Set
from app.models.schemas import LogEvent, AnomalyAlert, IncidentReport
from app.detector.statistical import AnomalyDetector
from app.mitre.matrix import MitreMapper


class ThreatCorrelator:
    @classmethod
    def correlate_incident(cls, events: List[LogEvent], alerts: List[AnomalyAlert]) -> IncidentReport:
        incident_id = f"INC-{str(uuid.uuid4())[:8].upper()}"
        
        # Check for multi-stage attack progression
        attacker_ips: Set[str] = set([a.source_ip for a in alerts if a.source_ip])
        tactics_observed: Set[str] = set([a.mitre_technique.tactic for a in alerts if a.mitre_technique])
        
        has_brute_force = any("Brute Force" in a.title for a in alerts)
        has_exploit = any("Exploitation" in a.title or "JNDI" in a.title for a in alerts)
        
        # Check if an attacker IP that failed later succeeded
        compromised_accounts = []
        privilege_elevated = False

        for ip in attacker_ips:
            for evt in events:
                if evt.source_ip == ip and evt.status == "SUCCESS":
                    if evt.action in ("SSH_AUTH_SUCCESS", "LOGIN_SUCCESS") or "Accepted" in evt.raw_log:
                        compromised_accounts.append((ip, evt.user or "root"))
                        tactics_observed.add("Initial Access")

        for evt in events:
            if "sudo:" in evt.raw_log or evt.action == "PRIVILEGE_ELEVATION":
                privilege_elevated = True
                tactics_observed.add("Privilege Escalation")

        # Determine overall severity
        if has_exploit or (has_brute_force and compromised_accounts) or privilege_elevated:
            overall_severity = "CRITICAL"
        elif has_brute_force or len(alerts) >= 2:
            overall_severity = "HIGH"
        elif len(alerts) == 1:
            overall_severity = alerts[0].severity
        else:
            overall_severity = "LOW"

        # Generate attack summary
        if overall_severity == "CRITICAL":
            summary = (
                f"Multi-stage intrusion campaign confirmed. Adversary originated from IP(s) {', '.join(attacker_ips) or 'external source'}, "
                f"executed initial attack vector, achieved authenticated access"
                f"{' and escalated privileges to root/admin' if privilege_elevated else ''}. "
                "Immediate containment protocol required."
            )
        elif overall_severity == "HIGH":
            summary = (
                f"High-threat activity detected. {len(alerts)} suspicious anomaly clusters identified including "
                f"targeted brute-force authentication. Compromise is suspected or impending."
            )
        elif len(alerts) > 0:
            summary = f"Isolated security anomalies detected across {len(events)} analyzed events. Review source telemetry."
        else:
            summary = f"Baseline audit completed. No actionable intrusion signatures or anomalous behavior detected."

        return IncidentReport(
            incident_id=incident_id,
            total_logs_analyzed=len(events),
            anomalies_detected=len(alerts),
            attack_detected=len(alerts) > 0 or len(compromised_accounts) > 0,
            overall_severity=overall_severity,
            attack_summary=summary,
            alerts=alerts,
            mitre_tactics_observed=list(tactics_observed)
        )

