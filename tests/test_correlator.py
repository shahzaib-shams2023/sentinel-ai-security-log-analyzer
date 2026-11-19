import pytest
from app.parsers.syslog_parser import LogParser
from app.detector.statistical import AnomalyDetector
from app.detector.correlator import ThreatCorrelator
from app.playbooks.generator import PlaybookGenerator
from app.scenarios import DEMO_SCENARIOS


def test_correlate_multi_stage_privilege_escalation():
    raw = DEMO_SCENARIOS["brute_force_privilege_escalation"]
    events = LogParser.parse_stream(raw)
    alerts = AnomalyDetector.detect_anomalies(events)
    report = ThreatCorrelator.correlate_incident(events, alerts)

    assert report.attack_detected is True
    assert report.overall_severity == "CRITICAL"
    assert "Privilege Escalation" in report.mitre_tactics_observed
    assert "Initial Access" in report.mitre_tactics_observed

    playbook = PlaybookGenerator.generate_playbook(report)
    assert playbook is not None
    assert any(s.action_type == "FIREWALL_BLOCK" for s in playbook.remediation_steps)
    assert any(s.action_type == "ACCOUNT_LOCK" for s in playbook.remediation_steps)

