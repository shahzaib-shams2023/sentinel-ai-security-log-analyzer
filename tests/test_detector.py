import pytest
from app.parsers.syslog_parser import LogParser
from app.detector.statistical import AnomalyDetector
from app.scenarios import DEMO_SCENARIOS


def test_detect_brute_force_cluster():
    raw = DEMO_SCENARIOS["brute_force_privilege_escalation"]
    events = LogParser.parse_stream(raw)
    alerts = AnomalyDetector.detect_anomalies(events)

    brute_alerts = [a for a in alerts if "Brute Force" in a.title]
    assert len(brute_alerts) == 1
    assert brute_alerts[0].source_ip == "198.51.100.44"
    assert brute_alerts[0].mitre_technique.technique_id == "T1110"


def test_detect_log4j_exploit_payload():
    raw = DEMO_SCENARIOS["log4j_exploit_injection"]
    events = LogParser.parse_stream(raw)
    alerts = AnomalyDetector.detect_anomalies(events)

    exploit_alerts = [a for a in alerts if "Log4Shell" in a.title]
    assert len(exploit_alerts) == 1
    assert exploit_alerts[0].severity == "CRITICAL"
    assert exploit_alerts[0].mitre_technique.technique_id == "T1190"


def test_benign_traffic_yields_zero_alerts():
    raw = DEMO_SCENARIOS["benign_baseline"]
    events = LogParser.parse_stream(raw)
    alerts = AnomalyDetector.detect_anomalies(events)
    assert len(alerts) == 0

