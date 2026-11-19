from fastapi.testclient import TestClient
from app.main import app
from app.scenarios import DEMO_SCENARIOS

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"


def test_scenarios_endpoint():
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    data = res.json()
    assert "brute_force_privilege_escalation" in data
    assert "log4j_exploit_injection" in data


def test_analyze_logs_endpoint():
    payload = {
        "raw_logs": DEMO_SCENARIOS["brute_force_privilege_escalation"]
    }
    res = client.post("/api/logs/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["attack_detected"] is True
    assert data["overall_severity"] == "CRITICAL"
    assert len(data["alerts"]) > 0
    assert data["playbook"] is not None

