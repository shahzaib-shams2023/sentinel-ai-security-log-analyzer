from typing import Dict, Optional
from app.models.schemas import MitreTechnique

MITRE_DATABASE: Dict[str, MitreTechnique] = {
    "T1110": MitreTechnique(
        technique_id="T1110",
        tactic="Credential Access",
        name="Brute Force",
        description="Adversaries systematically attempt multiple passwords or credential pairs against authentication interfaces."
    ),
    "T1078": MitreTechnique(
        technique_id="T1078",
        tactic="Initial Access",
        name="Valid Accounts",
        description="Adversaries obtain and abuse credentials of existing accounts to gain unauthorized access."
    ),
    "T1190": MitreTechnique(
        technique_id="T1190",
        tactic="Initial Access",
        name="Exploit Public-Facing Application",
        description="Adversaries exploit software vulnerabilities or command injection flaws in Internet-facing web servers."
    ),
    "T1548": MitreTechnique(
        technique_id="T1548",
        tactic="Privilege Escalation",
        name="Abuse Elevation Control Mechanism",
        description="Adversaries circumvent mechanisms designed to control elevation of privileges (e.g., sudo abuse)."
    ),
    "T1046": MitreTechnique(
        technique_id="T1046",
        tactic="Discovery",
        name="Network Service Discovery",
        description="Adversaries enumerate listening ports, remote services, and endpoints to identify target vulnerabilities."
    ),
    "T1567": MitreTechnique(
        technique_id="T1567",
        tactic="Exfiltration",
        name="Exfiltration Over Web Service",
        description="Adversaries steal sensitive assets by transmitting archives or buckets to external command and control endpoints."
    )
}


class MitreMapper:
    @staticmethod
    def get_technique(technique_id: str) -> Optional[MitreTechnique]:
        return MITRE_DATABASE.get(technique_id)

