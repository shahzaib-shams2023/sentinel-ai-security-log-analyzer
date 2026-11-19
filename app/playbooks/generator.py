from typing import Optional
from app.models.schemas import IncidentReport, SOCPlaybook, PlaybookStep


class PlaybookGenerator:
    @staticmethod
    def generate_playbook(report: IncidentReport) -> Optional[SOCPlaybook]:
        if not report.attack_detected:
            return None

        steps = []
        step_num = 1

        # Collect unique attacker IPs and targeted users
        attacker_ips = list(set([a.source_ip for a in report.alerts if a.source_ip]))
        targeted_users = list(set([a.targeted_user for a in report.alerts if a.targeted_user]))

        # Step 1: Network Perimeter Ingress Block
        for ip in attacker_ips:
            steps.append(PlaybookStep(
                step_number=step_num,
                action_type="FIREWALL_BLOCK",
                command=f"iptables -I INPUT 1 -s {ip} -j DROP && echo 'Blocked {ip} on ingress'",
                description=f"Instantly drop all incoming TCP/UDP traffic from adversary IP {ip} at host boundary.",
                automated=True
            ))
            step_num += 1

        # Step 2: Identity Lockdown & Token Revocation
        for user in targeted_users:
            steps.append(PlaybookStep(
                step_number=step_num,
                action_type="ACCOUNT_LOCK",
                command=f"passwd -l {user} && pkill -u {user} -9",
                description=f"Lock credentials for potentially compromised user '{user}' and terminate active interactive sessions.",
                automated=True
            ))
            step_num += 1

        # Step 3: Forensic Memory & Network Socket Preservation
        steps.append(PlaybookStep(
            step_number=step_num,
            action_type="FORENSIC_DUMP",
            command="ss -tupna > /tmp/forensic_sockets.txt && ps auxwf > /tmp/forensic_ps.txt",
            description="Capture volatile process trees, listening sockets, and active connections before host shutdown.",
            automated=True
        ))
        step_num += 1

        # Step 4: Web Application Firewall Rule (if exploit pattern detected)
        has_exploit = any("Exploit" in a.title or "JNDI" in a.title for a in report.alerts)
        if has_exploit:
            steps.append(PlaybookStep(
                step_number=step_num,
                action_type="WAF_RULE_UPDATE",
                command="aws wafv2 update-ip-set --scope CLOUDFRONT --id $WAF_ID --addresses '[\"" + '","'.join([f"{ip}/32" for ip in attacker_ips]) + "\"]'",
                description="Propagate global WAF block across CDN edge distribution to prevent further RCE payloads.",
                automated=False
            ))
            step_num += 1

        containment_time = 5 if report.overall_severity == "CRITICAL" else 15

        return SOCPlaybook(
            incident_id=report.incident_id,
            incident_type="Automated Intrusion Containment & Forensics",
            severity=report.overall_severity,
            remediation_steps=steps,
            estimated_containment_time_minutes=containment_time
        )

