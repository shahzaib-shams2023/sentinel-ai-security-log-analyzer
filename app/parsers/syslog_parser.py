import re
import json
import uuid
from typing import List, Optional
from datetime import datetime
from app.models.schemas import LogEvent


class LogParser:
    IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    TIMESTAMP_REGEX = r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"

    @classmethod
    def parse_stream(cls, raw_text: str) -> List[LogEvent]:
        """Parses lines into standardized LogEvent records."""
        events: List[LogEvent] = []
        lines = [line.strip() for line in raw_text.strip().split("\n") if line.strip()]

        for i, line in enumerate(lines):
            event = cls._parse_single_line(line, i + 1)
            if event:
                events.append(event)

        return events

    @classmethod
    def _parse_single_line(cls, line: str, index: int) -> LogEvent:
        event_id = f"EVT-{index:04d}-{str(uuid.uuid4())[:6]}"
        now_ts = datetime.utcnow().isoformat()

        # Try JSON
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                return LogEvent(
                    id=event_id,
                    timestamp=data.get("timestamp", now_ts),
                    raw_log=line,
                    log_format="json",
                    source_ip=data.get("src_ip") or data.get("source_ip") or data.get("client_ip"),
                    dest_ip=data.get("dst_ip") or data.get("dest_ip"),
                    user=data.get("user") or data.get("username"),
                    action=data.get("action") or data.get("event"),
                    status=(data.get("status") or "UNKNOWN").upper(),
                    service=data.get("service") or data.get("app"),
                    payload=data.get("payload") or data.get("query")
                )
            except Exception:
                pass

        # Try CEF
        if "CEF:" in line:
            return cls._parse_cef(line, event_id, now_ts)

        # Try Web Access Log
        if '"' in line and any(m in line for m in ["GET", "POST", "PUT", "DELETE", "HEAD"]):
            return cls._parse_web(line, event_id, now_ts)

        # Fallback to standard Syslog
        return cls._parse_syslog(line, event_id, now_ts)

    @classmethod
    def _parse_cef(cls, line: str, event_id: str, default_ts: str) -> LogEvent:
        src = re.search(r"src=([^\s]+)", line)
        dst = re.search(r"dst=([^\s]+)", line)
        suser = re.search(r"suser=([^\s]+)", line)
        act = re.search(r"act=([^\s]+)", line) or re.search(r"msg=([^\s]+)", line)

        status = "SUCCESS"
        if any(f in line.lower() for f in ["fail", "denied", "block", "reject"]):
            status = "FAILURE"

        return LogEvent(
            id=event_id,
            timestamp=default_ts,
            raw_log=line,
            log_format="cef",
            source_ip=src.group(1) if src else None,
            dest_ip=dst.group(1) if dst else None,
            user=suser.group(1) if suser else None,
            action=act.group(1) if act else "network_event",
            status=status,
            service="CEF_Firewall",
            payload=None
        )

    @classmethod
    def _parse_web(cls, line: str, event_id: str, default_ts: str) -> LogEvent:
        ip_match = re.search(cls.IP_REGEX, line)
        source_ip = ip_match.group(0) if ip_match else None

        req_match = re.search(r'"([A-Z]+)\s+([^"\s]+)', line)
        action = req_match.group(1) if req_match else "HTTP_REQUEST"
        payload = req_match.group(2) if req_match else None

        status = "SUCCESS"
        if " 401 " in line or " 403 " in line or " 400 " in line or " 500 " in line:
            status = "FAILURE"

        return LogEvent(
            id=event_id,
            timestamp=default_ts,
            raw_log=line,
            log_format="web_access",
            source_ip=source_ip,
            dest_ip=None,
            user=None,
            action=action,
            status=status,
            service="HTTP_WebServer",
            payload=payload
        )

    @classmethod
    def _parse_syslog(cls, line: str, event_id: str, default_ts: str) -> LogEvent:
        ip_match = re.search(cls.IP_REGEX, line)
        source_ip = ip_match.group(0) if ip_match else None

        # User extraction: handle "for invalid user <user>" or "for <user>" or "user <user>"
        user = None
        user_match = re.search(r"(?:for\s+(?:invalid\s+)?user|user|for)\s+([a-zA-Z0-9_\-\.]+)", line, re.IGNORECASE)
        if user_match:
            candidate = user_match.group(1)
            if candidate.lower() not in ("invalid", "a", "the"):
                user = candidate

        # Service: "sshd[123]:", "sudo:", "kernel:"
        svc_match = re.search(r"\b([a-zA-Z_\-]+)(?:\[\d+\])?:\s", line)
        service = svc_match.group(1) if svc_match else "syslog"

        status = "SUCCESS"
        if any(f in line.lower() for f in ["fail", "error", "invalid", "denied", "refused"]):
            status = "FAILURE"

        action = "syslog_event"
        if "Failed password" in line:
            action = "SSH_AUTH_FAILED"
        elif "Accepted password" in line or "Accepted publickey" in line:
            action = "SSH_AUTH_SUCCESS"
        elif "sudo:" in line:
            action = "PRIVILEGE_ELEVATION"

        return LogEvent(
            id=event_id,
            timestamp=default_ts,
            raw_log=line,
            log_format="syslog",
            source_ip=source_ip,
            dest_ip=None,
            user=user,
            action=action,
            status=status,
            service=service,
            payload=None
        )
