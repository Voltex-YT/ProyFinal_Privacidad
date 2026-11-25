import os
import re
import time
import json
import socket
from collections import defaultdict, deque

UDP_IP = "0.0.0.0"
UDP_PORT = 5514
LOG_DIR = "/siem/logs"
AUDIT_FILE = os.path.join(LOG_DIR, "siem_audit.log")
ALERTS_FILE = os.path.join(LOG_DIR, "siem_alerts.json")

os.makedirs(LOG_DIR, exist_ok=True)

PATTERNS = [
    (re.compile(r'\b[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d\b', re.IGNORECASE), '[CURP_REDACTED]'),
    (re.compile(r'\b\d{9}\b'), '[MATRICULA_REDACTED]'),
    (re.compile(r'\b(?:\d[ -]*?){13,16}\b'), '[CARD_REDACTED]'),
    (re.compile(r'(?i)(password|passwd|pwd|secret|pepper|token_raw)=([^\s&;]+)'), r'\1=[SECRET_REDACTED]')
]

RFC5424_REGEX = re.compile(
    r'^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+'
    r'(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+'
    r'(?P<appname>\S+)\s+(?P<procid>\S+)\s+'
    r'(?P<msgid>\S+)\s+(?P<sd>-|\[.*?\])\s+(?P<msg>.*)$'
)

brute_force_tracker = defaultdict(deque)
mass_query_tracker = defaultdict(deque)

def sanitize_message(text):
    sanitized = text
    for pattern, replacement in PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized

def emit_alert(rule_id, severity, entity, count, window_sec, details):
    alert = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rule_id": rule_id,
        "severity": severity,
        "entity": entity,
        "event_count": count,
        "window_seconds": window_sec,
        "details": details
    }
    with open(ALERTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    print(f"[ALERTA SIEM - {severity}] {rule_id}: {details}", flush=True)

def evaluate_correlations(msgid, msg):
    now = time.time()

    if msgid == "AUTH_FAIL":
        ip_match = re.search(r'src_ip=([0-9a-fA-F.:]+)', msg)
        src_ip = ip_match.group(1) if ip_match else "unknown_ip"
        dq = brute_force_tracker[src_ip]
        dq.append(now)
        while dq and now - dq[0] > 60:
            dq.popleft()
        if len(dq) == 5:
            emit_alert(
                "CORR-001-BRUTE-FORCE",
                "HIGH",
                src_ip,
                len(dq),
                60,
                f"Detectados 5 intentos fallidos de autenticacion desde {src_ip} en <= 60s"
            )

    elif msgid in ("PII_QUERY", "GRADE_READ"):
        actor_match = re.search(r'actor=([a-zA-Z0-9_-]+)', msg)
        actor = actor_match.group(1) if actor_match else "unknown_actor"
        dq = mass_query_tracker[actor]
        dq.append(now)
        while dq and now - dq[0] > 30:
            dq.popleft()
        if len(dq) == 10:
            emit_alert(
                "CORR-002-MASS-EXFILTRATION",
                "CRITICAL",
                actor,
                len(dq),
                30,
                f"Consulta masiva de expedientes detectada para el token {actor} (10 eventos en <= 30s)"
            )

def run_collector():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"Colector SIEM Syslog RFC 5424 activo en UDP {UDP_IP}:{UDP_PORT}", flush=True)

    while True:
        data, addr = sock.recvfrom(8192)
        raw_line = data.decode("utf-8", errors="replace").strip()
        clean_line = sanitize_message(raw_line)

        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(clean_line + "\n")

        parsed = RFC5424_REGEX.match(clean_line)
        if parsed:
            msgid = parsed.group("msgid")
            msg = parsed.group("msg")
            evaluate_correlations(msgid, msg)

if __name__ == "__main__":
    run_collector()
