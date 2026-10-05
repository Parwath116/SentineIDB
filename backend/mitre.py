"""MITRE ATT&CK technique catalog for the detections SentinelDB ships with."""
from __future__ import annotations

MITRE: dict[str, dict[str, str]] = {
    "brute_force": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "password_spraying": {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access"},
    "port_scan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "lateral_movement": {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    "exfiltration": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
}

RULE_TITLES: dict[str, str] = {
    "brute_force": "Brute-force login attempts",
    "password_spraying": "Password spraying across many accounts",
    "port_scan": "Port scan against internal host",
    "lateral_movement": "Lateral movement between servers",
    "exfiltration": "Abnormal outbound data transfer",
}
