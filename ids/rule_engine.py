"""Signature/rule engine. A match = 'worth investigating', NOT proof of an attack. Thresholds are configurable."""
import copy

SEVERITY_SCORE = {"INFO": 20, "LOW": 40, "MEDIUM": 60, "HIGH": 80, "CRITICAL": 95}
KNOWN_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443}

DEFAULT_RULES = [
    {"rule_id": "IDS-001", "name": "High Connection Rate", "severity": "HIGH", "enabled": True,
     "description": "Connection rate exceeded configured baseline.", "threshold": {"connection_rate": 15, "min_connections": 50}},
    {"rule_id": "IDS-002", "name": "Repeated Failed Connections", "severity": "HIGH", "enabled": True,
     "description": "Many failed connection attempts with a high failure ratio.", "threshold": {"failed": 15, "ratio": 0.5}},
    {"rule_id": "IDS-003", "name": "Multi-Port Activity", "severity": "HIGH", "enabled": True,
     "description": "One source touched an unusually large number of destination ports.", "threshold": {"ports": 20}},
    {"rule_id": "IDS-004", "name": "SYN-Heavy Behavior", "severity": "MEDIUM", "enabled": True,
     "description": "SYN packets dominate the flow; handshakes rarely complete.", "threshold": {"syn": 100, "ratio": 0.6}},
    {"rule_id": "IDS-005", "name": "Unusual Service Port", "severity": "MEDIUM", "enabled": True,
     "description": "Traffic to a port outside the approved service list.", "threshold": {}},
    {"rule_id": "IDS-006", "name": "Abnormal Traffic Volume", "severity": "CRITICAL", "enabled": True,
     "description": "Flow byte volume far above normal.", "threshold": {"bytes": 50_000_000, "bps": 5_000_000}},
]

_CHECKS = {
    "IDS-001": lambda f, t: f["connection_count"] >= t["min_connections"] and f["connection_rate"] >= t["connection_rate"],
    "IDS-002": lambda f, t: f["failed_connection_count"] >= t["failed"] and f["failure_ratio"] >= t["ratio"],
    "IDS-003": lambda f, t: f["unique_destination_ports"] >= t["ports"],
    "IDS-004": lambda f, t: f["syn_count"] >= t["syn"] and f["syn_ratio"] >= t["ratio"],
    "IDS-005": lambda f, t: f["destination_port"] not in KNOWN_PORTS,
    "IDS-006": lambda f, t: f["byte_count"] >= t["bytes"] or f["bytes_per_second"] >= t["bps"],
}


def default_rules():
    return copy.deepcopy(DEFAULT_RULES)


def analyze_flow(features: dict, rules=None):
    """Return (matches, signature_risk 0-100). Each match is the rule dict."""
    matches = [r for r in (rules or DEFAULT_RULES) if r.get("enabled", True) and r["rule_id"] in _CHECKS
               and _CHECKS[r["rule_id"]](features, r["threshold"])]
    if not matches:
        return [], 0.0
    top = max(SEVERITY_SCORE[m["severity"]] for m in matches)
    return matches, float(min(100, top + 5 * (len(matches) - 1)))  # extra corroborating rules add a little
