"""Alert generation. Alerts carry reasons + defensive investigation steps."""
STATUSES = ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
STEPS = ["Review related logs for the source IP", "Check whether the source is a known/authorized host",
         "Compare activity with the historical baseline", "Check authentication logs for the destination",
         "Review firewall records", "Review endpoint telemetry where authorized",
         "Decide whether the activity is expected (backup, scanner, batch job)"]


def should_alert(risk, matches):
    return bool(matches) or risk > 40


def generate_alert(alert_id, flow_id, ts, feat, matches, anomaly, ml_prob, risk, sev):
    top = max(matches, key=lambda m: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(m["severity"])) if matches else None
    reason = "; ".join(m["description"] for m in matches) if matches else "Traffic deviated significantly from the statistical baseline."
    return {"alert_id": alert_id, "flow_id": flow_id, "timestamp": ts, "source_ip": feat["source_ip"],
            "destination_ip": feat["destination_ip"], "protocol": feat["protocol"], "source_port": feat["source_port"],
            "destination_port": feat["destination_port"], "rule_id": top["rule_id"] if top else "ANOM-001",
            "alert_type": top["name"] if top else "Statistical Anomaly", "severity": sev, "risk_score": risk,
            "anomaly_score": anomaly, "ml_score": None if ml_prob is None else round(ml_prob * 100, 1),
            "description": reason, "status": "NEW"}
