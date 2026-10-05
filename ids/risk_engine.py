"""Hybrid risk scoring. Thresholds/weights are project assumptions - calibrate them in a real SOC."""
DEFAULT_WEIGHTS = {"rule": 0.4, "anomaly": 0.3, "ml": 0.3}
NO_ML_WEIGHTS = {"rule": 0.6, "anomaly": 0.4}


def calculate_risk_score(rule_risk, anomaly_risk, ml_probability=None, weights=None):
    """Weighted blend, 0-100. ml_probability is 0-1 or None (ML disabled -> 60/40 split)."""
    if ml_probability is None:
        w = (weights or NO_ML_WEIGHTS)
        total = (w["rule"] * rule_risk + w["anomaly"] * anomaly_risk) / (w["rule"] + w["anomaly"])
    else:
        w = (weights or DEFAULT_WEIGHTS)
        total = (w["rule"] * rule_risk + w["anomaly"] * anomaly_risk + w["ml"] * ml_probability * 100) / (w["rule"] + w["anomaly"] + w["ml"])
    return round(max(0.0, min(100.0, total)), 1)


def risk_level(score):
    return ("NORMAL" if score <= 20 else "LOW RISK" if score <= 40 else "SUSPICIOUS" if score <= 60
            else "HIGH RISK" if score <= 80 else "CRITICAL INVESTIGATION")


def classify(score):
    return "NORMAL" if score <= 40 else "SUSPICIOUS" if score <= 60 else "POTENTIAL INTRUSION"


def severity(score):
    return "INFO" if score <= 20 else "LOW" if score <= 40 else "MEDIUM" if score <= 60 else "HIGH" if score <= 80 else "CRITICAL"
