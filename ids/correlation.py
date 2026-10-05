"""EVENT = one observation, ALERT = detection needing attention, INCIDENT = group of related alerts."""
from datetime import datetime

_RANK = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _t(a):
    return datetime.fromisoformat(a["timestamp"]).timestamp()


def correlate_alerts(alerts, window_seconds=60):
    """Group alerts by (source_ip, alert_type); a gap larger than the window starts a new incident."""
    groups = {}
    for a in sorted(alerts, key=_t):
        key, lst = (a["source_ip"], a["alert_type"]), None
        lst = groups.setdefault(key, [[]])
        if lst[-1] and _t(a) - _t(lst[-1][-1]) > window_seconds:
            lst.append([])
        lst[-1].append(a)
    out = []
    for (src, typ), bursts in groups.items():
        for g in bursts:
            out.append({"source_ip": src, "alert_type": typ, "alert_count": len(g), "first_seen": g[0]["timestamp"],
                        "last_seen": g[-1]["timestamp"], "max_risk": max(x["risk_score"] for x in g),
                        "severity": max((x["severity"] for x in g), key=_RANK.index), "alert_ids": [x["alert_id"] for x in g]})
    out.sort(key=lambda i: i["last_seen"], reverse=True)
    for n, inc in enumerate(out, 1):
        inc["incident_id"] = f"INC-{n:04d}"
    return out
