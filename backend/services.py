"""IDS pipeline + SQLite storage. Flow -> features -> rules + anomaly + ML -> risk -> alert -> DB."""
import csv, json, os, random, sqlite3, threading, time, uuid
from datetime import datetime, timedelta, timezone
from ids.alert_engine import STATUSES, STEPS, generate_alert, should_alert
from ids.anomaly_detector import AnomalyDetector
from ids.correlation import correlate_alerts
from ids.feature_extractor import extract_network_features
from ids.risk_engine import calculate_risk_score, classify, risk_level, severity
from ids.rule_engine import SEVERITY_SCORE, analyze_flow, default_rules
from ml.predict import MLDetector
from simulator.generate_dataset import generate, make_flow, random_scenario

SCHEMA = """
CREATE TABLE IF NOT EXISTS network_flows(flow_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source_ip TEXT, destination_ip TEXT,
 source_port INT, destination_port INT, protocol TEXT, packet_count REAL, byte_count REAL, duration REAL, connection_count REAL,
 failed_connection_count REAL, syn_count REAL, rst_count REAL, unique_destination_ports REAL, signature_score REAL, anomaly_score REAL,
 ml_score REAL, risk_score REAL, risk_level TEXT, classification TEXT, label TEXT, scenario_type TEXT);
CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY, flow_id TEXT REFERENCES network_flows(flow_id), timestamp TEXT, source_ip TEXT,
 destination_ip TEXT, protocol TEXT, source_port INT, destination_port INT, rule_id TEXT, alert_type TEXT, severity TEXT, risk_score REAL,
 anomaly_score REAL, ml_score REAL, description TEXT, status TEXT DEFAULT 'NEW', created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS rules(rule_id TEXT PRIMARY KEY, rule_name TEXT, description TEXT, severity TEXT, threshold TEXT, enabled INT);
CREATE TABLE IF NOT EXISTS incident_notes(note_id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT REFERENCES alerts(alert_id), note TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS model_results(result_id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id TEXT, model_name TEXT, prediction INT, score REAL);
CREATE INDEX IF NOT EXISTS ix_flow_ts ON network_flows(timestamp); CREATE INDEX IF NOT EXISTS ix_flow_src ON network_flows(source_ip);
CREATE INDEX IF NOT EXISTS ix_alert_ts ON alerts(timestamp); CREATE INDEX IF NOT EXISTS ix_alert_sev ON alerts(severity, status);
CREATE INDEX IF NOT EXISTS ix_note_alert ON incident_notes(alert_id);
"""


class DuplicateFlow(Exception):
    pass


def now_iso():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def since(minutes):
    return (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=minutes)).isoformat(timespec="seconds")


class IDSService:
    def __init__(self, db_path, csv_path="data/network_traffic.csv", model_path="models/ids_rf.joblib"):
        self.lock = threading.RLock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.csv_path, self.ml, self.weights = csv_path, MLDetector(model_path), None
        self._load_rules()
        rows = self._dataset_rows()
        normal = [extract_network_features(r) for r in rows if r["label"] == "NORMAL"]
        self.anomaly = AnomalyDetector().fit(normal)
        self.dataset = rows
        self.flow_n = self.db.execute("SELECT COUNT(*) FROM network_flows").fetchone()[0]
        self.alert_n = self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    # ---------- setup ----------
    def _dataset_rows(self):
        if os.path.exists(self.csv_path):
            with open(self.csv_path) as f:
                return list(csv.DictReader(f))
        return generate(3000)

    def _load_rules(self):
        if not self.db.execute("SELECT COUNT(*) FROM rules").fetchone()[0]:
            for r in default_rules():
                self.db.execute("INSERT INTO rules VALUES(?,?,?,?,?,?)", (r["rule_id"], r["name"], r["description"], r["severity"], json.dumps(r["threshold"]), 1))
            self.db.commit()
        self.rules = [{"rule_id": r["rule_id"], "name": r["rule_name"], "description": r["description"], "severity": r["severity"],
                       "threshold": json.loads(r["threshold"]), "enabled": bool(r["enabled"])} for r in self.db.execute("SELECT * FROM rules ORDER BY rule_id")]

    def seed(self, count=1800, hours=3):
        """Load a sample of the synthetic dataset, re-timed across the last `hours`, through the full IDS pipeline."""
        if self.flow_n or not self.dataset or count <= 0:
            return
        rows = random.Random(7).sample(self.dataset, min(count, len(self.dataset)))
        start = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
        step = timedelta(hours=hours) / len(rows)
        for i, r in enumerate(rows):
            r["timestamp"] = (start + step * i).isoformat(timespec="seconds")
        for i in range(0, len(rows), 400):
            self.process_many(rows[i:i + 400], strict=False)

    def start_simulator(self, interval=1.0, ratio=0.2, per_tick=3):
        def loop():
            rng = random.Random()
            while True:
                ts = datetime.now(timezone.utc).replace(tzinfo=None)
                batch = [make_flow(random_scenario(rng, ratio), rng, ts, f"LIVE-{uuid.uuid4().hex[:10]}") for _ in range(per_tick)]
                try:
                    self.process_many(batch, strict=False)
                except Exception:
                    pass
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True).start()

    # ---------- pipeline ----------
    def process_many(self, raws, strict=True):
        prepared = []
        for raw in raws:
            try:
                f = extract_network_features(raw)
                ts = raw.get("timestamp") or now_iso()
                datetime.fromisoformat(str(ts))
                prepared.append((raw, f, str(ts)))
            except ValueError:
                if strict:
                    raise
        probs = self.ml.predict_batch([p[1] for p in prepared])
        results = []
        with self.lock:
            for (raw, f, ts), p in zip(prepared, probs):
                fid = raw.get("flow_id")
                if fid and self.db.execute("SELECT 1 FROM network_flows WHERE flow_id=?", (fid,)).fetchone():
                    if strict:
                        raise DuplicateFlow(fid)
                    continue
                self.flow_n += 1
                fid = fid or f"FLW-{self.flow_n:07d}"
                matches, sig = analyze_flow(f, self.rules)
                an, _ = self.anomaly.calculate_anomaly_score(f)
                risk = calculate_risk_score(sig, an, p, self.weights)
                self.db.execute("INSERT INTO network_flows VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (fid, ts, f["source_ip"], f["destination_ip"], f["source_port"], f["destination_port"], f["protocol"], f["packet_count"],
                     f["byte_count"], f["duration"], f["connection_count"], f["failed_connection_count"], f["syn_count"], f["rst_count"],
                     f["unique_destination_ports"], sig, an, None if p is None else p * 100, risk, risk_level(risk), classify(risk),
                     raw.get("label"), raw.get("scenario_type")))
                if p is not None:
                    self.db.execute("INSERT INTO model_results(flow_id,model_name,prediction,score) VALUES(?,?,?,?)", (fid, "random_forest", int(p >= .5), p))
                alert_id = None
                if should_alert(risk, matches):
                    self.alert_n += 1
                    alert_id = f"ALT-{10000 + self.alert_n}"
                    a = generate_alert(alert_id, fid, ts, f, matches, an, p, risk, severity(risk))
                    self.db.execute("INSERT INTO alerts VALUES(:alert_id,:flow_id,:timestamp,:source_ip,:destination_ip,:protocol,:source_port,:destination_port,"
                                    ":rule_id,:alert_type,:severity,:risk_score,:anomaly_score,:ml_score,:description,:status,:c,:c)", {**a, "c": now_iso()})
                results.append({"flow_id": fid, "classification": classify(risk), "risk_score": risk, "signature_score": sig, "anomaly_score": an,
                                "ml_score": None if p is None else round(p * 100, 1), "matched_rules": [m["rule_id"] for m in matches], "alert_id": alert_id})
            self.db.commit()
        return results

    # ---------- queries ----------
    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def flows(self, limit=100, classification=None, minutes=None):
        sql, args = "SELECT * FROM network_flows WHERE 1=1", []
        if classification: sql += " AND classification=?"; args.append(classification)
        if minutes: sql += " AND timestamp>=?"; args.append(since(minutes))
        return self.q(sql + " ORDER BY timestamp DESC LIMIT ?", (*args, min(limit, 1000)))

    def alerts(self, limit=100, severity=None, protocol=None, alert_type=None, status=None, minutes=None):
        sql, args = "SELECT * FROM alerts WHERE 1=1", []
        for col, v in (("severity", severity), ("protocol", protocol), ("alert_type", alert_type), ("status", status)):
            if v: sql += f" AND {col}=?"; args.append(v)
        if minutes: sql += " AND timestamp>=?"; args.append(since(minutes))
        return self.q(sql + " ORDER BY timestamp DESC, alert_id DESC LIMIT ?", (*args, min(limit, 1000)))

    def alert_detail(self, alert_id):
        a = self.q("SELECT * FROM alerts WHERE alert_id=?", (alert_id,))
        if not a: return None
        flow = self.q("SELECT * FROM network_flows WHERE flow_id=?", (a[0]["flow_id"],))
        notes = self.q("SELECT note_id,note,created_at FROM incident_notes WHERE alert_id=? ORDER BY note_id", (alert_id,))
        return {**a[0], "flow": flow[0] if flow else None, "notes": notes, "recommended_steps": STEPS}

    def add_note(self, alert_id, note):
        with self.lock:
            self.db.execute("INSERT INTO incident_notes(alert_id,note,created_at) VALUES(?,?,?)", (alert_id, note, now_iso()))
            self.db.execute("UPDATE alerts SET updated_at=? WHERE alert_id=?", (now_iso(), alert_id)); self.db.commit()

    def set_status(self, alert_id, status, note=None):
        old = self.q("SELECT status FROM alerts WHERE alert_id=?", (alert_id,))[0]["status"]
        with self.lock:
            self.db.execute("UPDATE alerts SET status=?, updated_at=? WHERE alert_id=?", (status, now_iso(), alert_id)); self.db.commit()
        self.add_note(alert_id, f"[STATUS] {old} -> {status}" + (f" | {note}" if note else ""))

    def update_rule(self, rule_id, body):
        rule = next((r for r in self.rules if r["rule_id"] == rule_id), None)
        if not rule: return None
        if "enabled" in body: rule["enabled"] = bool(body["enabled"])
        if "severity" in body:
            if body["severity"] not in SEVERITY_SCORE: raise ValueError("invalid severity")
            rule["severity"] = body["severity"]
        for k, v in (body.get("threshold") or {}).items():
            if k not in rule["threshold"] or not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0:
                raise ValueError(f"invalid threshold {k!r}")
            rule["threshold"][k] = v
        with self.lock:
            self.db.execute("UPDATE rules SET severity=?, threshold=?, enabled=? WHERE rule_id=?", (rule["severity"], json.dumps(rule["threshold"]), int(rule["enabled"]), rule_id)); self.db.commit()
        return rule

    # ---------- dashboard ----------
    def stats(self, minutes):
        s = since(minutes)
        f = self.q("SELECT COUNT(*) total, COALESCE(SUM(classification='NORMAL'),0) normal, COALESCE(AVG(risk_score),0) avg FROM network_flows WHERE timestamp>=?", (s,))[0]
        a = self.q("SELECT COALESCE(SUM(status IN ('NEW','INVESTIGATING')),0) open_alerts, COALESCE(SUM(severity='CRITICAL'),0) critical, COUNT(*) total FROM alerts WHERE timestamp>=?", (s,))[0]
        return {"total_flows": f["total"], "normal": f["normal"], "suspicious": f["total"] - f["normal"], "open_alerts": a["open_alerts"],
                "critical_alerts": a["critical"], "total_alerts": a["total"], "avg_risk": round(f["avg"], 1), "ml_enabled": self.ml.ready}

    def traffic(self, minutes):
        n, secs, pad = (16, 60, ":00") if minutes <= 60 else (15, 600, "0:00") if minutes <= 360 else (13, 3600, ":00:00")
        s = since(minutes)
        rows = self.q(f"SELECT substr(timestamp,1,{n}) b, COUNT(*) flows, SUM(packet_count) packets, SUM(byte_count) bytes, SUM(connection_count) conns, "
                      f"SUM(failed_connection_count) failed, AVG(risk_score) risk, SUM(classification!='NORMAL') suspicious FROM network_flows WHERE timestamp>=? GROUP BY b ORDER BY b", (s,))
        al = {r["b"]: r["c"] for r in self.q(f"SELECT substr(timestamp,1,{n}) b, COUNT(*) c FROM alerts WHERE timestamp>=? GROUP BY b", (s,))}
        return [{"time": r["b"] + pad, "flows": r["flows"], "pps": round(r["packets"] / secs, 1), "bps": round(r["bytes"] / secs),
                 "conns": r["conns"], "failed": r["failed"], "risk": round(r["risk"], 1), "alerts": al.get(r["b"], 0)} for r in rows]

    def dashboard_alerts(self, minutes):
        s = since(minutes)
        g = lambda sql: self.q(sql, (s,))
        recent = self.q("SELECT * FROM alerts WHERE timestamp>=? ORDER BY timestamp DESC LIMIT 600", (s,))
        return {
            "by_severity": g("SELECT severity k, COUNT(*) c FROM alerts WHERE timestamp>=? GROUP BY severity"),
            "top_types": g("SELECT alert_type k, COUNT(*) c FROM alerts WHERE timestamp>=? GROUP BY alert_type ORDER BY c DESC LIMIT 6"),
            "top_sources": g("SELECT source_ip k, COUNT(*) c, MAX(risk_score) risk FROM alerts WHERE timestamp>=? GROUP BY source_ip ORDER BY c DESC LIMIT 8"),
            "protocols": g("SELECT protocol k, COUNT(*) c FROM network_flows WHERE timestamp>=? GROUP BY protocol"),
            "ports": g("SELECT CAST(destination_port AS TEXT) k, COUNT(*) c FROM network_flows WHERE timestamp>=? GROUP BY destination_port ORDER BY c DESC LIMIT 8"),
            "risk_hist": g("SELECT CAST(MIN(risk_score,99.9)/10 AS INT) k, COUNT(*) c FROM network_flows WHERE timestamp>=? GROUP BY k ORDER BY k"),
            "rule_hits": g("SELECT rule_id k, COUNT(*) c FROM alerts WHERE timestamp>=? GROUP BY rule_id"),
            "feed": self.q("SELECT flow_id,timestamp,source_ip,destination_ip,protocol,destination_port,classification,risk_score FROM network_flows ORDER BY timestamp DESC, rowid DESC LIMIT 16"),
            "incidents": correlate_alerts(recent)[:8]}

    def report(self, minutes):
        st, da = self.stats(minutes), self.dashboard_alerts(minutes)
        L = [f"# IDS Incident Report", f"_Generated {now_iso()} UTC - window: last {minutes} min (synthetic data)_", "", "## Summary",
             f"- Flows analysed: {st['total_flows']} (normal {st['normal']}, suspicious {st['suspicious']})",
             f"- Alerts: {st['total_alerts']} (open {st['open_alerts']}, critical {st['critical_alerts']}) | Avg risk: {st['avg_risk']}", "", "## Top Alert Types"]
        L += [f"- {t['k']}: {t['c']}" for t in da["top_types"]] + ["", "## Top Source IPs"] + [f"- {t['k']}: {t['c']} alerts (max risk {t['risk']})" for t in da["top_sources"]]
        L += ["", "## Correlated Incidents"] + [f"- {i['incident_id']} {i['source_ip']} / {i['alert_type']}: {i['alert_count']} alerts, {i['severity']}, max risk {i['max_risk']}" for i in da["incidents"]]
        return "\n".join(L) + "\n"
