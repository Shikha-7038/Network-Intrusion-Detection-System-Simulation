"""30+ automated tests (unittest; also runs under pytest). Run: python -m unittest discover -s tests -v"""
import os, random, tempfile, unittest
from datetime import datetime, timezone
from backend.app import create_app
from ids.alert_engine import generate_alert
from ids.anomaly_detector import AnomalyDetector
from ids.correlation import correlate_alerts
from ids.feature_extractor import extract_network_features as fx
from ids.risk_engine import calculate_risk_score, classify, risk_level, severity
from ids.rule_engine import analyze_flow
from ml.train_model import train
from simulator.generate_dataset import generate, make_flow

import pandas as pd

BASE = {"source_ip": "192.0.2.15", "destination_ip": "198.51.100.20", "source_port": 49152, "destination_port": 443, "protocol": "TCP",
        "packet_count": 18, "byte_count": 12400, "duration_seconds": 2.8, "connection_count": 3, "failed_connection_count": 0, "syn_count": 2, "rst_count": 0}
now = lambda: datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def flow(**kw): return {**BASE, **kw}
def rules_hit(**kw): return {m["rule_id"] for m in analyze_flow(fx(flow(**kw)))[0]}


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = generate(1500, seed=1)
        cls.det = AnomalyDetector().fit([fx(r) for r in cls.rows if r["label"] == "NORMAL"])
        os.environ["IDS_RESET"] = "0"
        cls.app = create_app(os.path.join(tempfile.mkdtemp(), "t.db"), auto_sim=False, seed=0)
        cls.c = cls.app.test_client()

    # T01-T04 normal flows
    def test01_normal_tcp(self): self.assertEqual(rules_hit(), set())
    def test02_normal_udp(self): self.assertEqual(rules_hit(protocol="UDP", destination_port=123, packet_count=2), set())
    def test03_normal_dns(self): self.assertEqual(rules_hit(protocol="UDP", destination_port=53, connection_count=1), set())
    def test04_normal_https(self): self.assertEqual(rules_hit(destination_port=443), set())
    # T05-T09 suspicious patterns
    def test05_high_conn_rate(self): self.assertIn("IDS-001", rules_hit(connection_count=300, duration_seconds=2))
    def test06_failed_conns(self): self.assertIn("IDS-002", rules_hit(connection_count=40, failed_connection_count=35))
    def test07_multi_port(self): self.assertIn("IDS-003", rules_hit(unique_destination_ports=80))
    def test08_syn_heavy(self): self.assertIn("IDS-004", rules_hit(syn_count=400, packet_count=420))
    def test09_high_volume(self): self.assertIn("IDS-006", rules_hit(packet_count=200000, byte_count=200_000_000))
    def test09b_unusual_port(self): self.assertIn("IDS-005", rules_hit(destination_port=31337))
    # T10-T16 validation / edge cases
    def test10_bad_src_ip(self): self.assertRaises(ValueError, fx, flow(source_ip="999.1.1.1"))
    def test11_bad_dst_ip(self): self.assertRaises(ValueError, fx, flow(destination_ip="not-an-ip"))
    def test12_bad_src_port(self): self.assertRaises(ValueError, fx, flow(source_port=70000))
    def test13_bad_dst_port(self): self.assertRaises(ValueError, fx, flow(destination_port=-1))
    def test14_bad_protocol(self): self.assertRaises(ValueError, fx, flow(protocol="XYZ"))
    def test15_missing_packets(self):
        f = flow(); f.pop("packet_count"); self.assertEqual(fx(f)["average_packet_size"], 0.0)
    def test16_zero_duration(self): self.assertTrue(fx(flow(duration_seconds=0))["packets_per_second"] > 0)
    # T17-T22 engines
    def test17_feature_extraction(self):
        f = fx(flow()); self.assertAlmostEqual(f["bytes_per_second"], 12400 / 2.8); self.assertEqual(f["failure_ratio"], 0)
    def test18_rule_threshold_configurable(self):
        from ids.rule_engine import default_rules
        r = default_rules(); r[0]["threshold"]["connection_rate"] = 1; r[0]["threshold"]["min_connections"] = 1
        self.assertIn("IDS-001", {m["rule_id"] for m in analyze_flow(fx(flow()), r)[0]})
    def test19_anomaly_score(self):
        lo, _ = self.det.calculate_anomaly_score(fx(flow())); hi, _ = self.det.calculate_anomaly_score(fx(flow(connection_count=400, duration_seconds=1, unique_destination_ports=150, failed_connection_count=300)))
        self.assertLess(lo, 30); self.assertGreater(hi, 60)
    def test20_risk_score(self):
        self.assertEqual(calculate_risk_score(70, 60, 0.78), round(.4 * 70 + .3 * 60 + .3 * 78, 1)); self.assertEqual(calculate_risk_score(70, 60), 66.0)
    def test20b_risk_bands(self):
        self.assertEqual([risk_level(x) for x in (10, 30, 50, 70, 90)], ["NORMAL", "LOW RISK", "SUSPICIOUS", "HIGH RISK", "CRITICAL INVESTIGATION"])
        self.assertEqual((classify(30), classify(50), classify(90), severity(90)), ("NORMAL", "SUSPICIOUS", "POTENTIAL INTRUSION", "CRITICAL"))
    def test21_alert_creation(self):
        f = fx(flow(connection_count=300, duration_seconds=2)); m, s = analyze_flow(f)
        a = generate_alert("ALT-10001", "F1", now(), f, m, 50, None, 76, "HIGH")
        self.assertEqual((a["status"], a["rule_id"], a["severity"]), ("NEW", "IDS-001", "HIGH"))
    def test22_correlation(self):
        t = lambda s, src="192.0.2.1": {"alert_id": f"A{s}", "timestamp": f"2026-01-01T00:00:{s:02d}", "source_ip": src, "alert_type": "X", "risk_score": 70, "severity": "HIGH"}
        inc = correlate_alerts([t(1), t(10), t(30), t(5, "192.0.2.9")]); self.assertEqual(sorted(i["alert_count"] for i in inc), [1, 3])
    # T23-T30 API / DB
    def _post(self, **kw): return self.c.post("/api/flows", json=flow(timestamp=now(), **kw))
    def _alert(self):
        r = self._post(connection_count=300, duration_seconds=2, unique_destination_ports=90, failed_connection_count=250); self.assertEqual(r.status_code, 201)
        return r.get_json()["alert_id"]
    def test23_status_update(self):
        a = self._alert(); r = self.c.put(f"/api/alerts/{a}/status", json={"status": "INVESTIGATING"}); self.assertEqual(r.get_json()["status"], "INVESTIGATING")
        self.assertEqual(self.c.put(f"/api/alerts/{a}/status", json={"status": "BOGUS"}).status_code, 422)
    def test24_analyst_note(self):
        a = self._alert(); r = self.c.post(f"/api/alerts/{a}/notes", json={"note": "checked firewall"}); self.assertEqual(r.status_code, 201); self.assertEqual(r.get_json()["notes"][-1]["note"], "checked firewall")
    def test25_db_storage(self):
        r = self._post().get_json(); self.assertEqual(self.c.get(f"/api/flows/{r['flow_id']}").status_code, 200)
    def test26_dashboard_stats(self):
        self._alert(); s = self.c.get("/api/dashboard/stats").get_json(); self.assertGreater(s["total_flows"], 0); self.assertEqual(s["total_flows"], s["normal"] + s["suspicious"])
    def test27_ml_prediction(self):
        b, m = train(pd.DataFrame(self.rows)); self.assertGreater(m["models"]["random_forest"]["recall"], 0.8)
        self.assertEqual(sum(map(sum, m["models"]["random_forest"]["confusion"])), m["test_rows"])
    def test28_api_validation(self):
        self.assertEqual(self.c.post("/api/flows", json=flow(source_ip="bad")).status_code, 422); self.assertEqual(self.c.post("/api/flows", data="x").status_code, 400)
    def test29_empty_dataset(self):
        a = create_app(os.path.join(tempfile.mkdtemp(), "e.db"), auto_sim=False, seed=0).test_client()
        self.assertEqual(a.get("/api/dashboard/stats").get_json()["total_flows"], 0); self.assertEqual(a.get("/api/alerts").get_json(), [])
    def test30_duplicate_event(self):
        f = flow(flow_id="DUP-1", timestamp=now()); self.assertEqual(self.c.post("/api/flows", json=f).status_code, 201); self.assertEqual(self.c.post("/api/flows", json=f).status_code, 409)
    def test31_dataset_size_and_ips(self):
        self.assertTrue(all(r["source_ip"].split(".")[0:3] in (["192", "0", "2"], ["203", "0", "113"]) for r in self.rows)); self.assertGreaterEqual(len(generate(5000)), 5000)
    def test32_rule_update(self):
        r = self.c.put("/api/rules/IDS-003", json={"threshold": {"ports": 30}}); self.assertEqual(r.get_json()["threshold"]["ports"], 30)
        self.assertEqual(self.c.put("/api/rules/IDS-003", json={"threshold": {"nope": 1}}).status_code, 422)


if __name__ == "__main__":
    unittest.main()
