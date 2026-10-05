"""Flask REST API + dashboard host. Run: python -m backend.app"""
import json, os
from flask import Flask, jsonify, request, send_from_directory
from backend.services import DuplicateFlow, IDSService
from ids.alert_engine import STATUSES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app(db_path=None, auto_sim=None, seed=None):
    db_path = db_path or os.getenv("IDS_DB", os.path.join(ROOT, "data", "ids.db"))
    if os.getenv("IDS_RESET", "1") == "1" and os.path.exists(db_path):
        os.remove(db_path)  # fresh demo each run
    svc = IDSService(db_path, os.path.join(ROOT, "data", "network_traffic.csv"), os.path.join(ROOT, "models", "ids_rf.joblib"))
    seed = int(os.getenv("SEED_FLOWS", "1800")) if seed is None else seed
    svc.seed(seed)
    if (os.getenv("AUTO_SIM", "1") == "1") if auto_sim is None else auto_sim:
        svc.start_simulator(float(os.getenv("SIM_INTERVAL", "1.0")))
    app = Flask(__name__, static_folder=None)
    app.svc = svc
    err = lambda msg, code: (jsonify({"error": msg}), code)
    mins = lambda: max(1, min(request.args.get("minutes", 180, type=int), 10080))

    @app.before_request
    def auth():  # optional API-key for flow ingestion (set IDS_API_KEY). Use real analyst auth in production.
        key = os.getenv("IDS_API_KEY")
        if key and request.method == "POST" and request.path == "/api/flows" and request.headers.get("X-API-Key") != key:
            return err("unauthorized", 401)

    @app.errorhandler(404)
    def nf(_): return err("not found", 404)

    @app.errorhandler(Exception)
    def boom(e): return err("internal error", 500)

    @app.get("/")
    def index(): return send_from_directory(os.path.join(ROOT, "frontend"), "index.html")

    @app.get("/api/health")
    def health(): return jsonify({"status": "ok", "ml_enabled": svc.ml.ready})

    @app.post("/api/flows")
    def post_flow():
        body = request.get_json(silent=True)
        if not isinstance(body, dict): return err("JSON object body required", 400)
        try: return jsonify(svc.process_many([body])[0]), 201
        except ValueError as e: return err(str(e), 422)
        except DuplicateFlow: return err("duplicate flow_id", 409)

    @app.get("/api/flows")
    def list_flows():
        return jsonify(svc.flows(request.args.get("limit", 100, type=int), request.args.get("classification"), request.args.get("minutes", type=int)))

    @app.get("/api/flows/<fid>")
    def get_flow(fid):
        r = svc.q("SELECT * FROM network_flows WHERE flow_id=?", (fid,))
        return jsonify(r[0]) if r else err("flow not found", 404)

    @app.get("/api/alerts")
    def list_alerts():
        a = request.args
        return jsonify(svc.alerts(a.get("limit", 100, type=int), a.get("severity"), a.get("protocol"), a.get("alert_type"), a.get("status"), a.get("minutes", type=int)))

    @app.get("/api/alerts/<aid>")
    def get_alert(aid):
        r = svc.alert_detail(aid)
        return jsonify(r) if r else err("alert not found", 404)

    @app.put("/api/alerts/<aid>/status")
    def set_status(aid):
        b = request.get_json(silent=True) or {}
        if b.get("status") not in STATUSES: return err(f"status must be one of {STATUSES}", 422)
        if not svc.alert_detail(aid): return err("alert not found", 404)
        svc.set_status(aid, b["status"], str(b.get("note", ""))[:2000] or None)
        return jsonify(svc.alert_detail(aid))

    @app.post("/api/alerts/<aid>/notes")
    def add_note(aid):
        note = str((request.get_json(silent=True) or {}).get("note", "")).strip()
        if not note or len(note) > 2000: return err("note required (max 2000 chars)", 422)
        if not svc.alert_detail(aid): return err("alert not found", 404)
        svc.add_note(aid, note)
        return jsonify(svc.alert_detail(aid)), 201

    @app.get("/api/dashboard/stats")
    def d_stats(): return jsonify(svc.stats(mins()))

    @app.get("/api/dashboard/traffic")
    def d_traffic(): return jsonify(svc.traffic(mins()))

    @app.get("/api/dashboard/alerts")
    def d_alerts(): return jsonify(svc.dashboard_alerts(mins()))

    @app.get("/api/rules")
    def rules(): return jsonify(svc.rules)

    @app.put("/api/rules/<rid>")
    def put_rule(rid):
        try: r = svc.update_rule(rid, request.get_json(silent=True) or {})
        except ValueError as e: return err(str(e), 422)
        return jsonify(r) if r else err("rule not found", 404)

    @app.get("/api/incidents")
    def incidents():
        from ids.correlation import correlate_alerts
        return jsonify(correlate_alerts(svc.alerts(1000, minutes=mins()), request.args.get("window", 60, type=int)))

    @app.get("/api/model")
    def model():
        p = os.path.join(ROOT, "models", "metrics.json")
        return jsonify(json.load(open(p)) if os.path.exists(p) else {})

    @app.get("/api/report")
    def report(): return svc.report(mins()), 200, {"Content-Type": "text/markdown; charset=utf-8"}

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), threaded=True)
