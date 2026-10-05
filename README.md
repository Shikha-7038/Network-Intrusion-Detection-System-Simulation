# Network Intrusion Detection System (IDS) Simulation

A **defensive**, hybrid (signature + statistical anomaly + ML) network IDS simulation with a dense SOC dashboard.
> This project is designed exclusively for defensive cybersecurity education. All suspicious network behavior is represented using synthetic data or authorized isolated lab environments. No packets are ever sent; all IPs are RFC 5737 documentation ranges.

## Quick start (no network lab needed)
```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m simulator.generate_dataset      # 6,000 synthetic flows -> data/network_traffic.csv
python -m ml.train_model                  # real metrics -> models/metrics.json
python -m backend.app                     # open http://127.0.0.1:5000
python -m unittest discover -s tests -v   # 34 tests
```
The backend seeds ~1,800 flows, then a built-in simulator streams new flows every second; the dashboard polls every 3 s (polling is the simplest beginner option; SSE/WebSockets are future work).
Optional extra feeder: `python -m simulator.traffic_simulator --mode mixed --speed fast --post http://127.0.0.1:5000/api/flows` (localhost only).

## Pipeline
Synthetic flows → `ids/feature_extractor.py` (15 validated features) → rules (`rule_engine.py`, IDS-001..006, configurable thresholds) + anomaly (`anomaly_detector.py`, z-score on log rates + IQR fences, 0-100) + ML (Random Forest) → `risk_engine.py` (weights 40/30/30, or 60/40 without ML) → `alert_engine.py` → SQLite → dashboard. `correlation.py` groups alerts by source IP + type in a 60 s window into incidents.

Risk bands (project assumptions, calibrate in a real SOC): 0-20 NORMAL · 21-40 LOW · 41-60 SUSPICIOUS · 61-80 HIGH · 81-100 CRITICAL. Alert statuses: NEW → INVESTIGATING → RESOLVED / FALSE_POSITIVE, with analyst notes and an incident timeline.

## Dashboard (6 tabs: Overview, Alerts, Incidents, Flows, Rules, Model & Reports)
6 KPI cards, 9 charts (traffic pps/bps, connections & failures, alert/risk timeline, normal vs suspicious, severity, alert types, protocols, ports, risk histogram), top sources, correlated incidents, live feed, rule tuning table, ML evaluation + confusion matrix, filterable alerts table, and a click-through investigation drawer.

## API
`POST/GET /api/flows`, `GET /api/flows/<id>`, `GET /api/alerts[?severity&protocol&alert_type&status&minutes]`, `GET /api/alerts/<id>`, `PUT /api/alerts/<id>/status`, `POST /api/alerts/<id>/notes`, `GET /api/dashboard/{stats,traffic,alerts}`, `GET/PUT /api/rules[/<id>]`, `GET /api/incidents`, `GET /api/model`, `GET /api/report`.
Codes: 201 created · 400 bad body · 401 bad API key · 404 · 409 duplicate flow · 422 validation.

## Demo walkthrough
1. Open the dashboard (normal HTTPS flows show NORMAL). 2. Filter severity = CRITICAL. 3. Click an alert → read scores/reason. 4. Press **INVESTIGATING**, add a note, then **RESOLVED** or **FALSE_POSITIVE**; watch the timeline. 5. Toggle a rule off and watch hits change. 6. Open **Report**.

## Results & honesty notes
Metrics are computed by `ml/train_model.py` on a held-out 25% split (see `models/metrics.json`). Because the synthetic data is generated from the same patterns the rules and model look for, scores are optimistic; real traffic would be messier. Isolation Forest (unsupervised) has high recall but lower precision, which illustrates the false-positive trade-off of anomaly detection.

## Security notes
Synthetic data only, no payload storage, parameterised SQL, output escaping in the UI, optional API key for ingestion, secrets via `.env`. For production add analyst login + RBAC, TLS, rate limiting, audit logs.

## Limitations / future work
Single-flow detection with pre-aggregated port counts, polling instead of streaming, no authentication UI, no MITRE ATT&CK mapping or SIEM forwarder (JSON alerts from `/api/alerts` are SIEM-ready), no Zeek/Suricata ingestion.

## Suggested Git commits
`Initialize network IDS simulation` → `Add synthetic traffic dataset generator` → `Implement network traffic simulator` → `Add network feature extraction` → `Implement signature detection rules` → `Add anomaly detection engine` → `Implement hybrid risk scoring` → `Add security alert generation` → `Implement alert correlation` → `Add optional ML detection` → `Build SOC dashboard` → `Add incident investigation workflow` → `Implement automated tests` → `Complete README and documentation`

Repo name: `Network-Intrusion-Detection-System-Simulation` · Topics: cybersecurity, intrusion-detection, ids, network-security, soc, python, anomaly-detection, machine-learning, security-analytics, threat-detection, defensive-security
