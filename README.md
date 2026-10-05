# Network Intrusion Detection System (IDS) Simulation

A **defensive**, hybrid network IDS simulation that scores synthetic traffic with **rules + statistical anomaly detection + machine learning** and presents results in a 6-tab SOC dashboard.

> **Safety notice:** This project is designed exclusively for defensive cybersecurity education. All suspicious network behavior is represented using synthetic data or authorized isolated lab environments. No packets are ever sent, and all IPs come from RFC 5737 documentation ranges.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![Tests](https://img.shields.io/badge/tests-34%20passing-brightgreen) ![License](https://img.shields.io/badge/use-educational-lightgrey)

## Table of contents
1. [Key features](#key-features) · 2. [Quick start](#quick-start) · 3. [How it works](#how-it-works) · 4. [Dashboard tabs](#dashboard-tabs) · 5. [Detection rules](#detection-rules) · 6. [Results](#results) · 7. [API](#api) · 8. [Project structure](#project-structure) · 9. [Configuration](#configuration) · 10. [Demo walkthrough](#demo-walkthrough) · 11. [Troubleshooting](#troubleshooting) · 12. [Limitations](#limitations) · 13. [Future work](#future-work)

## Key features
- 6,000-flow synthetic dataset with **11 scenarios** (5 normal, 6 attack-like)
- **15 validated features** (rates, ratios, port diversity)
- **6 configurable rules**, a z-score anomaly detector and a Random Forest model
- Hybrid **0-100 risk score** with severity levels and explainable alerts
- Alert **correlation** into incidents and an **analyst workflow** (status, notes, timeline)
- Flask REST API (16 endpoints) with SQLite storage
- **34 automated tests**, plus an evaluation report comparing detectors

## Quick start
**Requirements:** Python 3.10+ and an internet connection when opening the dashboard (Chart.js loads from a CDN).

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m backend.app              # open http://127.0.0.1:5000
```

The dataset and trained model are already included. To regenerate everything:

| Step | Command | Output |
|---|---|---|
| 1. Generate data | `python -m simulator.generate_dataset` | `data/network_traffic.csv` |
| 2. Train models | `python -m ml.train_model` | `models/ids_rf.joblib`, `models/metrics.json` |
| 3. Evaluate detectors | `python -m ml.evaluate` | `reports/model_evaluation.md` |
| 4. Run tests | `python -m unittest discover -s tests -v` | 34 tests, expect `OK` |
| 5. Start app | `python -m backend.app` | Dashboard on port 5000 |

Optional extra feeder (localhost only): `python -m simulator.traffic_simulator --mode mixed --speed fast --post http://127.0.0.1:5000/api/flows`

## How it works
```
Simulator -> Features -> Rules ----\
                      -> Anomaly ---> Risk score -> Alert -> SQLite -> API -> Dashboard
                      -> ML (RF) --/                  \-> Correlation -> Incidents
```

| Risk score | Level | Classification | Severity |
|---|---|---|---|
| 0-20 | NORMAL | NORMAL | INFO |
| 21-40 | LOW RISK | NORMAL | LOW |
| 41-60 | SUSPICIOUS | SUSPICIOUS | MEDIUM |
| 61-80 | HIGH RISK | POTENTIAL INTRUSION | HIGH |
| 81-100 | CRITICAL INVESTIGATION | POTENTIAL INTRUSION | CRITICAL |

- Weights: **40% rule + 30% anomaly + 30% ML** (60/40 if no ML model).
- An alert is created when any rule matches or risk > 40.
- A rule match means *investigate*, not *confirmed attack*.
- Thresholds and weights are project assumptions; calibrate them for a real environment.

## Dashboard tabs
| Tab | Contents |
|---|---|
| **Overview** | 6 KPI cards, 9 charts, top source IPs, live flow feed, latest incidents |
| **Alerts** | Filterable alert table (severity, protocol, type, status), status and rule charts, investigation drawer |
| **Incidents** | Correlated incidents with severity and type charts |
| **Flows** | Searchable flow table with rule/anomaly/ML/risk scores and class charts |
| **Rules** | Edit severity, thresholds and on/off; hit counts; scoring explanation |
| **Model & Reports** | Model comparison, confusion matrices, incident report download |

## Detection rules
| ID | Rule | Severity | Triggers when |
|---|---|---|---|
| IDS-001 | High Connection Rate | HIGH | connections >= 50 and rate >= 15/s |
| IDS-002 | Repeated Failed Connections | HIGH | failures >= 15 and ratio >= 0.5 |
| IDS-003 | Multi-Port Activity | HIGH | >= 20 unique destination ports |
| IDS-004 | SYN-Heavy Behavior | MEDIUM | SYN >= 100 and SYN ratio >= 0.6 |
| IDS-005 | Unusual Service Port | MEDIUM | port outside approved list |
| IDS-006 | Abnormal Traffic Volume | CRITICAL | >= 50 MB or >= 5 MB/s |

Full logic: `docs/DETECTION_LOGIC.md`.

## Results
Held-out 25% split (1,500 synthetic flows):

| Detector | Precision | Recall | F1 | False positives | Missed attacks |
|---|---|---|---|---|---|
| Rules only | 1.000 | 0.997 | 0.998 | 0 | 1 |
| Anomaly only | 0.952 | 0.724 | 0.823 | 11 | 83 |
| Hybrid | 1.000 | 0.987 | 0.993 | 0 | 4 |

| ML model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Logistic Regression | 0.937 | 0.853 | 0.827 | 0.840 |
| Random Forest | 0.997 | 0.997 | 0.987 | 0.992 |
| Isolation Forest | 0.844 | 0.563 | 0.993 | 0.719 |

- Scores are **optimistic**: the synthetic attacks follow the patterns the detectors look for, so rules-only slightly beat the hybrid here. This does not prove rules are better on real traffic.
- Isolation Forest shows the anomaly-detection trade-off: very high recall, many false positives (alert fatigue).
- Details: `reports/model_evaluation.md`, sample output: `reports/sample_incident_report.md`.

## API
| Method | Path | Purpose |
|---|---|---|
| POST / GET | `/api/flows` | Submit or list flows |
| GET | `/api/flows/<id>` | One flow |
| GET | `/api/alerts` | List alerts with filters |
| GET | `/api/alerts/<id>` | Alert detail + notes + steps |
| PUT | `/api/alerts/<id>/status` | Change status |
| POST | `/api/alerts/<id>/notes` | Add analyst note |
| GET | `/api/incidents` | Correlated incidents |
| GET / PUT | `/api/rules`, `/api/rules/<id>` | View or tune rules |
| GET | `/api/dashboard/{stats,traffic,alerts}` | Dashboard data |
| GET | `/api/model`, `/api/report`, `/api/health` | Metrics, report, status |

Full reference with status codes and a curl example: `docs/API_REFERENCE.md`.

## Project structure
```
Network-IDS-Simulation/
├── simulator/   generate_dataset.py, traffic_simulator.py
├── ids/         feature_extractor, rule_engine, anomaly_detector, risk_engine, alert_engine, correlation
├── ml/          train_model.py, predict.py, evaluate.py
├── backend/     app.py (Flask API), services.py (pipeline + SQLite)
├── frontend/    index.html (tabbed dashboard)
├── data/        network_traffic.csv (ids.db created at runtime)
├── models/      ids_rf.joblib, metrics.json
├── tests/       test_ids.py (34 tests)
├── docs/        report, architecture, detection logic, API, testing, interview, resume
├── reports/     model_evaluation.md, sample_incident_report.md
└── screenshots/ capture checklist
```

| Document | Purpose |
|---|---|
| `docs/PROJECT_REPORT.md` | Full project report |
| `docs/ARCHITECTURE.md` | Data flow, modules, database schema |
| `docs/DETECTION_LOGIC.md` | Features, rules, scoring |
| `docs/API_REFERENCE.md` | Endpoints and codes |
| `docs/TESTING.md` | Test groups and manual checklist |
| `docs/INTERVIEW_QA.md` | Interview preparation |
| `docs/RESUME_AND_LINKEDIN.md` | Resume bullets and LinkedIn text |

## Configuration
| Variable | Default | Purpose |
|---|---|---|
| `PORT` | 5000 | Server port |
| `SIM_INTERVAL` | 1.0 | Seconds between simulated batches |
| `SEED_FLOWS` | 1800 | Flows loaded at startup |
| `AUTO_SIM` | 1 | `0` disables the live simulator |
| `IDS_RESET` | 1 | `0` keeps the database between runs |
| `IDS_API_KEY` | unset | Requires `X-API-Key` on `POST /api/flows` |

## Demo walkthrough
1. Open **Overview**: normal HTTPS/DNS flows appear as NORMAL in the feed.
2. Go to **Alerts**, filter severity = CRITICAL.
3. Click an alert: read the score breakdown, reason and investigation steps.
4. Click **INVESTIGATING**, add a note, then **RESOLVED** or **FALSE_POSITIVE**; see the timeline.
5. Open **Incidents** to see grouped alerts per source IP.
6. On **Rules**, disable IDS-005 or raise a threshold and watch new alerts change.
7. On **Model & Reports**, compare models and download the report.

## Troubleshooting
| Problem | Fix |
|---|---|
| Port 5000 in use (common on macOS) | `PORT=5001 python -m backend.app` (PowerShell: `$env:PORT=5001`) |
| `No module named backend` | Run from the project root folder |
| Charts are blank | Check internet access (Chart.js CDN) and the browser console |
| Dashboard empty | Wait a few seconds for seeding; confirm `AUTO_SIM` is not 0 |
| Model tab says run training | `python -m ml.train_model` |

## Security notes
- Synthetic data only; no scanning or packet sending; feeder posts to localhost only.
- Parameterised SQL, input validation (HTTP 422), escaped UI output, generic 500 errors.
- Secrets via environment variables; no payloads or personal data stored.
- For production add analyst login with roles, TLS, rate limiting and audit logs.

## Limitations
- Synthetic data makes scores optimistic; real traffic is noisier.
- Per-flow detection with pre-aggregated counts; no packet or encrypted-content analysis.
- Dashboard polls every 3 seconds; SQLite and a single process suit demos only.
- No analyst authentication; thresholds and weights need calibration.

## Future work
- Analyst login and RBAC, audit log
- MITRE ATT&CK mapping per rule
- Zeek/Suricata log ingestion
- SSE/WebSocket streaming and time-window aggregation
- Threshold tuning with precision-recall curves
- SIEM forwarding (JSON/syslog)

## Suggested Git commits
1. Initialize network IDS simulation
2. Add synthetic traffic dataset generator
3. Implement network traffic simulator
4. Add network feature extraction
5. Implement signature detection rules
6. Add anomaly detection engine
7. Implement hybrid risk scoring
8. Add security alert generation and correlation
9. Add ML training, prediction and evaluation
10. Build tabbed SOC dashboard
11. Add incident investigation workflow
12. Implement automated tests
13. Complete documentation and reports

**Repository name:** `Network-Intrusion-Detection-System-Simulation`
**Topics:** cybersecurity, intrusion-detection, ids, network-security, soc, python, flask, anomaly-detection, machine-learning, threat-detection, defensive-security

## License and use
Educational use. Do not use any part of this project to scan or attack systems you do not own or have written permission to test.
