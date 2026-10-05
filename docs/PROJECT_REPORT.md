# Project Report: Network Intrusion Detection System (IDS) Simulation

> Defensive cybersecurity education project. All traffic is **synthetic flow records** (no packets are sent). IPs use RFC 5737 documentation ranges.

## 1. Executive summary
- Built a hybrid IDS that scores every network flow with **rules + statistical anomaly detection + machine learning**.
- Alerts flow into a **6-tab SOC dashboard** with investigation workflow (status, notes, timeline), correlated incidents, rule tuning and reports.
- Dataset: **6,000 synthetic flows** (about 20% suspicious) across **11 scenarios** (5 normal, 6 suspicious).
- Random Forest reached **F1 0.99** on a held-out split of synthetic data. The result is optimistic (see section 9).
- **34 automated tests** pass.

## 2. Problem statement
| Problem | How this project addresses it |
|---|---|
| Analysts cannot read every flow | Automatic scoring (0-100) and severity ranking |
| Single detectors miss or over-alert | Hybrid scoring combines three detectors |
| Alerts without context waste time | Reason text, score breakdown, recommended investigation steps |
| Many alerts from one source look like noise | Correlation groups them into incidents |
| Testing on real attacks is risky | Safe synthetic data, no live traffic |

## 3. Objectives
- Generate realistic **normal and suspicious flow records** safely.
- Extract validated **behavioural features** (rates, ratios, port diversity).
- Detect with **configurable rules** and a **statistical baseline**, plus a trained ML classifier.
- Produce **explainable alerts** and an **analyst workflow**.
- Evaluate honestly with precision, recall, F1 and confusion matrices.

## 4. Scope
| In scope | Out of scope |
|---|---|
| Synthetic flow-level detection | Live packet capture or real attack traffic |
| Rules, z-score anomaly, ML | Deep packet inspection, encrypted-payload analysis |
| SQLite storage, Flask REST API | Production authentication / RBAC |
| Dashboard and incident workflow | Automated blocking or response |

## 5. Architecture
```
Synthetic simulator -> Feature extractor -> Rule engine ----\
                                        -> Anomaly detector --> Risk engine -> Alert engine -> SQLite -> Flask API -> Dashboard
                                        -> ML (Random Forest) -/                    \-> Correlation -> Incidents
```
See `docs/ARCHITECTURE.md` for the module map, database schema and data flow.

## 6. Dataset
| Scenario | Label | Distinguishing behaviour |
|---|---|---|
| NORMAL_WEB / DNS / SSH / EMAIL / DATABASE | NORMAL | Low connection counts, standard ports, rare harmless failures (3%) |
| HIGH_CONNECTION_RATE | SUSPICIOUS | 80-400 connections in 1-5 s |
| REPEATED_FAILED_CONNECTIONS | SUSPICIOUS | 60-95% failures on SSH/RDP |
| MULTI_PORT_PROBING_PATTERN | SUSPICIOUS | 25-200 distinct destination ports |
| SYN_HEAVY_PATTERN | SUSPICIOUS | 150-800 SYNs, mostly unanswered |
| UNUSUAL_PORT_ACTIVITY | SUSPICIOUS | Ports such as 4444, 6667, 31337 |
| HIGH_TRAFFIC_VOLUME | SUSPICIOUS | 60k-400k packets (tens to hundreds of MB) |

- Suspicious sources come from a small pool of 6 documentation IPs so "top sources" is meaningful.
- Columns: 19 (identifiers, ports, protocol, counts, durations, SYN/RST, unique ports/IPs, label, scenario).

## 7. Methodology
**Feature engineering (15 features):** packets/s, bytes/s, average packet size, connection rate, failure ratio, SYN ratio, unique destination ports/IPs and raw counts. Missing values default to 0, duration is floored at 0.001 s, and invalid IPs/ports/protocols are rejected.

**Rule engine:** 6 configurable rules (IDS-001 to IDS-006). A match means "investigate", not "confirmed attack".

**Anomaly detector:** baseline fitted on normal traffic only; log-scaled rates; per-metric z-score mapped to 0-100 (z <= 2.5 scores 0, z >= 7.5 scores 100); IQR outlier flags kept as detail.

**ML:** Logistic Regression, Random Forest and Isolation Forest trained on a stratified 75/25 split. Random Forest feeds the live pipeline.

**Hybrid risk score:**
| Component | Weight (with ML) | Weight (no ML) |
|---|---|---|
| Rule (signature) score | 40% | 60% |
| Anomaly score | 30% | 40% |
| ML probability x 100 | 30% | - |

| Risk score | Level | Classification | Alert severity |
|---|---|---|---|
| 0-20 | NORMAL | NORMAL | INFO |
| 21-40 | LOW RISK | NORMAL | LOW |
| 41-60 | SUSPICIOUS | SUSPICIOUS | MEDIUM |
| 61-80 | HIGH RISK | POTENTIAL INTRUSION | HIGH |
| 81-100 | CRITICAL INVESTIGATION | POTENTIAL INTRUSION | CRITICAL |

An alert is created when any rule matches or risk > 40.

## 8. Implementation summary
| Layer | Technology | Key files |
|---|---|---|
| Simulation | Python | `simulator/generate_dataset.py`, `traffic_simulator.py` |
| Detection | Python | `ids/*.py` |
| ML | scikit-learn, joblib | `ml/train_model.py`, `predict.py`, `evaluate.py` |
| Backend | Flask, SQLite | `backend/app.py`, `services.py` |
| Frontend | HTML/CSS/JS, Chart.js | `frontend/index.html` |
| Tests | unittest | `tests/test_ids.py` |

Dashboard tabs: **Overview, Alerts, Incidents, Flows, Rules, Model & Reports**.

## 9. Results (held-out 25%: 1,500 flows)
| Detector | Precision | Recall | F1 | False positives | Missed attacks |
|---|---|---|---|---|---|
| Rules only | 1.000 | 0.997 | 0.998 | 0 | 1 |
| Anomaly only | 0.952 | 0.724 | 0.823 | 11 | 83 |
| Hybrid | 1.000 | 0.987 | 0.993 | 0 | 4 |

| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| Logistic Regression | 0.937 | 0.853 | 0.827 | 0.840 |
| Random Forest | 0.997 | 0.997 | 0.987 | 0.992 |
| Isolation Forest | 0.844 | 0.563 | 0.993 | 0.719 |

**Findings**
- Rules alone score slightly higher than the hybrid here, because the synthetic attacks were generated from the same patterns the rules check. This does **not** show rules are better on real traffic.
- The anomaly detector misses attacks that look statistically normal (for example unusual-port activity, 0% detection) but needs no attack signatures.
- Isolation Forest finds nearly all attacks (recall 0.99) but raises 232 false positives: the classic anomaly-detection trade-off (alert fatigue).
- Full per-scenario table: `reports/model_evaluation.md`.

## 10. Limitations
- Synthetic, pattern-based data makes scores optimistic; real traffic is noisier and attackers adapt.
- Detection is per flow with pre-aggregated counts; no packet-level or encrypted-content analysis.
- Fixed thresholds and weights are assumptions that need calibration per environment.
- Polling dashboard (3 s), SQLite, single process: fine for a demo, not for high volume.
- No analyst authentication or role-based access.

## 11. Security and ethics
- Synthetic data only; no scanning, no packet sending; the optional `--post` feeder accepts localhost targets only.
- Parameterised SQL, escaped UI output, input validation (422 on bad data), optional API key for ingestion.
- No payloads or personal data stored.

## 12. Future work
| Idea | Benefit |
|---|---|
| Analyst login + RBAC, audit log | Production readiness |
| MITRE ATT&CK tag per rule | Standard threat vocabulary |
| Zeek/Suricata log ingestion | Real telemetry |
| SSE/WebSocket streaming | True real-time dashboard |
| Time-window aggregation per source | Detect slow scans |
| Threshold tuning with ROC/PR curves | Data-driven calibration |
| SIEM forwarding (JSON/syslog) | Integration |

## 13. Conclusion
The project demonstrates the full detection lifecycle: data, features, layered detection, risk scoring, alerting, correlation, investigation and honest evaluation, in a safe and reproducible form.
