# API Reference

Base URL: `http://127.0.0.1:5000`. All responses are JSON except `/api/report` (Markdown).

## Endpoints
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Status and ML availability |
| POST | `/api/flows` | Submit one flow for analysis (201) |
| GET | `/api/flows` | List flows (`limit`, `classification`, `minutes`) |
| GET | `/api/flows/<flow_id>` | One flow |
| GET | `/api/alerts` | List alerts (`limit`, `severity`, `protocol`, `alert_type`, `status`, `minutes`) |
| GET | `/api/alerts/<alert_id>` | Alert + flow + notes + recommended steps |
| PUT | `/api/alerts/<alert_id>/status` | Body `{"status": "...", "note": "..."}` |
| POST | `/api/alerts/<alert_id>/notes` | Body `{"note": "..."}` |
| GET | `/api/incidents` | Correlated incidents (`minutes`, `window`) |
| GET | `/api/rules` | Rules with thresholds |
| PUT | `/api/rules/<rule_id>` | Body may include `enabled`, `severity`, `threshold` |
| GET | `/api/dashboard/stats` | KPI numbers |
| GET | `/api/dashboard/traffic` | Time-bucketed traffic series |
| GET | `/api/dashboard/alerts` | Aggregates for charts, feed, incidents |
| GET | `/api/model` | Saved ML metrics |
| GET | `/api/report` | Markdown incident report |

## Status codes
| Code | Meaning |
|---|---|
| 200 / 201 | Success / created |
| 400 | Body is not a JSON object |
| 401 | Missing or wrong `X-API-Key` (only when `IDS_API_KEY` is set) |
| 404 | Unknown flow, alert, rule or route |
| 409 | Duplicate `flow_id` |
| 422 | Validation failure (bad IP/port/protocol, bad status, bad threshold) |
| 500 | Internal error (generic message, no stack trace leaked) |

## Example
```bash
curl -X POST http://127.0.0.1:5000/api/flows -H "Content-Type: application/json" -d '{
  "source_ip":"203.0.113.7","destination_ip":"198.51.100.20","source_port":51000,
  "destination_port":22,"protocol":"TCP","packet_count":300,"byte_count":18000,
  "duration_seconds":6,"connection_count":120,"failed_connection_count":100,
  "syn_count":120,"rst_count":100}'
```
Response: classification, risk/signature/anomaly/ML scores, matched rules and `alert_id` if an alert was created.

Optional fields: `flow_id`, `timestamp` (UTC ISO), `unique_destination_ports`, `unique_destination_ips`.
