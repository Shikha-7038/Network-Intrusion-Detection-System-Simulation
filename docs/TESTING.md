# Testing

Run: `python -m unittest discover -s tests -v` (34 tests; also works with pytest).

| Group | Tests | What is checked |
|---|---|---|
| Normal traffic | 4 | TCP, UDP, DNS, HTTPS flows trigger no rules |
| Suspicious patterns | 6 | Each of IDS-001..006 fires on its pattern |
| Validation / edge cases | 7 | Bad source/destination IP, bad ports, bad protocol, missing packet count, zero duration |
| Engines | 7 | Feature maths, configurable thresholds, anomaly low/high score, risk formula, risk bands, alert creation, correlation grouping |
| API / database | 10 | Status updates, analyst notes, DB storage, dashboard stats, ML recall, API validation, empty database, duplicate flow, dataset size and IP ranges, rule update |

## Manual test checklist (dashboard)
| # | Step | Expected |
|---|---|---|
| 1 | Open Overview | KPIs and 9 charts populate; feed updates every ~3 s |
| 2 | Alerts tab, severity = CRITICAL | Only critical alerts listed |
| 3 | Click an alert | Drawer shows scores, reason, steps |
| 4 | Click INVESTIGATING, add a note | Timeline shows status change and note |
| 5 | Incidents tab, click a row | Opens its first alert |
| 6 | Flows tab, search an IP | Table filters instantly |
| 7 | Rules tab, disable IDS-005 | New flows no longer trigger it |
| 8 | Model tab, Download .md | Report file downloads |
