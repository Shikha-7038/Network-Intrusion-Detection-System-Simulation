# Detection Evaluation (held-out 25% split, synthetic data)

- Test flows: **1500** (301 suspicious, 1199 normal)
- Hybrid alert threshold: risk score > 40. Anomaly-only threshold: anomaly score > 40.
- Scores are optimistic because the synthetic data follows the same patterns the detectors look for.

## Detector comparison

| Detector | Precision | Recall | F1 | Accuracy | False positives | Missed attacks |
|---|---|---|---|---|---|---|
| Rules only | 1.000 | 0.997 | 0.998 | 0.999 | 0 | 1 |
| Anomaly only | 0.952 | 0.724 | 0.823 | 0.937 | 11 | 83 |
| Hybrid (rules + anomaly + ML) | 1.000 | 0.987 | 0.993 | 0.997 | 0 | 4 |

## Per-scenario detection rate

| Scenario | Flows | Label | Rules | Anomaly | Hybrid |
|---|---|---|---|---|---|
| HIGH_CONNECTION_RATE | 52 | SUSPICIOUS | 100% | 100% | 100% |
| HIGH_TRAFFIC_VOLUME | 56 | SUSPICIOUS | 100% | 91% | 100% |
| MULTI_PORT_PROBING_PATTERN | 44 | SUSPICIOUS | 100% | 100% | 100% |
| NORMAL_DATABASE | 123 | NORMAL | 0% | 0% | 0% |
| NORMAL_DNS | 254 | NORMAL | 0% | 1% | 0% |
| NORMAL_EMAIL | 134 | NORMAL | 0% | 0% | 0% |
| NORMAL_SSH | 86 | NORMAL | 0% | 6% | 0% |
| NORMAL_WEB | 602 | NORMAL | 0% | 0% | 0% |
| REPEATED_FAILED_CONNECTIONS | 48 | SUSPICIOUS | 98% | 98% | 100% |
| SYN_HEAVY_PATTERN | 48 | SUSPICIOUS | 100% | 50% | 100% |
| UNUSUAL_PORT_ACTIVITY | 53 | SUSPICIOUS | 100% | 0% | 92% |

_For NORMAL scenarios a non-zero rate is a **false-positive rate**; for SUSPICIOUS scenarios it is the **detection rate**._

## Supervised / unsupervised model metrics (from `models/metrics.json`)

| Model | Accuracy | Precision | Recall | F1 | TN | FP | FN | TP |
|---|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.9367 | 0.8527 | 0.8272 | 0.8398 | 1156 | 43 | 52 | 249 |
| Random Forest | 0.9967 | 0.9966 | 0.9867 | 0.9917 | 1198 | 1 | 4 | 297 |
| Isolation Forest | 0.844 | 0.5631 | 0.9934 | 0.7188 | 967 | 232 | 2 | 299 |
