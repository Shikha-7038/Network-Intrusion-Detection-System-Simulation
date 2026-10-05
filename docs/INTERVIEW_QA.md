# Interview Q&A

| # | Question | Short answer |
|---|---|---|
| 1 | What does your project do? | A hybrid IDS simulation: synthetic flows are scored by rules, a statistical baseline and a Random Forest; alerts go to a SOC-style dashboard with an investigation workflow. |
| 2 | Why synthetic data? | It is safe, legal and repeatable, and labels are known so I can measure precision and recall. Downside: scores are optimistic. |
| 3 | Signature vs anomaly detection? | Signatures catch known patterns with few false positives but miss new ones. Anomaly detection can flag the unknown but produces more false positives. |
| 4 | Why a hybrid score? | No single detector is reliable alone. Weighted blending (40/30/30) lets rules, statistics and ML cover each other's blind spots. |
| 5 | What do your results show? | Random Forest F1 0.99; rules-only slightly beat hybrid on this data because attacks were generated from rule-like patterns. I report this instead of hiding it. |
| 6 | What are false positives and why care? | Benign activity flagged as malicious. Too many cause alert fatigue, so analysts miss real incidents. My Isolation Forest showed this: recall 0.99 but precision 0.56. |
| 7 | Why not just report accuracy? | Data is imbalanced (about 20% suspicious); a model that says "normal" always would still look 80% accurate. Precision, recall and the confusion matrix matter. |
| 8 | Event vs alert vs incident? | Event = one observation; alert = detection needing attention; incident = related alerts grouped (same source and type within 60 s). |
| 9 | How would you improve it? | Real telemetry (Zeek/Suricata), time-window aggregation, threshold tuning with PR curves, MITRE ATT&CK mapping, analyst login and RBAC. |
| 10 | How did you keep it ethical and secure? | Synthetic data only, no packets sent, localhost-only feeder, parameterised SQL, input validation, escaped UI output, optional API key. |

## Follow-ups to prepare
- Explain a z-score and why log scaling is used for rates.
- Explain precision vs recall using your confusion matrix.
- Explain why the anomaly baseline is fitted on normal traffic only.
- Describe how you would tune IDS-001 after a false positive from a backup job.
