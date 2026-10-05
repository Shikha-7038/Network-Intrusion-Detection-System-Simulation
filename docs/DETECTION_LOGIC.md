# Detection Logic

## Features
| Feature | Formula | Why it matters |
|---|---|---|
| packets_per_second | packets / duration | Floods and scans send many packets quickly |
| bytes_per_second | bytes / duration | Volume pressure, possible exfiltration |
| average_packet_size | bytes / packets | Tiny packets suggest probes; large suggest bulk transfer |
| connection_rate | connections / duration | Burst of new connections |
| failure_ratio | failed / connections | Brute force and probing fail often |
| syn_ratio | SYN / packets | SYN-dominated flows rarely complete handshakes |
| unique_destination_ports | distinct ports | Port scanning behaviour |
| unique_destination_ips | distinct hosts | Sweep behaviour |
| counts | packets, bytes, connections, failures, SYN, RST | Raw volume context |

Validation: invalid IP, port outside 0-65535 or unsupported protocol raises an error (HTTP 422); missing or negative numbers become 0; duration is at least 0.001 s.

## Rules (all thresholds editable in the Rules tab or via API)
| ID | Name | Default severity | Triggers when |
|---|---|---|---|
| IDS-001 | High Connection Rate | HIGH | connections >= 50 and connection_rate >= 15/s |
| IDS-002 | Repeated Failed Connections | HIGH | failed >= 15 and failure ratio >= 0.5 |
| IDS-003 | Multi-Port Activity | HIGH | unique destination ports >= 20 |
| IDS-004 | SYN-Heavy Behavior | MEDIUM | SYN >= 100 and SYN ratio >= 0.6 |
| IDS-005 | Unusual Service Port | MEDIUM | destination port not in the approved list |
| IDS-006 | Abnormal Traffic Volume | CRITICAL | bytes >= 50 MB or bytes/s >= 5 MB/s |

Approved ports: 20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443.

Signature score = highest matched severity score + 5 per extra matched rule (cap 100).

| Severity | Score |
|---|---|
| INFO | 20 |
| LOW | 40 |
| MEDIUM | 60 |
| HIGH | 80 |
| CRITICAL | 95 |

## Anomaly detector
- Baseline (mean, std, quartiles) is fitted on **normal** flows only.
- Metrics: packets/s, bytes/s, connection rate (log scale), failure ratio, unique ports.
- Per-metric score = clamp((z - 2.5) x 20, 0, 100); final = 0.7 x max + 0.3 x mean.
- A minimum standard deviation per metric prevents tiny variance from exploding the z-score.

## Correlation
- EVENT = one flow. ALERT = detection needing attention. INCIDENT = related alerts.
- Alerts with the same source IP and alert type belong to one incident until a gap above 60 seconds.

## Alert lifecycle
| Status | Meaning |
|---|---|
| NEW | Generated, not yet reviewed |
| INVESTIGATING | Analyst is working on it |
| RESOLVED | Handled |
| FALSE_POSITIVE | Benign activity; useful for tuning rules |

## Recommended investigation steps (shown in the drawer)
- Review related logs for the source IP.
- Check whether the source is a known or authorised host.
- Compare activity with the historical baseline.
- Check authentication logs for the destination.
- Review firewall records and (where authorised) endpoint telemetry.
- Decide whether the activity is expected (backup, scanner, batch job).
