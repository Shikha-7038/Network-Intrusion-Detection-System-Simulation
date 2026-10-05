"""Statistical anomaly detection: baseline (mean/std/IQR on NORMAL traffic) -> deviation (z-score) -> 0-100 score."""
import math
import statistics as st

# metric: (log-transform?, minimum std so tiny variance doesn't explode z-scores)
METRICS = {"packets_per_second": (True, 0.3), "bytes_per_second": (True, 0.3), "connection_rate": (True, 0.3),
           "failure_ratio": (False, 0.1), "unique_destination_ports": (False, 1.0)}


class AnomalyDetector:
    def __init__(self):
        self.baseline = {}

    @staticmethod
    def _t(metric, v):
        return math.log1p(v) if METRICS[metric][0] else v

    def fit(self, feature_rows):
        for m, (_, floor) in METRICS.items():
            vals = sorted(self._t(m, r[m]) for r in feature_rows)
            q1, q3 = vals[len(vals) // 4], vals[(3 * len(vals)) // 4]
            self.baseline[m] = {"mean": st.fmean(vals), "std": max(st.pstdev(vals), floor), "q1": q1, "q3": q3,
                                "fence": q3 + 1.5 * (q3 - q1)}
        return self

    def calculate_anomaly_score(self, feat):
        """Return (score 0-100, details). z<=2.5 scores 0; z>=7.5 scores 100 per metric."""
        if not self.baseline:
            return 0.0, {}
        details, scores = {}, []
        for m in METRICS:
            b, v = self.baseline[m], self._t(m, feat[m])
            z = (v - b["mean"]) / b["std"]
            s = min(100.0, max(0.0, (z - 2.5) * 20))
            scores.append(s); details[m] = {"z": round(z, 2), "iqr_outlier": v > b["fence"], "score": round(s, 1)}
        return round(min(100.0, 0.7 * max(scores) + 0.3 * st.fmean(scores)), 1), details
