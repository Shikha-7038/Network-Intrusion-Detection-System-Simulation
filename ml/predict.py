"""Loads the saved Random Forest and returns P(suspicious) in 0-1. Returns None-safe 'ready' flag."""
import os
import joblib, numpy as np
from ids.feature_extractor import ML_FEATURES


class MLDetector:
    def __init__(self, path="models/ids_rf.joblib"):
        self.model = joblib.load(path)["model"] if os.path.exists(path) else None

    @property
    def ready(self):
        return self.model is not None

    def predict_batch(self, feats):
        if not self.ready or not feats:
            return [None] * len(feats)
        X = np.array([[f[c] for c in ML_FEATURES] for f in feats])
        return [float(p) for p in self.model.predict_proba(X)[:, 1]]
