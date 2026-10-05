"""Train + evaluate Logistic Regression, Random Forest (supervised) and Isolation Forest (unsupervised).
All metrics are computed from the generated dataset - nothing is hard-coded."""
import json, os
import joblib, numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from ids.feature_extractor import ML_FEATURES, extract_network_features


def build_matrix(rows):
    return np.array([[extract_network_features(r)[c] for c in ML_FEATURES] for r in rows])


def _metrics(y, pred):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"accuracy": round(accuracy_score(y, pred), 4), "precision": round(precision_score(y, pred, zero_division=0), 4),
            "recall": round(recall_score(y, pred, zero_division=0), 4), "f1": round(f1_score(y, pred, zero_division=0), 4),
            "confusion": [[int(tn), int(fp)], [int(fn), int(tp)]]}


def train(df):
    X, y = build_matrix(df.to_dict("records")), (df["label"] == "SUSPICIOUS").astype(int).values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced")).fit(Xtr, ytr)
    rf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42, n_jobs=1).fit(Xtr, ytr)
    iso = make_pipeline(StandardScaler(), IsolationForest(contamination=0.2, random_state=42)).fit(Xtr[ytr == 0])
    metrics = {"rows": int(len(df)), "test_rows": int(len(yte)), "features": ML_FEATURES, "models": {
        "logistic_regression": _metrics(yte, lr.predict(Xte)), "random_forest": _metrics(yte, rf.predict(Xte)),
        "isolation_forest": _metrics(yte, (iso.predict(Xte) == -1).astype(int))}}
    return {"model": rf, "features": ML_FEATURES}, metrics


if __name__ == "__main__":
    df = pd.read_csv("data/network_traffic.csv")
    bundle, m = train(df)
    os.makedirs("models", exist_ok=True)
    joblib.dump(bundle, "models/ids_rf.joblib"); json.dump(m, open("models/metrics.json", "w"), indent=2)
    for name, r in m["models"].items():
        print(f"{name:20s} acc={r['accuracy']} prec={r['precision']} rec={r['recall']} f1={r['f1']} cm={r['confusion']}")
