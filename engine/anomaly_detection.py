"""DeceptIQ anomaly detection using Isolation Forest.

Run from project root: python engine/anomaly_detection.py
Inputs: data-ingestion/data/network_logs.csv and server_logs.csv
Outputs: engine/intermediate_output/anomaly_findings.json and anomaly_model.joblib
"""
from pathlib import Path
from datetime import datetime, timezone
import json
import re
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data-ingestion" / "data"
NETWORK_FILE = DATA / "network_logs.csv"
SERVER_FILE = DATA / "server_logs.csv"
OUT_DIR = ROOT / "engine" / "intermediate_output"
MODEL_FILE = OUT_DIR / "anomaly_model.joblib"
OUTPUT_FILE = OUT_DIR / "anomaly_findings.json"

SENSITIVE = ("/.env", "/.git", "/backup", "/config", "/phpmyadmin", "/admin", "/etc/passwd")
TRAVERSAL = re.compile(r"\.\./|%2e%2e", re.IGNORECASE)
FEATURES = ["request_count", "http_404_count", "sensitive_request_count",
            "failed_login_count", "unique_paths", "path_traversal_count"]


def safe_int(value):
    try:
        return int(value) if pd.notna(value) else 0
    except (TypeError, ValueError):
        return 0


def build_observations():
    observations = []

    if NETWORK_FILE.exists():
        net = pd.read_csv(NETWORK_FILE).fillna("")
        for _, row in net.iterrows():
            paths = [p.strip() for p in str(row.get("suspicious_paths", "")).split(";") if p.strip()]
            trigger = str(row.get("trigger_uri", ""))
            all_paths = paths + ([trigger] if trigger else [])
            observations.append({
                "observation_id": str(row.get("event_id", f"NET-{len(observations)+1}")),
                "source": "network_logs", "asset_id": None,
                "source_ip": str(row.get("source_ip", "")),
                "timestamp": str(row.get("timestamp", "")),
                "anomaly_type": str(row.get("anomaly_type", "NETWORK_EVENT")),
                "request_count": safe_int(row.get("request_count")),
                "http_404_count": safe_int(row.get("http_404_count")),
                "sensitive_request_count": safe_int(row.get("sensitive_request_count")),
                "failed_login_count": 0,
                "unique_paths": len(set(all_paths)),
                "path_traversal_count": sum(bool(TRAVERSAL.search(p)) for p in all_paths),
                "evidence": ";".join(all_paths[:8]),
            })

    if SERVER_FILE.exists():
        server = pd.read_csv(SERVER_FILE).fillna("")
        if not server.empty:
            server["_sensitive"] = server["path"].astype(str).str.lower().apply(
                lambda p: int(any(term in p for term in SENSITIVE)))
            server["_failed_login"] = ((server["method"].astype(str).str.upper() == "POST") &
                                       (server["path"].astype(str).str.lower() == "/login") &
                                       (pd.to_numeric(server["status"], errors="coerce") == 401)).astype(int)
            server["_traversal"] = server["path"].astype(str).apply(lambda p: int(bool(TRAVERSAL.search(p))))
            group_cols = [c for c in ["asset_id", "source_ip"] if c in server.columns]
            for (asset_id, source_ip), group in server.groupby(group_cols, dropna=False):
                paths = group["path"].astype(str).tolist()
                observations.append({
                    "observation_id": f"WEB-{asset_id}-{source_ip}",
                    "source": "server_logs", "asset_id": str(asset_id),
                    "source_ip": str(source_ip),
                    "timestamp": str(group["timestamp"].max()),
                    "anomaly_type": "SERVER_LOG_ACTIVITY",
                    "request_count": len(group),
                    "http_404_count": int((pd.to_numeric(group["status"], errors="coerce") == 404).sum()),
                    "sensitive_request_count": int(group["_sensitive"].sum()),
                    "failed_login_count": int(group["_failed_login"].sum()),
                    "unique_paths": len(set(paths)),
                    "path_traversal_count": int(group["_traversal"].sum()),
                    "evidence": ";".join(paths[:8]),
                })
    return observations


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    observations = build_observations()
    if len(observations) < 5:
        raise SystemExit(f"Not enough observations to fit a demo model: found {len(observations)}; need at least 5.")

    frame = pd.DataFrame(observations)
    X = frame[FEATURES].fillna(0).astype(float)
    model = Pipeline([
        ("scale", StandardScaler()),
        ("isolation_forest", IsolationForest(
            n_estimators=150, contamination=0.25, random_state=42
        )),
    ])
    model.fit(X)
    predictions = model.predict(X)  # -1 = anomaly, 1 = normal
    decision_scores = model.decision_function(X)  # lower = more unusual
    joblib.dump({"model": model, "features": FEATURES}, MODEL_FILE)

    findings = []
    for i, row in frame.iterrows():
        is_anomaly = int(predictions[i]) == -1
        findings.append({
            "observation_id": row["observation_id"],
            "source": row["source"],
            "asset_id": str(row["asset_id"]) if pd.notna(row["asset_id"]) and str(row["asset_id"]).strip() else None,
            "source_ip": row["source_ip"],
            "timestamp": row["timestamp"],
            "detected": is_anomaly,
            "anomaly_score": round(float(decision_scores[i]), 5),
            "severity": "HIGH" if is_anomaly and float(decision_scores[i]) < -0.05 else ("MEDIUM" if is_anomaly else "NORMAL"),
            "description": "Unusual activity pattern identified by Isolation Forest" if is_anomaly else "No anomaly detected by the trained model",
            "features": {name: int(row[name]) for name in FEATURES},
            "evidence": row["evidence"],
        })

    report = {
        "module": "DeceptIQ Anomaly Detection",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": "IsolationForest",
        "training_observations": len(observations),
        "features_used": FEATURES,
        "training_note": "Hackathon demonstration model trained on the currently available sample logs. Collect more normal baseline traffic and labelled incidents before production use.",
        "summary": {
            "total_observations": len(observations),
            "anomalies_detected": int(sum(predictions == -1)),
            "normal_observations": int(sum(predictions == 1)),
        },
        "findings": findings,
    }
    OUTPUT_FILE.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    print("Anomaly model trained successfully.")
    print(f"Observations used: {len(observations)}")
    print(f"Anomalies detected: {report['summary']['anomalies_detected']}")
    print(f"Model saved: {MODEL_FILE}")
    print(f"Findings saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
