"""
DeceptIQ Threat Intelligence Module

Reads the project's existing security data and produces a report using
the same top-level JSON structure as security_report(1).json:
metadata, summary, assets, alerts, honeypot, routing, anomalies.

This is local evidence-based enrichment. It does not claim external IP
reputation or live threat-feed verification.
"""

import json
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data-ingestion" / "data"
ENGINE_DIR = ROOT_DIR / "engine"
INTERMEDIATE_DIR = ENGINE_DIR / "intermediate_output"

ASSETS_FILE = DATA_DIR / "assets.csv"
NETWORK_LOGS_FILE = DATA_DIR / "network_logs.csv"
SERVER_LOGS_FILE = DATA_DIR / "server_logs.csv"
HONEYPOT_FILE = DATA_DIR / "honeypot_events.json"
VULNERABILITIES_FILE = DATA_DIR / "vulnerabilities.json"

VULNERABILITY_FINDINGS_FILE = INTERMEDIATE_DIR / "vulnerability_findings.json"
RISK_ASSESSMENT_FILE = INTERMEDIATE_DIR / "risk_assessment.json"
CORRELATED_EVENTS_FILE = INTERMEDIATE_DIR / "correllated_events.json"

# Existing report is used as the structural/template source.
SECURITY_REPORT_FILE = ENGINE_DIR / "security_report.json"

# New output, retaining the same JSON schema.
OUTPUT_FILE = ENGINE_DIR / "security_report.json"


def read_json(path, default=None, required=False):
    if not path.exists():
        if required:
            raise FileNotFoundError(f"Required JSON file not found: {path}")
        return default
    content = path.read_text(encoding="utf-8-sig").strip()
    if not content:
        return default
    return json.loads(content)


def read_csv(path):
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path).fillna("")


def normalise(value):
    return str(value or "").strip().lower()


def as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def unique_list(values):
    result = []
    seen = set()
    for value in values:
        if value in (None, ""):
            continue
        marker = str(value)
        if marker not in seen:
            seen.add(marker)
            result.append(value)
    return result


def severity_for_event(event_type, request_count=0, sensitive_count=0):
    event_type = str(event_type or "").upper()
    if event_type == "PATH_TRAVERSAL_ATTEMPT":
        return "CRITICAL"
    if event_type in {"HIGH_REQUEST_RATE", "SENSITIVE_PATH_PROBING"}:
        return "HIGH"
    if event_type == "EXCESSIVE_404_ERRORS":
        return "MEDIUM"
    if sensitive_count >= 3 or request_count >= 50:
        return "HIGH"
    return "MEDIUM"


def make_alert_id(prefix, identity):
    # Stable ID so repeated runs do not create random duplicate IDs.
    import hashlib
    digest = hashlib.sha1(str(identity).encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


def load_existing_report():
    report = read_json(SECURITY_REPORT_FILE, default={}, required=True)
    required_keys = {
        "metadata", "summary", "assets", "alerts",
        "honeypot", "routing", "anomalies"
    }
    missing = required_keys - set(report.keys())
    if missing:
        raise ValueError(
            "security_report.json is missing required sections: "
            + ", ".join(sorted(missing))
        )
    return report


def load_asset_context():
    assets_df = read_csv(ASSETS_FILE)
    if assets_df.empty:
        raise ValueError(f"No asset records found in {ASSETS_FILE}")

    assets = {}
    for row in assets_df.to_dict("records"):
        asset_id = str(row.get("asset_id", ""))
        if asset_id:
            assets[asset_id] = {
                "asset_id": asset_id,
                "hostname": row.get("hostname", ""),
                "ip_address": row.get("ip_address", ""),
                "software": row.get("software", ""),
                "version": row.get("version", ""),
                "environment": row.get("environment", ""),
                "internet_exposed": as_bool(row.get("internet_exposed", False)),
            }
    return assets


def load_risk_by_asset():
    risk = read_json(RISK_ASSESSMENT_FILE, default={})
    return {
        str(item.get("asset_id")): item
        for item in risk.get("assets", [])
        if item.get("asset_id")
    }


def load_validated_cves_by_asset(risk_by_asset):
    """Use risk assessment's validated CVEs, not raw unvalidated findings."""
    result = {}
    for asset_id, item in risk_by_asset.items():
        result[asset_id] = item.get("vulnerabilities", [])
    return result


def build_vulnerability_intelligence(vulnerabilities_db, cves_by_asset):
    """Enrich each asset's already-validated CVEs with KEV and CVSS data."""
    enriched = {}
    for asset_id, cves in cves_by_asset.items():
        records = []
        for item in cves:
            cve_id = item.get("cve_id")
            db_record = vulnerabilities_db.get(cve_id, {})
            records.append({
                "cve_id": cve_id,
                "severity": item.get("severity") or db_record.get("severity"),
                "cvss_score": item.get("cvss_score", db_record.get("cvss_score")),
                "is_kev": as_bool(
                    item.get("is_kev", db_record.get("is_kev", False))
                ),
                "description": (
                    item.get("description")
                    or (db_record.get("description") or {}).get("short")
                ),
                "references": db_record.get("references", []),
            })
        enriched[asset_id] = records
    return enriched


def build_log_alerts(network_df, server_df, assets):
    alerts = []
    source_evidence = defaultdict(lambda: {
        "event_types": [],
        "network_events": 0,
        "server_events": 0,
        "paths": [],
        "assets": set(),
        "timestamps": [],
    })

    # Aggregated network security events. These rows identify a source IP
    # and event category, but do not contain an asset_id. Attribute an asset
    # only if the same source IP is observed against an asset in server logs.
    ip_to_assets = defaultdict(set)
    for _, row in server_df.iterrows():
        ip = str(row.get("source_ip", "")).strip()
        asset_id = str(row.get("asset_id", "")).strip()
        if ip and asset_id in assets:
            ip_to_assets[ip].add(asset_id)

    for _, row in network_df.iterrows():
        ip = str(row.get("source_ip", "")).strip()
        event_type = str(row.get("anomaly_type", "NETWORK_ACTIVITY")).strip().upper()
        timestamp = str(row.get("timestamp", ""))
        try:
            request_count = int(row.get("request_count") or 0)
        except (ValueError, TypeError):
            request_count = 0
        try:
            sensitive_count = int(row.get("sensitive_request_count") or 0)
        except (ValueError, TypeError):
            sensitive_count = 0

        evidence = source_evidence[ip]
        evidence["event_types"].append(event_type)
        evidence["network_events"] += 1
        evidence["paths"].extend(
            str(row.get("suspicious_paths", "")).split(";")
        )
        evidence["timestamps"].append(timestamp)
        evidence["assets"].update(ip_to_assets.get(ip, set()))

        severity = severity_for_event(event_type, request_count, sensitive_count)
        related_assets = sorted(ip_to_assets.get(ip, set()))
        description = (
            f"{event_type.replace('_', ' ').title()} observed by "
            f"{row.get('detector', 'network log analyzer')}. "
            f"{request_count} requests in {row.get('window_seconds', 60)} seconds; "
            f"{sensitive_count} sensitive requests."
        )

        if event_type == "PATH_TRAVERSAL_ATTEMPT":
            description += f" Trigger URI: {row.get('trigger_uri', '')}."

        for asset_id in related_assets or [""]:
            asset = assets.get(asset_id, {})
            identity = f"network|{ip}|{event_type}|{timestamp}|{asset_id}"
            alerts.append({
                "alert_id": make_alert_id("TI", identity),
                "timestamp": timestamp,
                "asset_id": asset_id or None,
                "source_ip": ip,
                "alert_type": event_type,
                "severity": severity,
                "description": description,
                "risk_score": None,
                "recommended_action": (
                    "Investigate the source IP and request pattern; block or rate-limit "
                    "only after validating the activity."
                ),
            })

    # Detailed server requests. Group by source IP and asset, then add
    # one summary alert for sensitive-path activity or repeated login failures.
    grouped = defaultdict(list)
    for _, row in server_df.iterrows():
        ip = str(row.get("source_ip", "")).strip()
        asset_id = str(row.get("asset_id", "")).strip()
        grouped[(ip, asset_id)].append(row.to_dict())

    sensitive_tokens = (
        "/.env", "/.git", "/config", "/backup", "/admin",
        "/phpmyadmin", "../", "%2e", "/etc/passwd"
    )

    for (ip, asset_id), rows in grouped.items():
        sensitive_rows = [
            row for row in rows
            if any(token in normalise(row.get("path")) for token in sensitive_tokens)
        ]
        failed_logins = [
            row for row in rows
            if normalise(row.get("method")).upper() == "POST"
            and normalise(row.get("path")).rstrip("/") == "/login"
            and str(row.get("status")) == "401"
        ]

        if sensitive_rows:
            timestamp = str(sensitive_rows[-1].get("timestamp", ""))
            paths = unique_list([row.get("path") for row in sensitive_rows])
            alerts.append({
                "alert_id": make_alert_id(
                    "TI", f"server-sensitive|{ip}|{asset_id}|{'|'.join(paths)}"
                ),
                "timestamp": timestamp,
                "asset_id": asset_id or None,
                "source_ip": ip,
                "alert_type": "SENSITIVE_HTTP_REQUESTS",
                "severity": "HIGH",
                "description": (
                    f"{len(sensitive_rows)} requests to sensitive paths: "
                    + ", ".join(paths[:8])
                ),
                "risk_score": None,
                "recommended_action": (
                    "Review web-server access logs, verify whether the paths exist, "
                    "and investigate or block the source if malicious."
                ),
            })

        if len(failed_logins) >= 3:
            alerts.append({
                "alert_id": make_alert_id("TI", f"server-login|{ip}|{asset_id}"),
                "timestamp": str(failed_logins[-1].get("timestamp", "")),
                "asset_id": asset_id or None,
                "source_ip": ip,
                "alert_type": "BRUTE_FORCE",
                "severity": "HIGH" if len(failed_logins) >= 10 else "MEDIUM",
                "description": (
                    f"{len(failed_logins)} failed login attempts observed for "
                    f"{asset_id or 'an unassigned asset'}."
                ),
                "risk_score": None,
                "recommended_action": (
                    "Review authentication activity and apply rate limiting, MFA "
                    "and account protection controls as appropriate."
                ),
            })

    return alerts, source_evidence, ip_to_assets


def build_honeypot_intelligence(honeypot_data, source_evidence, ip_to_assets):
    events = honeypot_data.get("events", []) if isinstance(honeypot_data, dict) else []
    enriched_events = []
    source_counts = Counter()

    for event in events:
        ip = str(event.get("source_ip", ""))
        source_counts[ip] += 1
        enriched = dict(event)
        enriched["observed_in_network_logs"] = ip in source_evidence
        enriched["related_asset_ids"] = sorted(ip_to_assets.get(ip, set()))
        # Do not label an IP malicious based only on a honeypot hit.
        enriched["intelligence_assessment"] = "SUSPICIOUS_INTERACTION_OBSERVED"
        enriched_events.append(enriched)

    return {
        "status": "ACTIVE" if events else "NO_EVENTS",
        "total_interactions": len(events),
        "unique_source_ips": len(source_counts),
        "events": enriched_events,
    }, source_counts


def build_routing(honeypot_summary, existing_routing):
    # Retain existing routing decisions, then add only observed honeypot
    # sources not already present. This module recommends; it does not route.
    routing = list(existing_routing or [])
    known_ips = {str(item.get("source_ip", "")) for item in routing}

    for event in honeypot_summary.get("events", []):
        ip = str(event.get("source_ip", ""))
        if not ip or ip in known_ips:
            continue
        routing.append({
            "source_ip": ip,
            "action": "REVIEW_FOR_HONEYPOT",
            "reason": (
                "Source IP interacted with the honeypot. Validate surrounding "
                "activity before applying automated blocking or redirection."
            ),
            "status": "RECOMMENDED",
        })
        known_ips.add(ip)

    return routing


def main():
    print("\n========== DECEPTIQ THREAT INTELLIGENCE ==========\n")

    report = load_existing_report()
    assets = load_asset_context()
    risk_by_asset = load_risk_by_asset()
    vulnerabilities_db = read_json(VULNERABILITIES_FILE, default={}, required=True)
    cves_by_asset = load_validated_cves_by_asset(risk_by_asset)
    cve_intel_by_asset = build_vulnerability_intelligence(
        vulnerabilities_db, cves_by_asset
    )

    network_df = read_csv(NETWORK_LOGS_FILE)
    server_df = read_csv(SERVER_LOGS_FILE)
    honeypot_data = read_json(HONEYPOT_FILE, default={"events": []})

    network_alerts, source_evidence, ip_to_assets = build_log_alerts(
        network_df, server_df, assets
    )

    # Preserve original report alerts and add new intelligence alerts.
    existing_alerts = list(report.get("alerts", []))
    seen_alert_keys = {
        (
            str(item.get("source_ip", "")),
            str(item.get("alert_type", "")),
            str(item.get("asset_id", "")),
            str(item.get("timestamp", "")),
        )
        for item in existing_alerts
    }

    merged_alerts = existing_alerts[:]
    for alert in network_alerts:
        key = (
            str(alert.get("source_ip", "")),
            str(alert.get("alert_type", "")),
            str(alert.get("asset_id", "")),
            str(alert.get("timestamp", "")),
        )
        if key not in seen_alert_keys:
            merged_alerts.append(alert)
            seen_alert_keys.add(key)

    honeypot_summary, honeypot_source_counts = build_honeypot_intelligence(
        honeypot_data, source_evidence, ip_to_assets
    )

    # Keep the original honeypot event shape, enriched with evidence fields.
    report["honeypot"] = honeypot_summary
    report["routing"] = build_routing(
        honeypot_summary, report.get("routing", [])
    )

    # Populate each existing asset record with validated CVE and intelligence
    # indicators while retaining its original keys and overall schema.
    enriched_assets = []
    existing_asset_rows = {
        str(item.get("asset_id")): item
        for item in report.get("assets", [])
        if item.get("asset_id")
    }

    # Include every asset from assets.csv, even if the template report
    # currently contains only a subset of the inventory.
    for asset_id, asset in assets.items():
        original = existing_asset_rows.get(asset_id, {
            "asset_id": asset_id,
            "hostname": asset.get("hostname", ""),
            "ip_address": asset.get("ip_address", ""),
            "risk_score": risk_by_asset.get(asset_id, {}).get("risk_score", 0),
            "risk_level": risk_by_asset.get(asset_id, {}).get("risk_level", "LOW"),
            "internet_exposed": asset.get("internet_exposed", False),
            "findings": {},
            "cves": [],
            "remediation_status": "OPEN",
        })
        risk = risk_by_asset.get(asset_id, {})
        asset_copy = dict(original)

        findings = dict(asset_copy.get("findings", {}))
        cves = cve_intel_by_asset.get(asset_id, [])
        findings["vulnerability"] = bool(cves)

        risk_factors = risk.get("risk_factors", {})
        findings["suspicious_http"] = bool(
            findings.get("suspicious_http")
            or risk_factors.get("suspicious_http", False)
        )
        findings["brute_force"] = bool(
            findings.get("brute_force")
            or risk_factors.get("brute_force", False)
        )
        findings["port_scan"] = bool(
            findings.get("port_scan")
            or risk_factors.get("port_scan", False)
        )
        findings["ml_anomaly"] = bool(
            findings.get("ml_anomaly")
            or risk_factors.get("ml_anomaly_count", 0)
        )

        asset_copy["findings"] = findings
        asset_copy["cves"] = cves

        # Use the current risk assessment's score if available.
        if risk.get("risk_score") is not None:
            asset_copy["risk_score"] = risk["risk_score"]
            asset_copy["risk_level"] = risk.get(
                "risk_level", asset_copy.get("risk_level")
            )

        if asset:
            asset_copy["hostname"] = asset.get("hostname", asset_copy.get("hostname"))
            asset_copy["ip_address"] = asset.get("ip_address", asset_copy.get("ip_address"))
            asset_copy["internet_exposed"] = asset.get(
                "internet_exposed", asset_copy.get("internet_exposed")
            )

        enriched_assets.append(asset_copy)

    report["assets"] = enriched_assets
    report["alerts"] = merged_alerts

    # Keep existing anomaly section as-is because the user has not generated
    # anomaly findings yet.
    report["anomalies"] = report.get("anomalies", [])

    # Update summary values while retaining the same summary field names.
    summary = dict(report.get("summary", {}))
    summary["total_assets"] = len(assets)
    summary["vulnerable_assets"] = sum(
        1 for item in enriched_assets
        if item.get("findings", {}).get("vulnerability")
    )
    summary["suspicious_assets"] = sum(
        1 for item in enriched_assets
        if any([
            item.get("findings", {}).get("suspicious_http"),
            item.get("findings", {}).get("brute_force"),
            item.get("findings", {}).get("port_scan"),
        ])
    )
    summary["total_alerts"] = len(merged_alerts)

    severity_counts = Counter(
        str(alert.get("severity", "LOW")).upper()
        for alert in merged_alerts
    )
    summary["critical_alerts"] = severity_counts.get("CRITICAL", 0)
    summary["high_alerts"] = severity_counts.get("HIGH", 0)
    summary["medium_alerts"] = severity_counts.get("MEDIUM", 0)
    summary["low_alerts"] = severity_counts.get("LOW", 0)
    summary["anomalies_detected"] = sum(
        1 for item in report["anomalies"] if as_bool(item.get("detected"))
    )
    summary["honeypot_interactions"] = honeypot_summary["total_interactions"]
    report["summary"] = summary

    # Update metadata without changing its field structure.
    report["metadata"] = dict(report.get("metadata", {}))
    report["metadata"]["generated_at"] = datetime.now(timezone.utc).isoformat()
    report["metadata"]["report_version"] = (
        report["metadata"].get("report_version", "1.0")
    )

    # Add module provenance inside metadata (same top-level report structure).
    report["metadata"]["generated_by"] = "DeceptIQ Threat Intelligence"
    report["metadata"]["intelligence_sources"] = [
        "vulnerabilities.json",
        "vulnerability_findings validated through risk_assessment.json",
        "network_logs.csv",
        "server_logs.csv",
        "honeypot_events.json",
    ]

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(report, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )

    print("Threat intelligence report generated.")
    print(f"Assets: {summary['total_assets']}")
    print(f"Alerts: {summary['total_alerts']}")
    print(f"KEV CVEs by asset: " + str({
        asset_id: sum(1 for cve in records if cve.get("is_kev"))
        for asset_id, records in cve_intel_by_asset.items()
    }))
    print(f"Honeypot interactions: {summary['honeypot_interactions']}")
    print(f"Output: {OUTPUT_FILE}")
    print("\nNote: IP reputation is not externally verified by this local-data module.")
    print("\n==================================================\n")


if __name__ == "__main__":
    main()
