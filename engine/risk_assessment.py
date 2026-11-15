import json
from collections import defaultdict
from pathlib import Path

import pandas as pd
from packaging.version import Version, InvalidVersion


# ============================================================
# DECEPTIQ - ASSET RISK ASSESSMENT
# Combines validated vulnerability, network, honeypot and
# optional ML anomaly findings into an asset-level risk score.
# ============================================================

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data-ingestion" / "data"
ENGINE_DIR = ROOT_DIR / "engine"
INTERMEDIATE_DIR = ENGINE_DIR / "intermediate_output"

ASSETS_FILE = DATA_DIR / "assets.csv"
VULNERABILITIES_FILE = DATA_DIR / "vulnerabilities.json"
SERVER_LOGS_FILE = DATA_DIR / "server_logs.csv"
HONEYPOT_FILE = DATA_DIR / "honeypot_events.json"
NETWORK_LOGS_FILE = DATA_DIR / "network_logs.csv"

VULNERABILITY_FINDINGS_FILE = (
    INTERMEDIATE_DIR / "vulnerability_findings.json"
)
CORRELATED_EVENTS_FILE = (
    INTERMEDIATE_DIR / "correllated_events.json"
)
ANOMALY_FINDINGS_FILE = (
    INTERMEDIATE_DIR / "anomaly_findings.json"
)

OUTPUT_FILE = INTERMEDIATE_DIR / "risk_assessment.json"


# ----------------------------
# Initial DeceptIQ scoring model
# ----------------------------
# Maximum component contributions:
# Vulnerabilities:       35
# CISA KEV:               15
# Internet exposure:     10
# Production environment: 5
# Suspicious HTTP:        12
# Brute force:             8
# Port scan:               8
# Honeypot correlation:    8
# ML anomaly:             10
# Final score is capped at 100.

SEVERITY_THRESHOLDS = {
    "CRITICAL": 85,
    "HIGH": 65,
    "MEDIUM": 35,
    "LOW": 0,
}


def load_json(path, required=True, default=None):
    """Load JSON safely. Optional files return their default if absent."""
    if not path.exists():
        if required:
            raise FileNotFoundError(f"Required file not found: {path}")
        return default

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def load_csv(path, required=True):
    """Load CSV safely."""
    if not path.exists():
        if required:
            raise FileNotFoundError(f"Required file not found: {path}")
        return pd.DataFrame()

    return pd.read_csv(path)


def normalise(value):
    return str(value or "").strip().lower()


def parse_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def version_is_affected(installed_version, product):
    """
    Return True/False/None for a CPE product version match.
    None means the available CPE data cannot establish a safe match.
    """
    try:
        installed = Version(str(installed_version))
    except (InvalidVersion, TypeError):
        return None

    cpe_version = product.get("cpe_version")

    # Exact CPE version
    if cpe_version and cpe_version not in {"*", "-"}:
        try:
            return installed == Version(str(cpe_version))
        except InvalidVersion:
            return None

    start_including = product.get("version_start_including")
    start_excluding = product.get("version_start_excluding")
    end_including = product.get("version_end_including")
    end_excluding = product.get("version_end_excluding")

    try:
        if start_including and installed < Version(str(start_including)):
            return False
        if start_excluding and installed <= Version(str(start_excluding)):
            return False
        if end_including and installed > Version(str(end_including)):
            return False
        if end_excluding and installed >= Version(str(end_excluding)):
            return False
    except InvalidVersion:
        return None

    if not any([
        start_including,
        start_excluding,
        end_including,
        end_excluding,
    ]):
        return None

    return True


def get_validated_vulnerabilities(asset, finding_rows, vulnerability_db):
    """
    Validate each vulnerability finding against:
    1. The asset's actual software name.
    2. The asset's installed version.
    3. The affected product/version data in vulnerabilities.json.

    This avoids counting CVEs for a different product as confirmed findings.
    """
    asset_id = asset["asset_id"]
    asset_software = normalise(asset.get("software"))
    installed_version = asset.get("version")

    validated = {}
    rejected_product_mismatch = 0
    unresolved_version = 0

    for row in finding_rows:
        if str(row.get("asset_id")) != str(asset_id):
            continue

        finding = row.get("vulnerabilities", {})
        cve_id = finding.get("cve_id")

        if not cve_id or cve_id not in vulnerability_db:
            continue

        cve_record = vulnerability_db[cve_id]

        matching_products = [
            product
            for product in cve_record.get("affected_products", [])
            if normalise(product.get("software")) == asset_software
        ]

        if not matching_products:
            rejected_product_mismatch += 1
            continue

        version_results = [
            version_is_affected(installed_version, product)
            for product in matching_products
        ]

        if True in version_results:
            validated[cve_id] = cve_record
        elif any(result is None for result in version_results):
            unresolved_version += 1

    return (
        list(validated.values()),
        rejected_product_mismatch,
        unresolved_version,
    )


def build_network_indicators(assets, correlated_events, server_logs):
    """Build asset-level indicators from correlated events and server logs."""
    indicators = {
        str(asset["asset_id"]): {
            "suspicious_http": False,
            "brute_force": False,
            "port_scan": False,
            "server_log_events": 0,
            "failed_login_attempts": 0,
            "suspicious_http_events": 0,
        }
        for asset in assets
    }

    # Existing event-correlation output
    for event in correlated_events:
        asset_id = str(event.get("asset_id", ""))
        if asset_id not in indicators:
            continue

        indicators[asset_id]["suspicious_http"] |= parse_bool(
            event.get("Suspicious_HTTP", False)
        )
        indicators[asset_id]["brute_force"] |= parse_bool(
            event.get("Brute_Force", False)
        )
        indicators[asset_id]["port_scan"] |= parse_bool(
            event.get("Port_Scan", event.get("port_scan", False))
        )

    # Server logs provide direct asset_id attribution.
    if not server_logs.empty and "asset_id" in server_logs.columns:
        for _, row in server_logs.iterrows():
            asset_id = str(row.get("asset_id", ""))
            if asset_id not in indicators:
                continue

            item = indicators[asset_id]
            item["server_log_events"] += 1

            path = normalise(row.get("path"))
            method = normalise(row.get("method")).upper()
            try:
                status = int(row.get("status"))
            except (ValueError, TypeError):
                status = 0

            sensitive_tokens = (
                "/.env",
                "/.git",
                "/config",
                "/backup",
                "/admin",
                "/phpmyadmin",
                "../",
                "%2e",
            )

            if (
                any(token in path for token in sensitive_tokens)
                and status in {400, 401, 403, 404}
            ):
                item["suspicious_http"] = True
                item["suspicious_http_events"] += 1

            if method == "POST" and path.rstrip("/") == "/login" and status == 401:
                item["failed_login_attempts"] += 1

        for item in indicators.values():
            if item["failed_login_attempts"] >= 3:
                item["brute_force"] = True

    return indicators


def map_honeypot_to_assets(assets, honeypot_data, server_logs):
    """
    Attribute honeypot source IPs to assets only when the same source IP
    is observed in server_logs with an asset_id.
    """
    source_to_assets = defaultdict(set)

    if not server_logs.empty and {
        "source_ip", "asset_id"
    }.issubset(server_logs.columns):
        for _, row in server_logs.iterrows():
            source_ip = str(row.get("source_ip", ""))
            asset_id = str(row.get("asset_id", ""))
            if source_ip and asset_id:
                source_to_assets[source_ip].add(asset_id)

    asset_events = defaultdict(list)

    for event in honeypot_data.get("events", []):
        source_ip = str(event.get("source_ip", ""))
        for asset_id in source_to_assets.get(source_ip, set()):
            asset_events[asset_id].append(event)

    return asset_events

def load_optional_anomalies():

    if not ANOMALY_FINDINGS_FILE.exists():
        print("No anomaly findings file found. Skipping ML scoring.")
        return {}, False

    try:
        with open(
            ANOMALY_FINDINGS_FILE,
            "r",
            encoding="utf-8-sig"
        ) as file:
            content = file.read().strip()

        if not content:
            print("Anomaly findings file is empty. Skipping ML scoring.")
            return {}, False

        data = json.loads(content)

        if isinstance(data, dict):
            rows = data.get("findings", [])
        elif isinstance(data, list):
            rows = data
        else:
            rows = []

        by_asset = defaultdict(list)

        for row in rows:
            asset_id = row.get("asset_id")

            if asset_id and parse_bool(
                row.get("is_anomaly", row.get("detected", False))
            ):
                by_asset[str(asset_id)].append(row)

        print(f"Loaded anomaly findings for {len(by_asset)} assets.")
        return by_asset, True

    except json.JSONDecodeError:
        print("Invalid anomaly JSON. Skipping ML scoring.")
        return {}, False


def severity_from_score(score):
    if score >= SEVERITY_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if score >= SEVERITY_THRESHOLDS["HIGH"]:
        return "HIGH"
    if score >= SEVERITY_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def recommended_actions(factors):
    actions = []

    if factors["validated_vulnerability_count"] > 0:
        actions.append(
            "Review validated CVEs and upgrade affected software to fixed versions."
        )

    if factors["kev_count"] > 0:
        actions.append(
            "Prioritise remediation of vulnerabilities listed in CISA KEV."
        )

    if factors["suspicious_http"]:
        actions.append(
            "Investigate suspicious HTTP requests and block confirmed malicious sources."
        )

    if factors["brute_force"]:
        actions.append(
            "Review authentication logs and enforce rate limiting or account protection."
        )

    if factors["port_scan"]:
        actions.append(
            "Investigate port scanning activity and review exposed network services."
        )

    if factors["honeypot_interactions"] > 0:
        actions.append(
            "Investigate source IPs observed interacting with the honeypot."
        )

    if factors["ml_anomaly_count"] > 0:
        actions.append(
            "Review ML-flagged events and validate whether the behaviour is malicious."
        )

    if factors["internet_exposed"]:
        actions.append(
            "Confirm that only required services are exposed to the internet."
        )

    if not actions:
        actions.append(
            "Continue monitoring and maintain regular vulnerability assessments."
        )

    return actions


def calculate_asset_risk(
    asset,
    vulnerabilities,
    network_indicators,
    honeypot_events,
    anomaly_events,
    rejected_mismatch_count,
    unresolved_version_count,
):
    """Calculate an explainable 0-100 risk score for one asset."""

    max_cvss = max(
        [float(v.get("cvss_score") or 0) for v in vulnerabilities],
        default=0.0,
    )
    kev_count = sum(1 for v in vulnerabilities if parse_bool(v.get("is_kev")))

    # Vulnerability component: CVSS contributes up to 29.4 points;
    # count contributes up to 5.6 points. Maximum = 35.
    vulnerability_score = min(
        35.0,
        (max_cvss * 3.0) + min(len(vulnerabilities), 8) * 0.7,
    )

    kev_score = 15.0 if kev_count else 0.0
    exposure_score = 10.0 if parse_bool(asset.get("internet_exposed")) else 0.0
    environment_score = (
        5.0 if normalise(asset.get("environment")) == "production" else 0.0
    )

    network = network_indicators
    suspicious_http_score = 12.0 if network["suspicious_http"] else 0.0
    brute_force_score = 8.0 if network["brute_force"] else 0.0
    port_scan_score = 8.0 if network["port_scan"] else 0.0
    honeypot_score = 8.0 if honeypot_events else 0.0
    anomaly_score = 10.0 if anomaly_events else 0.0

    raw_score = sum([
        vulnerability_score,
        kev_score,
        exposure_score,
        environment_score,
        suspicious_http_score,
        brute_force_score,
        port_scan_score,
        honeypot_score,
        anomaly_score,
    ])

    risk_score = round(min(100.0, raw_score), 1)

    factors = {
        "validated_vulnerability_count": len(vulnerabilities),
        "max_cvss_score": max_cvss,
        "kev_count": kev_count,
        "internet_exposed": parse_bool(asset.get("internet_exposed")),
        "environment": asset.get("environment"),
        "suspicious_http": bool(network["suspicious_http"]),
        "suspicious_http_events": network["suspicious_http_events"],
        "brute_force": bool(network["brute_force"]),
        "failed_login_attempts": network["failed_login_attempts"],
        "port_scan": bool(network["port_scan"]),
        "honeypot_interactions": len(honeypot_events),
        "ml_anomaly_count": len(anomaly_events),
        "rejected_product_mismatch_findings": rejected_mismatch_count,
        "unresolved_version_findings": unresolved_version_count,
    }

    score_breakdown = {
        "vulnerabilities": round(vulnerability_score, 1),
        "cisa_kev": round(kev_score, 1),
        "internet_exposure": round(exposure_score, 1),
        "production_environment": round(environment_score, 1),
        "suspicious_http": round(suspicious_http_score, 1),
        "brute_force": round(brute_force_score, 1),
        "port_scan": round(port_scan_score, 1),
        "honeypot": round(honeypot_score, 1),
        "ml_anomaly": round(anomaly_score, 1),
    }

    cve_summaries = [
        {
            "cve_id": v.get("cve_id"),
            "severity": v.get("severity"),
            "cvss_score": v.get("cvss_score"),
            "is_kev": parse_bool(v.get("is_kev")),
            "description": (v.get("description") or {}).get("short"),
        }
        for v in vulnerabilities
    ]

    return {
        "asset_id": asset.get("asset_id"),
        "hostname": asset.get("hostname"),
        "ip_address": asset.get("ip_address"),
        "software": asset.get("software"),
        "installed_version": asset.get("version"),
        "environment": asset.get("environment"),
        "internet_exposed": parse_bool(asset.get("internet_exposed")),
        "risk_score": risk_score,
        "risk_level": severity_from_score(risk_score),
        "score_breakdown": score_breakdown,
        "risk_factors": factors,
        "vulnerabilities": cve_summaries,
        "network_evidence": {
            "server_log_events": network["server_log_events"],
            "failed_login_attempts": network["failed_login_attempts"],
            "suspicious_http_events": network["suspicious_http_events"],
        },
        "honeypot_events": honeypot_events,
        "ml_anomalies": anomaly_events,
        "recommended_actions": recommended_actions(factors),
    }


def run_risk_assessment():
    print("\n========== DECEPTIQ RISK ASSESSMENT ==========\n")

    assets_df = load_csv(ASSETS_FILE)
    if assets_df.empty:
        raise ValueError("assets.csv contains no assets.")

    assets = assets_df.fillna("").to_dict("records")

    vulnerability_db = load_json(VULNERABILITIES_FILE)
    vulnerability_findings = load_json(VULNERABILITY_FINDINGS_FILE)

    correlated_events = load_json(
        CORRELATED_EVENTS_FILE,
        required=False,
        default=[],
    )

    honeypot_data = load_json(
        HONEYPOT_FILE,
        required=False,
        default={"events": []},
    )

    server_logs = load_csv(SERVER_LOGS_FILE, required=False)

    # network_logs.csv is loaded for visibility, but the supplied schema
    # has no asset_id. Do not assign those events to an asset unless their
    # source IP can be mapped through server_logs.
    network_logs = load_csv(NETWORK_LOGS_FILE, required=False)

    anomaly_by_asset, anomaly_file_available = load_optional_anomalies()

    network_by_asset = build_network_indicators(
        assets,
        correlated_events,
        server_logs,
    )

    honeypot_by_asset = map_honeypot_to_assets(
        assets,
        honeypot_data,
        server_logs,
    )

    asset_results = []

    for asset in assets:
        asset_id = str(asset["asset_id"])

        (
            validated_vulnerabilities,
            rejected_mismatches,
            unresolved_versions,
        ) = get_validated_vulnerabilities(
            asset,
            vulnerability_findings,
            vulnerability_db,
        )

        result = calculate_asset_risk(
            asset=asset,
            vulnerabilities=validated_vulnerabilities,
            network_indicators=network_by_asset.get(
                asset_id,
                {
                    "suspicious_http": False,
                    "brute_force": False,
                    "port_scan": False,
                    "server_log_events": 0,
                    "failed_login_attempts": 0,
                    "suspicious_http_events": 0,
                },
            ),
            honeypot_events=honeypot_by_asset.get(asset_id, []),
            anomaly_events=anomaly_by_asset.get(asset_id, []),
            rejected_mismatch_count=rejected_mismatches,
            unresolved_version_count=unresolved_versions,
        )

        asset_results.append(result)

    # Highest-risk assets first
    asset_results.sort(
        key=lambda item: item["risk_score"],
        reverse=True,
    )

    risk_counts = {
        level: sum(1 for item in asset_results if item["risk_level"] == level)
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    }

    report = {
        "module": "DeceptIQ Risk Assessment",
        "generated_at": pd.Timestamp.now(tz="UTC").isoformat(),
        "scoring_model": "DeceptIQ Contextual Risk Score v1",
        "anomaly_data_available": anomaly_file_available,
        "input_files": {
            "assets": str(ASSETS_FILE),
            "vulnerability_findings": str(VULNERABILITY_FINDINGS_FILE),
            "vulnerability_database": str(VULNERABILITIES_FILE),
            "correlated_events": str(CORRELATED_EVENTS_FILE),
            "server_logs": str(SERVER_LOGS_FILE),
            "honeypot_events": str(HONEYPOT_FILE),
            "network_logs": str(NETWORK_LOGS_FILE),
            "anomaly_findings": (
                str(ANOMALY_FINDINGS_FILE)
                if anomaly_file_available
                else None
            ),
        },
        "summary": {
            "total_assets_assessed": len(asset_results),
            "critical_assets": risk_counts["CRITICAL"],
            "high_risk_assets": risk_counts["HIGH"],
            "medium_risk_assets": risk_counts["MEDIUM"],
            "low_risk_assets": risk_counts["LOW"],
            "total_validated_vulnerabilities": sum(
                item["risk_factors"]["validated_vulnerability_count"]
                for item in asset_results
            ),
            "assets_with_suspicious_http": sum(
                1 for item in asset_results
                if item["risk_factors"]["suspicious_http"]
            ),
            "assets_with_brute_force": sum(
                1 for item in asset_results
                if item["risk_factors"]["brute_force"]
            ),
            "assets_with_honeypot_evidence": sum(
                1 for item in asset_results
                if item["risk_factors"]["honeypot_interactions"] > 0
            ),
            "ml_anomalies_included": sum(
                item["risk_factors"]["ml_anomaly_count"]
                for item in asset_results
            ),
        },
        "risk_thresholds": SEVERITY_THRESHOLDS,
        "assets": asset_results,
        "data_quality_notes": [
            (
                "Anomaly findings file was not present. ML anomaly points "
                "were excluded from all asset scores."
                if not anomaly_file_available
                else "Anomaly findings were included where asset_id was available."
            ),
            (
                "Network aggregate events are not assigned to assets unless "
                "their source IP can be mapped to an asset through server_logs."
            ),
            (
                "Vulnerability findings were validated against each asset's "
                "software and installed version using vulnerabilities.json. "
                "Product mismatches and unresolved version ranges were excluded."
            ),
        ],
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    print("Risk assessment completed.")
    print(f"Assets assessed: {len(asset_results)}")
    print(f"Critical: {risk_counts['CRITICAL']}")
    print(f"High:     {risk_counts['HIGH']}")
    print(f"Medium:   {risk_counts['MEDIUM']}")
    print(f"Low:      {risk_counts['LOW']}")
    print(f"Anomaly findings available: {anomaly_file_available}")
    print(f"Report saved to: {OUTPUT_FILE}")

    print("\nAsset risk ranking:")
    for item in asset_results:
        print(
            f"{item['asset_id']} | {item['hostname']} | "
            f"{item['risk_score']}/100 | {item['risk_level']}"
        )

    print("\n==============================================\n")


if __name__ == "__main__":
    run_risk_assessment()
