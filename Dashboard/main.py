import json

from pathlib import Path

import pandas as pd

import plotly.express as px

import streamlit as st



# ---------------------------------------------------------
# 1. PAGE CONFIG & DARK SOC THEME STYLING
# ---------------------------------------------------------
st.set_page_config(

    page_title="DeceptIQ | Autonomous SOC Dashboard",

    page_icon="🛡️",

    layout="wide",

    initial_sidebar_state="expanded",

)



st.markdown(

    """

    <style>

    /* Deep Dark SOC Background */

    .stApp {

        background-color: #0b0e14;

        color: #e2e8f0;

    }

    section[data-testid="stSidebar"] {

        background-color: #0f131a;

        border-right: 1px solid #1e293b;

    }

    /* Metric Cards Styling */

    div[data-testid="stMetric"] {

        background-color: #121721;

        border: 1px solid #1e293b;

        border-radius: 10px;

        padding: 16px 20px;

        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);

    }

    div[data-testid="stMetricLabel"] {

        color: #94a3b8 !important;

        font-size: 0.85rem !important;

        font-weight: 600;

    }

    div[data-testid="stMetricValue"] {

        color: #f8fafc !important;

        font-size: 1.85rem !important;

    }

    /* Custom Section Headers */

    .soc-header {

        font-size: 1.1rem;

        font-weight: 600;

        color: #f1f5f9;

        margin-top: 10px;

        margin-bottom: 12px;

        padding-bottom: 6px;

        border-bottom: 1px solid #1e293b;

    }

    </style>

    """,

    unsafe_allow_html=True,

)



# ---------------------------------------------------------
# 2. DATA LOADING (RELATIVE PATH TO engine/security_report.json)
# ---------------------------------------------------------
# Resolves DeceptIQ/Dashboard/main.py -> DeceptIQ/engine/security_report.json
BASE_DIR = Path(__file__).resolve().parent.parent

REPORT_PATH = BASE_DIR / "engine" / "security_report.json"





def load_security_report(file_path: Path) -> dict:

    if not file_path.exists():

        st.error(f"Report file not found at: `{file_path}`")

        st.stop()

    try:

        with open(file_path, "r", encoding="utf-8") as f:

            return json.load(f)

    except json.JSONDecodeError as e:

        st.error(f"Invalid JSON format in `security_report.json`: {e}")

        st.stop()





data = load_security_report(REPORT_PATH)



metadata = data.get("metadata", {})

summary = data.get("summary", {})

assets = data.get("assets", [])

alerts = data.get("alerts", [])

honeypot = data.get("honeypot", {})

routing = data.get("routing", [])

anomalies = data.get("anomalies", [])



# ---------------------------------------------------------
# 3. SIDEBAR NAVIGATION & REPORT METADATA
# ---------------------------------------------------------
with st.sidebar:

    st.title("🛡️ DeceptIQ")

    st.caption("Autonomous Cyber Deception & SOC")

    st.divider()



    page = st.radio(

        "Navigation",

        ["Overview", "Assets & Risk", "Alerts & Triage", "Honeypot & Routing"],

        index=0,

    )



    st.divider()

    st.markdown("**Telemetry Source**")

    st.code(f"Project: {metadata.get('project', 'N/A')}\n"

            f"Env:     {metadata.get('environment', 'N/A')}\n"

            f"Version: {metadata.get('report_version', 'N/A')}\n"

            f"Updated: {metadata.get('generated_at', 'N/A')}", language="text")



    if st.button("🔄 Refresh Report Data", use_container_width=True):

        st.rerun()



# ---------------------------------------------------------
# 4. TOP HEADER & KPI METRIC CARDS
# ---------------------------------------------------------
col_title, col_badge = st.columns([4, 1])

with col_title:

    st.title(f"{metadata.get('project', 'DeceptIQ')} — Security Operations Overview")

with col_badge:

    hp_status = honeypot.get("status", "UNKNOWN")

    st.markdown(

        f"<div style='text-align:right; padding-top:18px;'>"

        f"<span style='background:#064e3b; color:#34d399; padding:6px 14px; "

        f"border-radius:20px; font-weight:700; font-size:0.85rem; border:1px solid #10b981;'>"

        f"● HONEYPOT {hp_status}</span></div>",

        unsafe_allow_html=True,

    )



# 6-Column KPI Row matching SOC layout
k1, k2, k3, k4, k5, k6 = st.columns(6)

k1.metric("Total Alerts", summary.get("total_alerts", 0))

k2.metric("Critical Alerts", summary.get("critical_alerts", 0))

k3.metric("High Alerts", summary.get("high_alerts", 0))

k4.metric("Assets at Risk", f"{summary.get('suspicious_assets', 0)} / {summary.get('total_assets', 0)}")

k5.metric("Honeypot Hits", summary.get("honeypot_interactions", 0))

k6.metric("ML Anomalies", summary.get("anomalies_detected", 0))



st.markdown("<br>", unsafe_allow_html=True)





def build_readable_report_table(report):
    """Build one compact table using shared columns across report sections."""
    columns = [
        "Section",
        "Record",
        "Timestamp",
        "Asset / Host",
        "IP Address",
        "Event / Finding",
        "Severity / Risk",
        "Score",
        "Status",
        "Details / Recommended Action",
    ]
    rows = []

    def add_row(section, record="", timestamp="", asset_host="", ip="",
                event="", severity="", score=None, status="", details=""):
        rows.append({
            "Section": section,
            "Record": record,
            "Timestamp": timestamp,
            "Asset / Host": asset_host,
            "IP Address": ip,
            "Event / Finding": event,
            "Severity / Risk": severity,
            "Score": score,
            "Status": status,
            "Details / Recommended Action": details,
        })

    # Metadata and summary rows intentionally omitted from this table.

    # Assets: shared fields are promoted into columns; remaining findings
    # and CVE information are kept together in the final Details column.
    for index, asset in enumerate(report.get("assets", []), start=1):
        findings = asset.get("findings", {}) or {}
        finding_text = ", ".join(
            f"{name.replace('_', ' ').title()}: {'Yes' if value else 'No'}"
            for name, value in findings.items()
        ) or "No finding details"
        cves = asset.get("cves", []) or []
        if cves:
            finding_text += " | CVEs: " + ", ".join(map(str, cves))
        finding_text += " | Internet exposed: " + (
            "Yes" if asset.get("internet_exposed") else "No"
        )
        add_row(
            "Asset",
            record=asset.get("asset_id", f"Asset {index}"),
            asset_host=asset.get("hostname", ""),
            ip=asset.get("ip_address", ""),
            event="Asset posture",
            severity=asset.get("risk_level", ""),
            score=asset.get("risk_score", ""),
            status=asset.get("remediation_status", ""),
            details=finding_text
        )

    # Alerts
    for index, alert in enumerate(report.get("alerts", []), start=1):
        description = alert.get("description", "")
        action = alert.get("recommended_action", "")
        details = description
        if action:
            details += (" | " if details else "") + "Recommended: " + action
        add_row(
            "Alert",
            record=alert.get("alert_id", f"Alert {index}"),
            timestamp=alert.get("timestamp", ""),
            asset_host=alert.get("asset_id", ""),
            ip=alert.get("source_ip", ""),
            event=alert.get("alert_type", ""),
            severity=alert.get("severity", ""),
            score=alert.get("risk_score", ""),
            status=alert.get("status", ""),
            details=details
        )

    # Honeypot overview and captured events
    honeypot = report.get("honeypot", {}) or {}
    if honeypot:
        hp_details = (
            f"Total interactions: {honeypot.get('total_interactions', 0)}"
            f" | Unique source IPs: {honeypot.get('unique_source_ips', 0)}"
        )
        add_row(
            "Honeypot",
            record="Overview",
            event="Honeypot activity",
            status=honeypot.get("status", ""),
            details=hp_details
        )
        for index, event in enumerate(honeypot.get("events", []), start=1):
            add_row(
                "Honeypot event",
                record=event.get("event_id", f"Event {index}"),
                timestamp=event.get("timestamp", ""),
                ip=event.get("source_ip", ""),
                event=f"{event.get('method', '')} {event.get('path', '')}".strip(),
                details=f"Captured honeypot interaction"
            )

    # Deception routing rules
    for index, rule in enumerate(report.get("routing", []), start=1):
        add_row(
            "Routing",
            record=f"Rule {index}",
            ip=rule.get("source_ip", ""),
            event=rule.get("action", ""),
            status=rule.get("status", ""),
            details=rule.get("reason", "")
        )

    # ML anomaly records
    for index, anomaly in enumerate(report.get("anomalies", []), start=1):
        score = anomaly.get("anomaly_score")
        add_row(
            "ML anomaly",
            record=anomaly.get("asset_id", f"Anomaly {index}"),
            event="Anomaly detected" if anomaly.get("detected") else "No anomaly detected",
            severity="ANOMALY" if anomaly.get("detected") else "NORMAL",
            score=score if score is not None else None,
            details=anomaly.get("description", "")
        )

    # Preserve any extra top-level JSON sections without expanding the table.
    known_sections = {
        "metadata", "summary", "assets", "alerts",
        "honeypot", "routing", "anomalies"
    }
    for section, value in report.items():
        if section not in known_sections:
            add_row(
                section.replace("_", " ").title(),
                record="Additional data",
                event="Additional report section",
                details=json.dumps(value, ensure_ascii=False)
            )

    return pd.DataFrame(rows, columns=columns)


# ---------------------------------------------------------
# 5. MAIN DASHBOARD VIEWS
# ---------------------------------------------------------
if page == "Overview":

    # ROW 1: Severity Donut Chart + Active Deception Routing Engine
    left_col, right_col = st.columns([1.1, 1.9])



    with left_col:

        st.markdown('<div class="soc-header">Alerts by Severity</div>', unsafe_allow_html=True)

        sev_df = pd.DataFrame({

            "Severity": ["Critical", "High", "Medium", "Low"],

            "Count": [

                summary.get("critical_alerts", 0),

                summary.get("high_alerts", 0),

                summary.get("medium_alerts", 0),

                summary.get("low_alerts", 0),

            ],

        })



        fig_donut = px.pie(

            sev_df,

            names="Severity",

            values="Count",

            hole=0.62,

            color="Severity",

            color_discrete_map={

                "Critical": "#ef4444",

                "High": "#f97316",

                "Medium": "#eab308",

                "Low": "#3b82f6",

            },

        )

        fig_donut.update_traces(textinfo="value+label", textfont_size=12)

        fig_donut.update_layout(

            paper_bgcolor="#121721",

            plot_bgcolor="#121721",

            font_color="#e2e8f0",

            margin=dict(t=20, b=20, l=10, r=10),

            height=290,

            showlegend=True,

            legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.02),

            annotations=[

                dict(

                    text=f"<b>{summary.get('total_alerts', 0)}</b><br>Total",

                    x=0.5, y=0.5, font_size=16, showarrow=False, font_color="#f8fafc"

                )

            ],

        )

        st.plotly_chart(fig_donut, use_container_width=True)



    with right_col:

        st.markdown('<div class="soc-header">Active Deception Routing & Honeypot Trap</div>', unsafe_allow_html=True)

        if routing:

            df_routing = pd.DataFrame(routing)

            st.dataframe(df_routing, use_container_width=True, hide_index=True)



            # Interactive Action Simulator for Hackathon Demo
            for idx, rule in enumerate(routing):

                if rule.get("status") == "PENDING":

                    st.warning(

                        f"⚠️ **Action Required:** Source IP `{rule['source_ip']}` flagged for "

                        f"*{rule['reason']}*. Recommended target: **{rule['action']}**."

                    )

                    if st.button(f"⚡ Approve & Deploy Deception Rule for {rule['source_ip']}", key=f"route_{idx}"):

                        data["routing"][idx]["status"] = "ACTIVE_REDIRECT"

                        with open(REPORT_PATH, "w", encoding="utf-8") as f:

                            json.dump(data, f, indent=2)

                        st.success(f"Traffic from {rule['source_ip']} is now actively diverted to Honeypot!")

                        st.rerun()

        else:

            st.info("No active routing rules in queue.")



        st.markdown('<div class="soc-header">Recent Honeypot Events</div>', unsafe_allow_html=True)

        hp_events = honeypot.get("events", [])

        if hp_events:

            st.dataframe(pd.DataFrame(hp_events), use_container_width=True, hide_index=True)



    # ROW 2: Assets at Risk & Security Alerts Feed
    col_assets, col_alerts = st.columns([1.2, 1.8])



    with col_assets:

        st.markdown('<div class="soc-header">Monitored Assets & Risk Posture</div>', unsafe_allow_html=True)

        if assets:

            asset_rows = []

            for a in assets:

                active_flags = [k.upper() for k, v in a.get("findings", {}).items() if v]

                asset_rows.append({

                    "ID": a.get("asset_id"),

                    "Host": a.get("hostname"),

                    "IP": a.get("ip_address"),

                    "Risk Score": a.get("risk_score"),

                    "Level": a.get("risk_level"),

                    "Exposed": "🌐 Yes" if a.get("internet_exposed") else "🔒 Internal",

                    "Detections": ", ".join(active_flags) if active_flags else "Clean",

                    "Status": a.get("remediation_status"),

                })

            df_assets = pd.DataFrame(asset_rows)

            st.dataframe(

                df_assets,

                use_container_width=True,

                hide_index=True,

                column_config={

                    "Risk Score": st.column_config.ProgressColumn(

                        "Risk Score", min_value=0, max_value=100, format="%d/100"

                    )

                },

            )



    with col_alerts:

        st.markdown('<div class="soc-header">Security Alerts & Recommended Actions</div>', unsafe_allow_html=True)

        if alerts:

            df_alerts = pd.DataFrame(alerts)

            st.dataframe(df_alerts, use_container_width=True, hide_index=True)



    # ROW 3: ML Anomaly Detection Status
    st.markdown('<div class="soc-header">ML Behavioral Anomaly Telemetry</div>', unsafe_allow_html=True)

    if anomalies:

        st.dataframe(pd.DataFrame(anomalies), use_container_width=True, hide_index=True)




    # Full Security Report
    st.markdown(
        '<div class="soc-header">Full Security Report</div>',
        unsafe_allow_html=True
    )

    df_full_report = build_readable_report_table(data)

    if not df_full_report.empty:
        report_column_config = {
            "Section": st.column_config.TextColumn("Section", width="small"),
            "Record": st.column_config.TextColumn("Record", width="small"),
            "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
            "Asset / Host": st.column_config.TextColumn("Asset / Host", width="small"),
            "IP Address": st.column_config.TextColumn("IP Address", width="small"),
            "Event / Finding": st.column_config.TextColumn("Event / Finding", width="medium"),
            "Severity / Risk": st.column_config.TextColumn("Severity / Risk", width="small"),
            "Score": st.column_config.NumberColumn("Score", width="small"),
            "Status": st.column_config.TextColumn("Status", width="small"),
            "Details / Recommended Action": st.column_config.TextColumn(
                "Details / Recommended Action", width="large"
            ),
        }

        st.dataframe(
            df_full_report,
            use_container_width=True,
            hide_index=True,
            height=600,
            row_height=65,
            column_config=report_column_config
        )
    else:
        st.info("The security report is empty.")


elif page == "Assets & Risk":

    st.markdown('<div class="soc-header">Detailed Asset Inventory & Findings</div>', unsafe_allow_html=True)

    for asset in assets:

        with st.expander(f"{asset['asset_id']} — {asset['hostname']} ({asset['ip_address']}) | Risk: {asset['risk_level']} ({asset['risk_score']}/100)", expanded=True):

            c1, c2, c3 = st.columns(3)

            c1.write(f"**Internet Exposed:** {asset['internet_exposed']}")

            c2.write(f"**Remediation Status:** {asset['remediation_status']}")

            c3.write(f"**CVEs Linked:** {len(asset.get('cves', []))}")

            st.json(asset.get("findings", {}))



elif page == "Alerts & Triage":

    st.markdown('<div class="soc-header">Alert Triage Queue</div>', unsafe_allow_html=True)

    sev_filter = st.multiselect(

        "Filter by Severity",

        options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],

        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],

    )

    filtered_alerts = [a for a in alerts if a.get("severity") in sev_filter]

    st.dataframe(pd.DataFrame(filtered_alerts), use_container_width=True, hide_index=True)



elif page == "Honeypot & Routing":

    st.markdown('<div class="soc-header">Deception Infrastructure Telemetry</div>', unsafe_allow_html=True)

    h1, h2, h3 = st.columns(3)

    h1.metric("Honeypot Status", honeypot.get("status", "OFFLINE"))

    h2.metric("Total Interactions", honeypot.get("total_interactions", 0))

    h3.metric("Unique Attacker IPs", honeypot.get("unique_source_ips", 0))



    st.subheader("Captured Honeypot Events")

    st.dataframe(pd.DataFrame(honeypot.get("events", [])), use_container_width=True, hide_index=True)



    st.subheader("Dynamic Routing Rules")

    st.dataframe(pd.DataFrame(routing), use_container_width=True, hide_index=True)
