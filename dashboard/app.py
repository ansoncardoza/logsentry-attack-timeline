import streamlit as st
import pandas as pd

from pathlib import Path
from src.analysis_pipeline import run_analysis
from src.reporting.json_reporter import generate_json_report
from src.reporting.pdf_reporter import generate_pdf_report


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="LogSentry | Security Investigation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------
# CUSTOM STYLING
# --------------------------------------------------

st.markdown(
    """
    <style>
    .main {
        background-color: #0e1117;
    }

    [data-testid="stMetric"] {
        background-color: #1b2430;
        border: 1px solid #293849;
        padding: 16px;
        border-radius: 10px;
    }

    .section-heading {
        color: #60a5fa;
        font-size: 22px;
        font-weight: 600;
        margin-top: 20px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# --------------------------------------------------
# LOAD ANALYSIS
# --------------------------------------------------

scenario = st.selectbox(
    "Select Analysis Scenario",
    [
        "Default Sample",
        "Correlated Attack",
    ],
)

@st.cache_data(ttl=30)
def load_analysis(selected_scenario):

    if selected_scenario == "Correlated Attack":

        scenario_path = Path("data/scenarios/correlated_attack")

        return run_analysis(
            auth_log_path=scenario_path / "auth.log",
            apache_log_path=scenario_path / "apache_access.log",
            firewall_log_path=scenario_path / "firewall.log",
            year=2026,
        )

    return run_analysis()


try:
    results = load_analysis(scenario)
except Exception as error:
    st.error(f"Analysis could not be completed: {error}")
    st.stop()

summary = results["summary"]
alerts = results["alerts"]
incidents = results["incidents"]
incident_results = results["incident_results"]


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

st.sidebar.title("🛡️ LogSentry")

st.sidebar.caption("Security Log Investigation Platform")

page = st.sidebar.radio(
    "Navigation",
    [
        "Overview",
        "Security Alerts",
        "Incident Investigation",
        "Attack Timeline",
        "MITRE ATT&CK",
        "Parsed Logs",
    ],
)

st.sidebar.divider()

if st.sidebar.button("Refresh Analysis"):
    load_analysis.clear()
    st.rerun()


# --------------------------------------------------
# REPORT DOWNLOADS
# --------------------------------------------------

st.sidebar.divider()
st.sidebar.subheader("Export Reports")

try:
    # Generate reports using the existing analysis results.
    json_report_path = generate_json_report(results)
    pdf_report_path = generate_pdf_report(results)

    # JSON download button.
    st.sidebar.download_button(
        label="Download JSON Report",
        data=json_report_path.read_bytes(),
        file_name="logsentry_report.json",
        mime="application/json",
        use_container_width=True,
    )

    # PDF download button.
    st.sidebar.download_button(
        label="Download PDF Report",
        data=pdf_report_path.read_bytes(),
        file_name="logsentry_report.pdf",
        mime="application/pdf",
        use_container_width=True,
    )

except Exception as error:
    st.sidebar.error(f"Report generation failed: {error}")


st.sidebar.caption("Rule-based security analysis")
st.sidebar.caption("Synthetic / Authorized Logs Only")


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ LogSentry Security Dashboard")

st.caption(
    "Log Analysis & Attack Timeline Reconstruction Platform"
)

st.divider()


# --------------------------------------------------
# OVERVIEW PAGE
# --------------------------------------------------

if page == "Overview":

    st.subheader("System Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Log Events",
        summary["total_events"],
    )

    col2.metric(
        "Security Alerts",
        summary["total_alerts"],
    )

    col3.metric(
        "Correlated Incidents",
        summary["total_incidents"],
    )

    medium_alerts = sum(
        1 for alert in alerts
        if alert.get("severity") == "Medium"
    )

    col4.metric(
        "Medium Severity Alerts",
        medium_alerts,
    )

    st.divider()

    st.subheader("Log Source Summary")

    source_col1, source_col2, source_col3 = st.columns(3)

    source_col1.metric(
        "Authentication Events",
        summary["authentication_events"],
    )

    source_col2.metric(
        "Apache Events",
        summary["apache_events"],
    )

    source_col3.metric(
        "Firewall Events",
        summary["firewall_events"],
    )

    st.divider()

    st.subheader("Detection Summary")

    detection_data = pd.DataFrame(
        {
            "Detection Type": [
                "SSH Brute Force",
                "Possible Port Scan",
                "Web Path Reconnaissance",
            ],
            "Alerts": [
                summary["brute_force_alerts"],
                summary["port_scan_alerts"],
                summary["web_path_alerts"],
            ],
        }
    )

    st.bar_chart(
        detection_data.set_index("Detection Type")
    )

    st.subheader("Recent Security Alerts")

    if alerts:
        alert_table = pd.DataFrame(alerts)

        display_columns = [
            "alert_type",
            "severity",
            "source_ip",
        ]

        st.dataframe(
            alert_table[display_columns],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("No security alerts detected.")


# --------------------------------------------------
# SECURITY ALERTS PAGE
# --------------------------------------------------

elif page == "Security Alerts":

    st.subheader("Security Alerts")

    if alerts:

        alert_table = pd.DataFrame(alerts)

        st.dataframe(
            alert_table,
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Alert Investigation")

        for index, alert in enumerate(alerts, start=1):

            with st.expander(
                f"{index}. {alert['alert_type']} – "
                f"{alert.get('source_ip', 'Unknown')}"
            ):

                st.write(
                    "**Severity:**",
                    alert.get("severity", "Unknown"),
                )

                st.write(
                    "**Description:**",
                    alert.get("description", "Not available"),
                )

                st.write(
                    "**First Seen:**",
                    alert.get("first_seen", "Unknown"),
                )

                st.write(
                    "**Last Seen:**",
                    alert.get("last_seen", "Unknown"),
                )

                st.json(alert)

    else:
        st.success("No security alerts detected.")


# --------------------------------------------------
# INCIDENT INVESTIGATION PAGE
# --------------------------------------------------

elif page == "Incident Investigation":

    st.subheader("Correlated Security Incidents")

    if incidents:

        for result in incident_results:

            incident = result["incident"]

            with st.expander(
                f"{incident['incident_id']} – "
                f"{incident['source_ip']}",
                expanded=True,
            ):

                st.write(
                    "**Alert Count:**",
                    incident["alert_count"],
                )

                st.write(
                    "**Alert Types:**",
                    ", ".join(incident["alert_types"]),
                )

                st.write(
                    "**First Seen:**",
                    incident["first_seen"],
                )

                st.write(
                    "**Last Seen:**",
                    incident["last_seen"],
                )

                st.write(incident["description"])

    else:

        st.info(
            "No correlated incidents identified in the current "
            "log dataset. The detected alerts originate from "
            "different source IP addresses."
        )


# --------------------------------------------------
# ATTACK TIMELINE PAGE
# --------------------------------------------------

elif page == "Attack Timeline":

    st.subheader("Chronological Attack Timeline")

    if incident_results:

        for result in incident_results:

            incident = result["incident"]

            st.markdown(
                f"### {incident['incident_id']} – "
                f"{incident['source_ip']}"
            )

            timeline_data = pd.DataFrame(
                result["timeline"]
            )

            st.dataframe(
                timeline_data[
                    [
                        "timestamp",
                        "event_type",
                        "severity",
                        "description",
                    ]
                ],
                use_container_width=True,
                hide_index=True,
            )

    else:

        st.info(
            "No incident timelines are available because "
            "the current dataset contains no correlated incidents."
        )



# --------------------------------------------------
# MITRE ATT&CK PAGE
# --------------------------------------------------

elif page == "MITRE ATT&CK":

    from src.mitre.attack_mapper import map_alert_to_attack

    st.subheader("MITRE ATT&CK Technique Mapping")

    st.write(
        "Security detections are mapped individually to relevant "
        "MITRE ATT&CK techniques. Correlated incidents are not "
        "required for individual alert mapping."
    )

    mappings = []

    for alert in alerts:

        mapping = map_alert_to_attack(alert)

        if mapping is not None:
            mappings.append(mapping)

    if mappings:

        st.subheader("Detection Technique Summary")

        mapping_table = pd.DataFrame(mappings)

        st.dataframe(
            mapping_table[
                [
                    "alert_type",
                    "technique",
                    "technique_id",
                    "tactic",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

        st.divider()

        st.subheader("Technique Investigation")

        for mapping in mappings:

            with st.expander(
                f"{mapping['technique_id']} – "
                f"{mapping['technique']}"
            ):

                st.write(
                    "**Detection:**",
                    mapping["alert_type"],
                )

                st.write(
                    "**Tactic:**",
                    mapping["tactic"],
                )

                st.write(
                    "**Rationale:**",
                    mapping["rationale"],
                )

                st.markdown(
                    f"[Official MITRE Reference]({mapping['url']})"
                )

        st.caption(
            "MITRE ATT&CK mappings provide contextual classification "
            "of observed activity. They do not prove attacker identity, "
            "intent, or successful compromise."
        )

    else:

        st.info(
            "No recognized security detections are available "
            "for MITRE ATT&CK mapping."
        )

# --------------------------------------------------
# PARSED LOGS PAGE
# --------------------------------------------------

elif page == "Parsed Logs":

    st.subheader("Parsed Security Events")

    authentication_tab, apache_tab, firewall_tab = st.tabs(
        [
            "Authentication Logs",
            "Apache Access Logs",
            "Firewall Logs",
        ]
    )

    with authentication_tab:

        st.write("Structured SSH authentication events")

        st.dataframe(
            pd.DataFrame(
                results["parsed_events"]["authentication"]
            ),
            use_container_width=True,
            hide_index=True,
        )

    with apache_tab:

        st.write("Structured Apache access events")

        st.dataframe(
            pd.DataFrame(
                results["parsed_events"]["apache"]
            ),
            use_container_width=True,
            hide_index=True,
        )

    with firewall_tab:

        st.write("Structured firewall events")

        st.dataframe(
            pd.DataFrame(
                results["parsed_events"]["firewall"]
            ),
            use_container_width=True,
            hide_index=True,
        )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "LogSentry | Defensive Security Investigation | "
    "Alerts indicate suspicious activity and do not independently "
    "prove system compromise."
)