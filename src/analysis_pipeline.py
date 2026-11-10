
from pathlib import Path

from src.parsers.apache_parser import parse_apache_log
from src.parsers.auth_parser import parse_auth_log
from src.parsers.firewall_parser import parse_firewall_log

from src.detection.brute_force_detector import detect_brute_force
from src.detection.port_scan_detector import detect_port_scan
from src.detection.web_path_detector import detect_suspicious_web_paths

from src.correlation.event_correlator import correlate_alerts
from src.timeline.timeline_builder import build_timeline
from src.mitre.attack_mapper import map_incident_to_attack


# Project root directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def parse_log_file(file_path, parser, parser_name, **parser_kwargs):
    """
    Read a log file and parse each non-empty line.

    Raises a descriptive error if a log entry cannot be parsed.
    """
    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    parsed_events = []

    with file_path.open("r", encoding="utf-8-sig") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if not line.strip():
                continue

            try:
                event = parser(line.rstrip("\r\n"), **parser_kwargs)
                parsed_events.append(event)
            except Exception as error:
                raise ValueError(
                    f"{parser_name} parsing failed in "
                    f"{file_path}, line {line_number}: {error}"
                ) from error

    return parsed_events


def run_analysis(
    auth_log_path=None,
    apache_log_path=None,
    firewall_log_path=None,
    year=2026,
    brute_force_threshold=5,
    port_scan_threshold=5,
    web_path_threshold=3,
    correlation_window_seconds=300,
):
    """
    Run the complete LogSentry investigation pipeline.

    Returns parsed events, security alerts, correlated incidents,
    incident timelines, and MITRE ATT&CK mappings.
    """

    # Step 1: Resolve input log file paths.
    auth_log_path = auth_log_path or PROJECT_ROOT / "data" / "raw" / "auth.log"
    apache_log_path = apache_log_path or PROJECT_ROOT / "data" / "raw" / "apache_access.log"
    firewall_log_path = firewall_log_path or PROJECT_ROOT / "data" / "raw" / "firewall.log"

    # Step 2: Parse all three log sources.
    auth_events = parse_log_file(
        auth_log_path,
        parse_auth_log,
        "Authentication log",
        year=year,
    )

    apache_events = parse_log_file(
        apache_log_path,
        parse_apache_log,
        "Apache access log",
    )

    firewall_events = parse_log_file(
        firewall_log_path,
        parse_firewall_log,
        "Firewall log",
        year=year,
    )

    # Step 3: Run the security detection engines.
    brute_force_alerts = detect_brute_force(
        auth_events,
        threshold=brute_force_threshold,
    )

    port_scan_alerts = detect_port_scan(
        firewall_events,
        threshold=port_scan_threshold,
    )

    web_path_alerts = detect_suspicious_web_paths(
        apache_events,
        threshold=web_path_threshold,
    )

    # Step 4: Combine alerts from all detection engines.
    all_alerts = (
        brute_force_alerts
        + port_scan_alerts
        + web_path_alerts
    )

    # Step 5: Correlate alerts into incidents.
    incidents = correlate_alerts(
        all_alerts,
        window_seconds=correlation_window_seconds,
    )

    # Step 6: Reconstruct timelines and map ATT&CK techniques.
    incident_results = []

    for incident in incidents:
        timeline = build_timeline(incident)

        attack_mappings = map_incident_to_attack(incident)

        incident_results.append({
            "incident": incident,
            "timeline": timeline,
            "attack_mappings": attack_mappings,
        })

    # Step 7: Return a consolidated analysis result.
    return {
        "summary": {
            "authentication_events": len(auth_events),
            "apache_events": len(apache_events),
            "firewall_events": len(firewall_events),
            "total_events": (
                len(auth_events)
                + len(apache_events)
                + len(firewall_events)
            ),
            "brute_force_alerts": len(brute_force_alerts),
            "port_scan_alerts": len(port_scan_alerts),
            "web_path_alerts": len(web_path_alerts),
            "total_alerts": len(all_alerts),
            "total_incidents": len(incidents),
        },
        "parsed_events": {
            "authentication": auth_events,
            "apache": apache_events,
            "firewall": firewall_events,
        },
        "alerts": all_alerts,
        "incidents": incidents,
        "incident_results": incident_results,
    }


if __name__ == "__main__":
    results = run_analysis()

    print("\nLOGSENTRY – INTEGRATED ANALYSIS PIPELINE")
    print("=" * 55)

    for name, count in results["summary"].items():
        print(f"{name.replace('_', ' ').title()}: {count}")

    print("\nSECURITY ALERTS")
    print("-" * 55)

    for alert in results["alerts"]:
        print(
            f"{alert['alert_type']} | "
            f"Severity: {alert.get('severity', 'Unknown')} | "
            f"Source IP: {alert.get('source_ip', 'Unknown')}"
        )

    print("\nCORRELATED INCIDENTS")
    print("-" * 55)

    if not results["incident_results"]:
        print("No correlated incidents identified.")

    for result in results["incident_results"]:
        incident = result["incident"]

        print(
            f"{incident['incident_id']} | "
            f"Source IP: {incident['source_ip']} | "
            f"Alerts: {incident['alert_count']}"
        )

        for mapping in result["attack_mappings"]:
            print(
                f"  {mapping['technique_id']} - "
                f"{mapping['technique']}"
            )

    print("\nPIPELINE EXECUTION COMPLETED")
