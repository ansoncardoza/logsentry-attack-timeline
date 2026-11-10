
import json
from datetime import datetime, timezone
from pathlib import Path
from src.mitre.attack_mapper import map_alert_to_attack

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def json_serializer(value):
    """
    Convert Python objects that JSON cannot serialize directly.
    """
    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Path):
        return str(value)

    raise TypeError(
        f"Object of type {type(value).__name__} "
        "is not JSON serializable"
    )


def generate_json_report(analysis_results, output_path=None):
    """
    Generate a JSON investigation report from LogSentry analysis results.

    Args:
        analysis_results: Dictionary returned by run_analysis().
        output_path: Optional destination for the JSON report.

    Returns:
        Path to the generated JSON report.
    """

    if not isinstance(analysis_results, dict):
        raise TypeError("Analysis results must be a dictionary.")

    required_sections = [
        "summary",
        "parsed_events",
        "alerts",
        "incidents",
        "incident_results",
    ]

    for section in required_sections:
        if section not in analysis_results:
            raise ValueError(
                f"Analysis results are missing the '{section}' section."
            )
        # Map each security alert to its MITRE ATT&CK technique.
    alert_mappings = [
        mapping
        for alert in analysis_results["alerts"]
        if (mapping := map_alert_to_attack(alert)) is not None
    ]
    # Build the report structure.
    report = {
        "metadata": {
            "project": "LogSentry",
            "report_type": "Security Investigation Report",
            "report_generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "report_version": "1.0",
        },
        "summary": analysis_results["summary"],
        "parsed_events": analysis_results["parsed_events"],
        "alerts": analysis_results["alerts"],
        "alert_mappings": alert_mappings,
        "incidents": analysis_results["incidents"],
        "incident_results": analysis_results["incident_results"],
    }

    # Use the default reports directory if no path is supplied.
    if output_path is None:
        output_path = (
            PROJECT_ROOT
            / "reports"
            / "logsentry_report.json"
        )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the report as formatted JSON.
    with output_path.open("w", encoding="utf-8") as report_file:
        json.dump(
            report,
            report_file,
            indent=4,
            ensure_ascii=False,
            default=json_serializer,
        )

    return output_path
