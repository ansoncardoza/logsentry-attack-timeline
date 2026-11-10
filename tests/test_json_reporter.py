
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.reporting.json_reporter import generate_json_report


def sample_analysis_results():
    """Create sample analysis results for reporting tests."""

    return {
        "summary": {
            "total_events": 20,
            "total_alerts": 3,
            "total_incidents": 0,
        },
        "parsed_events": {
            "authentication": [
                {
                    "source_ip": "203.0.113.50",
                    "timestamp": datetime(
                        2026, 11, 10, 9, 15, 22,
                        tzinfo=timezone.utc,
                    ),
                }
            ],
            "apache": [],
            "firewall": [],
        },
        "alerts": [
            {
                "alert_type": "SSH Brute-Force Attempt",
                "severity": "Medium",
                "source_ip": "203.0.113.50",
            }
        ],
        "incidents": [],
        "incident_results": [],
    }


def test_generate_json_report_creates_valid_file(tmp_path):
    """The exporter should create a readable JSON file."""

    output_path = tmp_path / "reports" / "test_report.json"

    report_path = generate_json_report(
        sample_analysis_results(),
        output_path,
    )

    assert report_path == output_path
    assert report_path.is_file()

    with report_path.open("r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["summary"]["total_events"] == 20
    assert len(report["alerts"]) == 1
    assert report["incidents"] == []
    assert len(report["alert_mappings"]) == 1
    assert report["alert_mappings"][0]["technique_id"] == "T1110.001"


def test_json_report_contains_metadata():
    """The report should contain project and generation metadata."""

    output_path = generate_json_report(
        sample_analysis_results(),
        Path("reports") / "test_metadata_report.json",
    )

    try:
        with output_path.open("r", encoding="utf-8") as file:
            report = json.load(file)

        assert report["metadata"]["project"] == "LogSentry"
        assert report["metadata"]["report_version"] == "1.0"

        generated_at = report["metadata"]["report_generated_at"]
        datetime.fromisoformat(generated_at)

    finally:
        output_path.unlink(missing_ok=True)


def test_json_report_serializes_datetime(tmp_path):
    """Datetime objects should become ISO 8601 strings."""

    output_path = tmp_path / "datetime_report.json"

    generate_json_report(
        sample_analysis_results(),
        output_path,
    )

    with output_path.open("r", encoding="utf-8") as file:
        report = json.load(file)

    timestamp = report["parsed_events"]["authentication"][0]["timestamp"]

    assert timestamp == "2026-11-10T09:15:22+00:00"


def test_json_report_rejects_missing_sections(tmp_path):
    """The exporter should reject incomplete analysis results."""

    incomplete_results = {
        "summary": {},
        "alerts": [],
    }

    with pytest.raises(ValueError, match="parsed_events"):
        generate_json_report(
            incomplete_results,
            tmp_path / "invalid_report.json",
        )


def test_json_report_rejects_non_dictionary_input(tmp_path):
    """The exporter should reject non-dictionary input."""

    with pytest.raises(TypeError, match="must be a dictionary"):
        generate_json_report(
            [],
            tmp_path / "invalid_report.json",
        )
