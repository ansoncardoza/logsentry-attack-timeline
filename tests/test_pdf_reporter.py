
from datetime import datetime, timezone

import pytest

from src.reporting.pdf_reporter import generate_pdf_report


def sample_analysis_results():
    """Create sample analysis results for PDF reporting tests."""

    return {
        "summary": {
            "authentication_events": 7,
            "apache_events": 7,
            "firewall_events": 6,
            "total_events": 20,
            "brute_force_alerts": 1,
            "port_scan_alerts": 1,
            "web_path_alerts": 1,
            "total_alerts": 3,
            "total_incidents": 0,
        },
        "parsed_events": {
            "authentication": [
                {
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
                "failed_attempts": 5,
                "first_seen": "2026-11-10T09:15:22+00:00",
                "last_seen": "2026-11-10T09:15:46+00:00",
                "description": "Five failed SSH login attempts.",
            }
        ],
        "incidents": [],
        "incident_results": [],
    }


def test_generate_pdf_report_creates_valid_file(tmp_path):
    """The PDF exporter should create a valid PDF file."""

    output_path = tmp_path / "test_report.pdf"

    report_path = generate_pdf_report(
        sample_analysis_results(),
        output_path,
    )

    assert report_path == output_path
    assert report_path.is_file()
    assert report_path.stat().st_size > 0

    with report_path.open("rb") as file:
        assert file.read(5) == b"%PDF-"


def test_pdf_report_creates_parent_directory(tmp_path):
    """The exporter should create missing output directories."""

    output_path = tmp_path / "reports" / "nested" / "test_report.pdf"

    report_path = generate_pdf_report(
        sample_analysis_results(),
        output_path,
    )

    assert report_path.is_file()


def test_pdf_report_rejects_missing_sections(tmp_path):
    """The exporter should reject incomplete analysis results."""

    incomplete_results = {
        "summary": {},
        "alerts": [],
    }

    with pytest.raises(ValueError, match="parsed_events"):
        generate_pdf_report(
            incomplete_results,
            tmp_path / "invalid_report.pdf",
        )


def test_pdf_report_rejects_non_dictionary_input(tmp_path):
    """The exporter should reject non-dictionary input."""

    with pytest.raises(TypeError, match="must be a dictionary"):
        generate_pdf_report(
            [],
            tmp_path / "invalid_report.pdf",
        )


def test_pdf_report_handles_empty_analysis_results(tmp_path):
    """The exporter should generate a PDF when there are no events or alerts."""

    results = {
        "summary": {
            "total_events": 0,
            "total_alerts": 0,
            "total_incidents": 0,
        },
        "parsed_events": {
            "authentication": [],
            "apache": [],
            "firewall": [],
        },
        "alerts": [],
        "incidents": [],
        "incident_results": [],
    }

    output_path = tmp_path / "empty_report.pdf"

    report_path = generate_pdf_report(results, output_path)

    assert report_path.is_file()
    assert report_path.stat().st_size > 0

    with report_path.open("rb") as file:
        assert file.read(5) == b"%PDF-"


def test_pdf_report_handles_special_characters(tmp_path):
    """Log-derived text containing HTML characters should not break PDF generation."""

    results = sample_analysis_results()
    results["alerts"][0]["description"] = (
        '<script>alert("test")</script> '
        'Suspicious request: /search?a=1&b=2'
    )

    output_path = tmp_path / "special_characters_report.pdf"

    report_path = generate_pdf_report(results, output_path)

    assert report_path.is_file()
    assert report_path.stat().st_size > 0


def test_pdf_report_handles_unknown_alert_mapping(tmp_path):
    """Unknown detection types should not prevent PDF generation."""

    results = sample_analysis_results()
    results["alerts"].append({
        "alert_type": "Unknown Detection",
        "severity": "Low",
        "source_ip": "203.0.113.99",
        "description": "Unrecognized detection type."
    })

    output_path = tmp_path / "unknown_mapping_report.pdf"

    report_path = generate_pdf_report(results, output_path)

    assert report_path.is_file()
    assert report_path.stat().st_size > 0
