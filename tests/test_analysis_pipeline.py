
import pytest

from src.analysis_pipeline import run_analysis


def test_pipeline_parses_all_log_sources():
    results = run_analysis()

    assert results["summary"]["authentication_events"] == 7
    assert results["summary"]["apache_events"] == 7
    assert results["summary"]["firewall_events"] == 6
    assert results["summary"]["total_events"] == 20


def test_pipeline_generates_expected_alerts():
    results = run_analysis()

    assert results["summary"]["brute_force_alerts"] == 1
    assert results["summary"]["port_scan_alerts"] == 1
    assert results["summary"]["web_path_alerts"] == 1
    assert results["summary"]["total_alerts"] == 3

    alert_types = {
        alert["alert_type"]
        for alert in results["alerts"]
    }

    assert alert_types == {
        "SSH Brute-Force Attempt",
        "Possible Port Scan",
        "Possible Web Path Reconnaissance",
    }


def test_pipeline_does_not_correlate_different_source_ips():
    results = run_analysis()

    assert results["summary"]["total_incidents"] == 0
    assert results["incidents"] == []
    assert results["incident_results"] == []


def test_pipeline_raises_error_for_missing_log_file(tmp_path):
    missing_file = tmp_path / "missing_auth.log"

    with pytest.raises(FileNotFoundError):
        run_analysis(auth_log_path=missing_file)


def test_pipeline_respects_custom_detection_thresholds():
    results = run_analysis(
        brute_force_threshold=6,
        port_scan_threshold=6,
        web_path_threshold=5
    )

    assert results["summary"]["brute_force_alerts"] == 0
    assert results["summary"]["port_scan_alerts"] == 0
    assert results["summary"]["web_path_alerts"] == 0
    assert results["summary"]["total_alerts"] == 0


def test_pipeline_reports_malformed_log_location(tmp_path):
    malformed_auth_log = tmp_path / "malformed_auth.log"
    malformed_auth_log.write_text(
        "This is not a valid authentication log entry\n",
        encoding="utf-8"
    )

    with pytest.raises(
        ValueError,
        match=r"Authentication log parsing failed.*line 1"
    ):
        run_analysis(auth_log_path=malformed_auth_log)


def test_pipeline_handles_empty_log_files(tmp_path):
    auth_log = tmp_path / "auth.log"
    apache_log = tmp_path / "apache_access.log"
    firewall_log = tmp_path / "firewall.log"

    auth_log.write_text("", encoding="utf-8")
    apache_log.write_text("", encoding="utf-8")
    firewall_log.write_text("", encoding="utf-8")

    results = run_analysis(
        auth_log_path=auth_log,
        apache_log_path=apache_log,
        firewall_log_path=firewall_log
    )

    assert results["summary"]["total_events"] == 0
    assert results["summary"]["total_alerts"] == 0
    assert results["summary"]["total_incidents"] == 0
    assert results["alerts"] == []
    assert results["incidents"] == []
