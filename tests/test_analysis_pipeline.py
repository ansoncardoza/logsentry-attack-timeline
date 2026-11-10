
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
