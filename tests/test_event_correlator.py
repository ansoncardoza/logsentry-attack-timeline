
from src.correlation.event_correlator import correlate_alerts


def create_alert(alert_type, source_ip, first_seen, last_seen=None):
    return {
        "alert_type": alert_type,
        "severity": "Medium",
        "source_ip": source_ip,
        "first_seen": first_seen,
        "last_seen": last_seen or first_seen
    }


def test_correlate_different_alert_types_from_same_ip():
    alerts = [
        create_alert(
            "SSH Brute-Force Attempt",
            "203.0.113.50",
            "2026-11-10T09:15:22"
        ),
        create_alert(
            "Possible Port Scan",
            "203.0.113.50",
            "2026-11-10T09:17:00"
        )
    ]

    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1
    assert incidents[0]["source_ip"] == "203.0.113.50"
    assert incidents[0]["alert_count"] == 2
    assert len(incidents[0]["alert_types"]) == 2


def test_do_not_correlate_different_source_ips():
    alerts = [
        create_alert(
            "SSH Brute-Force Attempt",
            "203.0.113.50",
            "2026-11-10T09:15:22"
        ),
        create_alert(
            "Possible Port Scan",
            "203.0.113.70",
            "2026-11-10T09:16:00"
        )
    ]

    assert correlate_alerts(alerts) == []


def test_do_not_correlate_alerts_outside_time_window():
    alerts = [
        create_alert(
            "SSH Brute-Force Attempt",
            "203.0.113.50",
            "2026-11-10T09:15:00"
        ),
        create_alert(
            "Possible Port Scan",
            "203.0.113.50",
            "2026-11-10T09:21:00"
        )
    ]

    assert correlate_alerts(alerts) == []


def test_single_alert_does_not_create_incident():
    alerts = [
        create_alert(
            "SSH Brute-Force Attempt",
            "203.0.113.50",
            "2026-11-10T09:15:00"
        )
    ]

    assert correlate_alerts(alerts) == []


def test_correlate_timezone_aware_and_naive_timestamps():
    alerts = [
        create_alert(
            "SSH Brute-Force Attempt",
            "203.0.113.50",
            "2026-11-10T09:15:00"
        ),
        create_alert(
            "Possible Port Scan",
            "203.0.113.50",
            "2026-11-10T09:16:00+00:00"
        )
    ]

    incidents = correlate_alerts(alerts)

    assert len(incidents) == 1
    assert incidents[0]["alert_count"] == 2
