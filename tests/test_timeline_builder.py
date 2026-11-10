
import pytest

from src.timeline.timeline_builder import build_timeline


def create_incident():
    return {
        "incident_id": "INC-001",
        "source_ip": "203.0.113.99",
        "alerts": [
            {
                "alert_type": "Possible Web Path Reconnaissance",
                "severity": "Medium",
                "source_ip": "203.0.113.99",
                "first_seen": "2026-11-10T09:17:00",
                "last_seen": "2026-11-10T09:17:06"
            },
            {
                "alert_type": "SSH Brute-Force Attempt",
                "severity": "Medium",
                "source_ip": "203.0.113.99",
                "first_seen": "2026-11-10T09:15:00",
                "last_seen": "2026-11-10T09:15:24"
            },
            {
                "alert_type": "Possible Port Scan",
                "severity": "Medium",
                "source_ip": "203.0.113.99",
                "first_seen": "2026-11-10T09:16:00",
                "last_seen": "2026-11-10T09:16:05"
            }
        ]
    }


def test_timeline_is_chronological():
    timeline = build_timeline(create_incident())

    assert len(timeline) == 3

    assert [
        event["event_type"] for event in timeline
    ] == [
        "SSH Brute-Force Attempt",
        "Possible Port Scan",
        "Possible Web Path Reconnaissance"
    ]


def test_timeline_preserves_source_ip():
    timeline = build_timeline(create_incident())

    assert all(
        event["source_ip"] == "203.0.113.99"
        for event in timeline
    )


def test_timeline_preserves_original_alert_evidence():
    incident = create_incident()
    timeline = build_timeline(incident)

    assert timeline[0]["evidence"] == incident["alerts"][1]


def test_timeline_normalizes_timezone():
    incident = {
        "alerts": [
            {
                "alert_type": "Test Event",
                "source_ip": "203.0.113.99",
                "first_seen": "2026-11-10T09:15:00"
            },
            {
                "alert_type": "Second Event",
                "source_ip": "203.0.113.99",
                "first_seen": "2026-11-10T09:16:00+00:00"
            }
        ]
    }

    timeline = build_timeline(incident)

    assert timeline[0]["timestamp"].endswith("+00:00")
    assert timeline[1]["timestamp"].endswith("+00:00")


def test_missing_alerts_raises_error():
    with pytest.raises(ValueError, match="Incident is missing alerts"):
        build_timeline({"incident_id": "INC-001"})


def test_missing_alert_timestamp_raises_error():
    incident = {
        "alerts": [
            {
                "alert_type": "Test Event",
                "source_ip": "203.0.113.99"
            }
        ]
    }

    with pytest.raises(ValueError, match="Alert is missing required timeline fields"):
        build_timeline(incident)


def test_empty_alert_list_returns_empty_timeline():
    timeline = build_timeline({"alerts": []})

    assert timeline == []
