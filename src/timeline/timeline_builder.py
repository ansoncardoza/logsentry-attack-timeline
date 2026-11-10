
from datetime import datetime, timezone


def _parse_timestamp(value):
    """
    Convert an ISO timestamp into a timezone-aware UTC datetime.
    """

    timestamp = datetime.fromisoformat(value)

    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def build_timeline(incident):
    """
    Build a chronological timeline from a correlated incident.

    Each related alert becomes one timeline event.

    Returns a list of timeline event dictionaries.
    """

    if "alerts" not in incident:
        raise ValueError("Incident is missing alerts")

    timeline = []

    for alert in incident["alerts"]:

        if "first_seen" not in alert or "alert_type" not in alert:
            raise ValueError("Alert is missing required timeline fields")

        event_time = _parse_timestamp(alert["first_seen"])

        timeline.append({
            "timestamp": event_time.isoformat(),
            "event_type": alert["alert_type"],
            "source_ip": alert.get(
                "source_ip",
                incident.get("source_ip", "Unknown")
            ),
            "severity": alert.get("severity", "Unknown"),
            "description": alert.get(
                "description",
                alert["alert_type"]
            ),
            "evidence": alert
        })

    # Sort events from earliest to latest.
    timeline.sort(
        key=lambda event: _parse_timestamp(event["timestamp"])
    )

    return timeline
