
from datetime import datetime, timedelta, timezone


def _parse_timestamp(value):
    """
    Convert an ISO timestamp into a timezone-aware UTC datetime.

    Timestamps without timezone information are treated as UTC.
    """

    timestamp = datetime.fromisoformat(value)

    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def correlate_alerts(alerts, window_seconds=300):
    """
    Correlate security alerts using source IP and timestamps.

    An incident requires at least two different detection types
    from the same source IP within the configured time window.

    Returns a list of correlated incidents.
    """

    events_by_ip = {}

    # Group alerts by their source IP.
    for alert in alerts:
        required_fields = ("source_ip", "alert_type", "first_seen")

        if any(field not in alert for field in required_fields):
            raise ValueError("Alert is missing required correlation fields")

        source_ip = alert["source_ip"]

        events_by_ip.setdefault(source_ip, []).append(alert)

    incidents = []

    # Analyze each source IP independently.
    for source_ip, events in sorted(events_by_ip.items()):

        events.sort(
            key=lambda event: _parse_timestamp(event["first_seen"])
        )

        index = 0

        while index < len(events):

            first_event = events[index]
            first_time = _parse_timestamp(first_event["first_seen"])

            window_end = first_time + timedelta(
                seconds=window_seconds
            )

            matching_events = [
                event for event in events[index:]
                if _parse_timestamp(event["first_seen"]) <= window_end
            ]

            alert_types = sorted({
                event["alert_type"]
                for event in matching_events
            })

            # Require at least two different detection types.
            if len(alert_types) >= 2:

                first_seen = min(
                    _parse_timestamp(event["first_seen"])
                    for event in matching_events
                )

                last_seen = max(
                    _parse_timestamp(
                        event.get("last_seen", event["first_seen"])
                    )
                    for event in matching_events
                )

                incidents.append({
                    "incident_id": f"INC-{len(incidents) + 1:03d}",
                    "source_ip": source_ip,
                    "alert_count": len(matching_events),
                    "alert_types": alert_types,
                    "first_seen": first_seen.isoformat(),
                    "last_seen": last_seen.isoformat(),
                    "alerts": matching_events,
                    "description": (
                        f"{len(alert_types)} different detection types "
                        f"were observed from {source_ip} within "
                        f"{window_seconds} seconds."
                    )
                })

                # Move past the alerts already included in this incident.
                index += len(matching_events)

            else:
                index += 1

    return incidents
