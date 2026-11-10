
from datetime import datetime, timedelta


def detect_brute_force(auth_events, threshold=5, window_seconds=60):
    """
    Detect repeated failed SSH login attempts from the same IP.

    Args:
        auth_events: List of parsed authentication log dictionaries.
        threshold: Minimum failed attempts required for an alert.
        window_seconds: Time window used for detection.

    Returns:
        A list of brute-force alerts.
    """

    # Keep only failed authentication events.
    failed_events = [
        event for event in auth_events
        if event["result"] == "Failed"
    ]

    # Group failed events by source IP.
    events_by_ip = {}

    for event in failed_events:
        source_ip = event["source_ip"]

        events_by_ip.setdefault(source_ip, []).append(event)

    alerts = []

    # Examine each source IP separately.
    for source_ip, events in events_by_ip.items():

        # Sort events chronologically.
        events.sort(
            key=lambda event: datetime.fromisoformat(event["timestamp"])
        )

        # Check each event as the start of a time window.
        for index, first_event in enumerate(events):

            first_time = datetime.fromisoformat(
                first_event["timestamp"]
            )

            window_end = first_time + timedelta(
                seconds=window_seconds
            )

            matching_events = [
                event for event in events[index:]
                if datetime.fromisoformat(event["timestamp"]) <= window_end
            ]

            if len(matching_events) >= threshold:

                last_event = matching_events[-1]

                usernames = sorted({
                    event["username"]
                    for event in matching_events
                })

                alerts.append({
                    "alert_type": "SSH Brute-Force Attempt",
                    "severity": "Medium",
                    "source_ip": source_ip,
                    "failed_attempts": len(matching_events),
                    "first_seen": first_event["timestamp"],
                    "last_seen": last_event["timestamp"],
                    "usernames": usernames,
                    "description": (
                        f"{len(matching_events)} failed SSH login attempts "
                        f"from {source_ip} within {window_seconds} seconds."
                    )
                })

                # Avoid generating duplicate alerts for the same cluster.
                break

    return alerts
