
from datetime import datetime, timedelta
from urllib.parse import urlsplit


SUSPICIOUS_PATHS = {
    "/admin",
    "/.env",
    "/phpmyadmin",
    "/wp-config.php",
    "/wp-admin",
    "/server-status",
    "/config.php",
    "/backup"
}


def detect_suspicious_web_paths(
    apache_events,
    threshold=3,
    window_seconds=60
):
    """
    Detect possible web reconnaissance through suspicious path requests.

    Groups requests by source IP and identifies distinct sensitive
    paths requested within a time window.
    """

    # Group events by source IP.
    events_by_ip = {}

    for event in apache_events:
        source_ip = event["source_ip"]
        events_by_ip.setdefault(source_ip, []).append(event)

    alerts = []

    for source_ip, events in events_by_ip.items():

        # Identify requests to known suspicious paths.
        suspicious_events = []

        for event in events:
            normalized_path = (
                urlsplit(event["path"]).path.lower().rstrip("/") or "/"
            )

            if normalized_path in SUSPICIOUS_PATHS:
                suspicious_events.append({
                    **event,
                    "normalized_path": normalized_path
                })

        suspicious_events.sort(
            key=lambda event: datetime.fromisoformat(event["timestamp"])
        )

        # Examine each event as the start of a time window.
        for index, first_event in enumerate(suspicious_events):

            first_time = datetime.fromisoformat(
                first_event["timestamp"]
            )

            window_end = first_time + timedelta(
                seconds=window_seconds
            )

            matching_events = [
                event for event in suspicious_events[index:]
                if datetime.fromisoformat(event["timestamp"]) <= window_end
            ]

            distinct_paths = sorted({
                event["normalized_path"]
                for event in matching_events
            })

            if len(distinct_paths) >= threshold:

                alerts.append({
                    "alert_type": "Possible Web Path Reconnaissance",
                    "severity": "Medium",
                    "source_ip": source_ip,
                    "distinct_paths": len(distinct_paths),
                    "suspicious_paths": distinct_paths,
                    "request_count": len(matching_events),
                    "first_seen": first_event["timestamp"],
                    "last_seen": matching_events[-1]["timestamp"],
                    "status_codes": sorted({
                        event["status_code"]
                        for event in matching_events
                    }),
                    "description": (
                        f"{source_ip} requested {len(distinct_paths)} "
                        f"distinct suspicious web paths within "
                        f"{window_seconds} seconds."
                    )
                })

                # Avoid duplicate alerts for the same source IP.
                break

    return alerts
