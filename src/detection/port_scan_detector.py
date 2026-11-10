
from datetime import datetime, timedelta


def detect_port_scan(firewall_events, threshold=5, window_seconds=60):
    """
    Detect possible port scanning from firewall events.

    Groups events by source IP and destination IP, then checks
    for attempts to reach multiple distinct destination ports.

    Returns a list of port-scan alerts.
    """

    # Group events by source and destination IP.
    events_by_pair = {}

    for event in firewall_events:
        key = (event["source_ip"], event["destination_ip"])
        events_by_pair.setdefault(key, []).append(event)

    alerts = []

    # Analyze each source and destination pair separately.
    for (source_ip, destination_ip), events in events_by_pair.items():

        events.sort(
            key=lambda event: datetime.fromisoformat(event["timestamp"])
        )

        # Examine each event as the start of a time window.
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

            # Count distinct destination ports, not total events.
            destination_ports = sorted({
                event["destination_port"]
                for event in matching_events
            })

            if len(destination_ports) >= threshold:

                alerts.append({
                    "alert_type": "Possible Port Scan",
                    "severity": "Medium",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "distinct_ports": len(destination_ports),
                    "destination_ports": destination_ports,
                    "first_seen": first_event["timestamp"],
                    "last_seen": matching_events[-1]["timestamp"],
                    "actions": sorted({
                        event["action"]
                        for event in matching_events
                    }),
                    "description": (
                        f"{source_ip} targeted {len(destination_ports)} "
                        f"distinct destination ports on {destination_ip} "
                        f"within {window_seconds} seconds."
                    )
                })

                # Avoid duplicate alerts for the same source/target pair.
                break

    return alerts
