
from src.correlation.event_correlator import correlate_alerts
from src.timeline.timeline_builder import build_timeline


# Synthetic security alerts for demonstration.
alerts = [
    {
        "alert_type": "Possible Web Path Reconnaissance",
        "severity": "Medium",
        "source_ip": "203.0.113.99",
        "distinct_paths": 4,
        "first_seen": "2026-11-10T09:17:00",
        "last_seen": "2026-11-10T09:17:06",
        "description": "Four sensitive web paths requested."
    },
    {
        "alert_type": "SSH Brute-Force Attempt",
        "severity": "Medium",
        "source_ip": "203.0.113.99",
        "failed_attempts": 5,
        "first_seen": "2026-11-10T09:15:00",
        "last_seen": "2026-11-10T09:15:24",
        "description": "Five failed SSH login attempts."
    },
    {
        "alert_type": "Possible Port Scan",
        "severity": "Medium",
        "source_ip": "203.0.113.99",
        "distinct_ports": 5,
        "first_seen": "2026-11-10T09:16:00",
        "last_seen": "2026-11-10T09:16:05",
        "description": "Five distinct destination ports targeted."
    }
]


# Step 1: Correlate the alerts.
incidents = correlate_alerts(alerts)

print("\nLOGSENTRY – ATTACK TIMELINE RECONSTRUCTION")
print("=" * 60)

print(f"Security alerts analyzed: {len(alerts)}")
print(f"Correlated incidents: {len(incidents)}")


# Step 2: Build a timeline for each correlated incident.
for incident in incidents:

    timeline = build_timeline(incident)

    print("\nINCIDENT DETAILS")
    print("-" * 60)
    print(f"Incident ID: {incident['incident_id']}")
    print(f"Source IP: {incident['source_ip']}")
    print(f"Timeline events: {len(timeline)}")

    print("\nCHRONOLOGICAL ATTACK TIMELINE")
    print("-" * 60)

    for index, event in enumerate(timeline, start=1):

        print(f"\nEvent {index}")
        print(f"Timestamp: {event['timestamp']}")
        print(f"Event type: {event['event_type']}")
        print(f"Severity: {event['severity']}")
        print(f"Source IP: {event['source_ip']}")
        print(f"Description: {event['description']}")

    print("\nEND OF INCIDENT TIMELINE")
