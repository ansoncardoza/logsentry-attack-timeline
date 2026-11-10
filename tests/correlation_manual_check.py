
from src.correlation.event_correlator import correlate_alerts


# Synthetic alerts for demonstrating event correlation.
# These are test records, not observations from a real network.

alerts = [
    {
        "alert_type": "SSH Brute-Force Attempt",
        "severity": "Medium",
        "source_ip": "203.0.113.99",
        "failed_attempts": 5,
        "first_seen": "2026-11-10T09:15:00",
        "last_seen": "2026-11-10T09:15:24"
    },
    {
        "alert_type": "Possible Port Scan",
        "severity": "Medium",
        "source_ip": "203.0.113.99",
        "distinct_ports": 5,
        "first_seen": "2026-11-10T09:16:00",
        "last_seen": "2026-11-10T09:16:05"
    },
    {
        "alert_type": "Possible Web Path Reconnaissance",
        "severity": "Medium",
        "source_ip": "203.0.113.99",
        "distinct_paths": 4,
        "first_seen": "2026-11-10T09:17:00",
        "last_seen": "2026-11-10T09:17:06"
    }
]


# Correlate alerts using the default five-minute window.
incidents = correlate_alerts(alerts)


print("\nLOGSENTRY – EVENT CORRELATION")
print("=" * 55)

print(f"Security alerts analyzed: {len(alerts)}")
print(f"Correlated incidents generated: {len(incidents)}")

for incident in incidents:

    print("\nCORRELATED INCIDENT")
    print("-" * 55)

    print(f"Incident ID: {incident['incident_id']}")
    print(f"Source IP: {incident['source_ip']}")
    print(f"Alert count: {incident['alert_count']}")
    print(f"Detection types: {incident['alert_types']}")
    print(f"First seen: {incident['first_seen']}")
    print(f"Last seen: {incident['last_seen']}")
    print(f"Description: {incident['description']}")

    print("\nRELATED ALERTS")

    for alert in incident["alerts"]:
        print(
            f"- {alert['alert_type']} "
            f"({alert['first_seen']})"
        )
