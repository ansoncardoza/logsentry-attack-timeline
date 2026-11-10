
from src.correlation.event_correlator import correlate_alerts
from src.mitre.attack_mapper import map_incident_to_attack


# Synthetic alerts for demonstration.
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


# Step 1: Correlate the alerts into an incident.
incidents = correlate_alerts(alerts)

print("\nLOGSENTRY – MITRE ATT&CK MAPPING")
print("=" * 60)

print(f"Security alerts analyzed: {len(alerts)}")
print(f"Correlated incidents: {len(incidents)}")


# Step 2: Map each incident to MITRE ATT&CK.
for incident in incidents:

    mappings = map_incident_to_attack(incident)

    print("\nINCIDENT DETAILS")
    print("-" * 60)
    print(f"Incident ID: {incident['incident_id']}")
    print(f"Source IP: {incident['source_ip']}")

    print("\nMITRE ATT&CK TECHNIQUE MAPPINGS")
    print("-" * 60)

    for index, mapping in enumerate(mappings, start=1):

        print(f"\nMapping {index}")
        print(f"Detection: {mapping['alert_type']}")
        print(f"Technique: {mapping['technique']}")
        print(f"Technique ID: {mapping['technique_id']}")
        print(f"Tactic: {mapping['tactic']}")
        print(f"Reference: {mapping['url']}")
        print(f"Rationale: {mapping['rationale']}")

    print("\nEND OF MITRE MAPPING")
