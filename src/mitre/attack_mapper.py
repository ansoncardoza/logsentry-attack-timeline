
MITRE_ATTACK_MAPPINGS = {
    "SSH Brute-Force Attempt": {
        "technique": "Brute Force: Password Guessing",
        "technique_id": "T1110.001",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "rationale": (
            "Repeated failed SSH password authentication attempts "
            "are consistent with password guessing activity."
        )
    },
    "Possible Port Scan": {
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "rationale": (
            "Attempts to reach multiple destination ports may indicate "
            "network service discovery."
        )
    },
    "Possible Web Path Reconnaissance": {
        "technique": "Active Scanning: Wordlist Scanning",
        "technique_id": "T1595.003",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/003/",
        "rationale": (
            "Requests for multiple sensitive or commonly targeted web "
            "paths are consistent with wordlist-based reconnaissance."
        )
    }
}


def map_alert_to_attack(alert):
    """
    Map one LogSentry alert to a MITRE ATT&CK technique.

    Returns mapping details, or None if no mapping exists.
    """

    alert_type = alert.get("alert_type")

    mapping = MITRE_ATTACK_MAPPINGS.get(alert_type)

    if mapping is None:
        return None

    return {
        "alert_type": alert_type,
        **mapping
    }


def map_incident_to_attack(incident):
    """
    Map all recognized alerts in a correlated incident.

    Unknown alert types are skipped rather than assigned
    an unsupported ATT&CK technique.
    """

    if "alerts" not in incident:
        raise ValueError("Incident is missing alerts")

    mappings = []

    for alert in incident["alerts"]:

        mapping = map_alert_to_attack(alert)

        if mapping is not None:
            mappings.append(mapping)

    return mappings
