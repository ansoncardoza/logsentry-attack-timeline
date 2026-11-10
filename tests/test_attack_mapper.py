
import pytest

from src.mitre.attack_mapper import (
    map_alert_to_attack,
    map_incident_to_attack
)


def test_map_ssh_brute_force():
    alert = {
        "alert_type": "SSH Brute-Force Attempt"
    }

    result = map_alert_to_attack(alert)

    assert result["technique_id"] == "T1110.001"
    assert result["tactic"] == "Credential Access"


def test_map_port_scan():
    alert = {
        "alert_type": "Possible Port Scan"
    }

    result = map_alert_to_attack(alert)

    assert result["technique_id"] == "T1046"
    assert result["tactic"] == "Discovery"


def test_map_suspicious_web_paths():
    alert = {
        "alert_type": "Possible Web Path Reconnaissance"
    }

    result = map_alert_to_attack(alert)

    assert result["technique_id"] == "T1595.003"
    assert result["tactic"] == "Reconnaissance"


def test_unknown_alert_returns_none():
    alert = {
        "alert_type": "Unknown Detection"
    }

    assert map_alert_to_attack(alert) is None


def test_map_all_alerts_in_incident():
    incident = {
        "incident_id": "INC-001",
        "alerts": [
            {"alert_type": "SSH Brute-Force Attempt"},
            {"alert_type": "Possible Port Scan"},
            {"alert_type": "Possible Web Path Reconnaissance"}
        ]
    }

    results = map_incident_to_attack(incident)

    assert len(results) == 3

    assert {
        result["technique_id"] for result in results
    } == {
        "T1110.001",
        "T1046",
        "T1595.003"
    }


def test_unknown_alert_is_skipped_in_incident():
    incident = {
        "alerts": [
            {"alert_type": "SSH Brute-Force Attempt"},
            {"alert_type": "Unknown Detection"}
        ]
    }

    results = map_incident_to_attack(incident)

    assert len(results) == 1
    assert results[0]["technique_id"] == "T1110.001"


def test_missing_alerts_raises_error():
    with pytest.raises(ValueError, match="Incident is missing alerts"):
        map_incident_to_attack({"incident_id": "INC-001"})
