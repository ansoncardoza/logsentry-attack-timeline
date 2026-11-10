
from src.detection.brute_force_detector import detect_brute_force


def create_auth_event(timestamp, result="Failed", source_ip="203.0.113.50",
                      username="admin"):
    return {
        "timestamp": timestamp,
        "result": result,
        "source_ip": source_ip,
        "username": username
    }


def test_detect_brute_force_with_five_failures():
    events = [
        create_auth_event("2026-11-10T09:15:22", username="admin"),
        create_auth_event("2026-11-10T09:15:28", username="root"),
        create_auth_event("2026-11-10T09:15:34", username="test"),
        create_auth_event("2026-11-10T09:15:40", username="anson"),
        create_auth_event("2026-11-10T09:15:46", username="admin")
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "203.0.113.50"
    assert alerts[0]["failed_attempts"] == 5
    assert alerts[0]["severity"] == "Medium"


def test_ignore_successful_authentication():
    events = [
        create_auth_event(
            "2026-11-10T09:15:22",
            result="Accepted"
        )
        for _ in range(5)
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_ignore_fewer_than_five_failures():
    events = [
        create_auth_event("2026-11-10T09:15:22"),
        create_auth_event("2026-11-10T09:15:28"),
        create_auth_event("2026-11-10T09:15:34"),
        create_auth_event("2026-11-10T09:15:40")
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_ignore_failures_outside_time_window():
    events = [
        create_auth_event("2026-11-10T09:15:00"),
        create_auth_event("2026-11-10T09:16:10"),
        create_auth_event("2026-11-10T09:17:20"),
        create_auth_event("2026-11-10T09:18:30"),
        create_auth_event("2026-11-10T09:19:40")
    ]

    alerts = detect_brute_force(events)

    assert alerts == []
