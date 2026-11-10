
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


def test_detect_brute_force_from_multiple_ips():
    events = [
        create_auth_event(
            "2026-11-10T09:15:00",
            source_ip="203.0.113.50"
        ),
        create_auth_event(
            "2026-11-10T09:15:05",
            source_ip="203.0.113.50"
        ),
        create_auth_event(
            "2026-11-10T09:15:10",
            source_ip="203.0.113.50"
        ),
        create_auth_event(
            "2026-11-10T09:15:15",
            source_ip="203.0.113.50"
        ),
        create_auth_event(
            "2026-11-10T09:15:20",
            source_ip="203.0.113.50"
        ),
        create_auth_event(
            "2026-11-10T09:16:00",
            source_ip="203.0.113.60"
        ),
        create_auth_event(
            "2026-11-10T09:16:05",
            source_ip="203.0.113.60"
        ),
        create_auth_event(
            "2026-11-10T09:16:10",
            source_ip="203.0.113.60"
        ),
        create_auth_event(
            "2026-11-10T09:16:15",
            source_ip="203.0.113.60"
        ),
        create_auth_event(
            "2026-11-10T09:16:20",
            source_ip="203.0.113.60"
        )
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 2
    assert {alert["source_ip"] for alert in alerts} == {
        "203.0.113.50",
        "203.0.113.60"
    }


def test_successful_login_does_not_count_toward_threshold():
    events = [
        create_auth_event("2026-11-10T09:15:00"),
        create_auth_event("2026-11-10T09:15:05"),
        create_auth_event("2026-11-10T09:15:10"),
        create_auth_event("2026-11-10T09:15:15"),
        create_auth_event("2026-11-10T09:15:20"),
        create_auth_event(
            "2026-11-10T09:15:25",
            result="Accepted"
        )
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["failed_attempts"] == 5


def test_detect_brute_force_at_exact_window_boundary():
    events = [
        create_auth_event("2026-11-10T09:15:00"),
        create_auth_event("2026-11-10T09:15:15"),
        create_auth_event("2026-11-10T09:15:30"),
        create_auth_event("2026-11-10T09:15:45"),
        create_auth_event("2026-11-10T09:16:00")
    ]

    alerts = detect_brute_force(
        events,
        threshold=5,
        window_seconds=60
    )

    assert len(alerts) == 1
    assert alerts[0]["failed_attempts"] == 5


def test_detect_brute_force_with_more_than_five_failures():
    events = [
        create_auth_event("2026-11-10T09:15:00"),
        create_auth_event("2026-11-10T09:15:05"),
        create_auth_event("2026-11-10T09:15:10"),
        create_auth_event("2026-11-10T09:15:15"),
        create_auth_event("2026-11-10T09:15:20"),
        create_auth_event("2026-11-10T09:15:25"),
        create_auth_event("2026-11-10T09:15:30")
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["failed_attempts"] == 7
