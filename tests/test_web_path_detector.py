
from src.detection.web_path_detector import detect_suspicious_web_paths


def create_apache_event(timestamp, path, source_ip="203.0.113.60",
                        status_code=404):
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "path": path,
        "status_code": status_code
    }


def test_detect_suspicious_web_paths():
    events = [
        create_apache_event("2026-11-10T09:35:00", "/admin"),
        create_apache_event("2026-11-10T09:35:02", "/.env"),
        create_apache_event("2026-11-10T09:35:04", "/phpmyadmin"),
        create_apache_event("2026-11-10T09:35:06", "/wp-config.php")
    ]

    alerts = detect_suspicious_web_paths(events)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "203.0.113.60"
    assert alerts[0]["distinct_paths"] == 4
    assert alerts[0]["request_count"] == 4
    assert alerts[0]["severity"] == "Medium"


def test_ignore_normal_web_paths():
    events = [
        create_apache_event("2026-11-10T09:35:00", "/index.html"),
        create_apache_event("2026-11-10T09:35:02", "/about.html"),
        create_apache_event("2026-11-10T09:35:04", "/contact.html")
    ]

    alerts = detect_suspicious_web_paths(events)

    assert alerts == []


def test_ignore_repeated_requests_to_same_suspicious_path():
    events = [
        create_apache_event("2026-11-10T09:35:00", "/admin"),
        create_apache_event("2026-11-10T09:35:02", "/admin"),
        create_apache_event("2026-11-10T09:35:04", "/admin")
    ]

    alerts = detect_suspicious_web_paths(events)

    assert alerts == []


def test_ignore_suspicious_paths_outside_time_window():
    events = [
        create_apache_event("2026-11-10T09:35:00", "/admin"),
        create_apache_event("2026-11-10T09:36:10", "/.env"),
        create_apache_event("2026-11-10T09:37:20", "/phpmyadmin")
    ]

    alerts = detect_suspicious_web_paths(events)

    assert alerts == []


def test_detect_suspicious_paths_from_multiple_ips():
    events = [
        create_apache_event(
            "2026-11-10T09:35:00", "/admin",
            source_ip="203.0.113.60"
        ),
        create_apache_event(
            "2026-11-10T09:35:02", "/.env",
            source_ip="203.0.113.60"
        ),
        create_apache_event(
            "2026-11-10T09:35:04", "/phpmyadmin",
            source_ip="203.0.113.60"
        ),
        create_apache_event(
            "2026-11-10T09:36:00", "/admin",
            source_ip="203.0.113.61"
        ),
        create_apache_event(
            "2026-11-10T09:36:02", "/.env",
            source_ip="203.0.113.61"
        ),
        create_apache_event(
            "2026-11-10T09:36:04", "/phpmyadmin",
            source_ip="203.0.113.61"
        )
    ]

    alerts = detect_suspicious_web_paths(events)

    assert len(alerts) == 2
    assert {alert["source_ip"] for alert in alerts} == {
        "203.0.113.60",
        "203.0.113.61"
    }


def test_normalize_case_trailing_slashes_and_query_strings():
    events = [
        create_apache_event(
            "2026-11-10T09:35:00", "/ADMIN/?next=login"
        ),
        create_apache_event(
            "2026-11-10T09:35:02", "/.ENV?debug=true"
        ),
        create_apache_event(
            "2026-11-10T09:35:04", "/PHPMYADMIN/"
        )
    ]

    alerts = detect_suspicious_web_paths(events)

    assert len(alerts) == 1
    assert alerts[0]["suspicious_paths"] == [
        "/.env",
        "/admin",
        "/phpmyadmin"
    ]


def test_detect_suspicious_paths_at_exact_window_boundary():
    events = [
        create_apache_event("2026-11-10T09:35:00", "/admin"),
        create_apache_event("2026-11-10T09:35:30", "/.env"),
        create_apache_event("2026-11-10T09:36:00", "/phpmyadmin")
    ]

    alerts = detect_suspicious_web_paths(
        events,
        threshold=3,
        window_seconds=60
    )

    assert len(alerts) == 1
    assert alerts[0]["distinct_paths"] == 3


def test_alert_preserves_http_status_codes():
    events = [
        create_apache_event(
            "2026-11-10T09:35:00", "/admin", status_code=404
        ),
        create_apache_event(
            "2026-11-10T09:35:02", "/.env", status_code=403
        ),
        create_apache_event(
            "2026-11-10T09:35:04", "/phpmyadmin", status_code=200
        )
    ]

    alerts = detect_suspicious_web_paths(events)

    assert len(alerts) == 1
    assert alerts[0]["status_codes"] == [200, 403, 404]
