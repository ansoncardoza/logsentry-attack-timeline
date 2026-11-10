
from src.detection.port_scan_detector import detect_port_scan


def create_firewall_event(timestamp, destination_port,
                          source_ip="203.0.113.70",
                          destination_ip="192.168.1.100",
                          action="BLOCK"):
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "action": action
    }


def test_detect_port_scan_with_five_distinct_ports():
    events = [
        create_firewall_event("2026-11-10T10:00:01", 22),
        create_firewall_event("2026-11-10T10:00:02", 80),
        create_firewall_event("2026-11-10T10:00:03", 443),
        create_firewall_event("2026-11-10T10:00:04", 3389),
        create_firewall_event("2026-11-10T10:00:05", 8080)
    ]

    alerts = detect_port_scan(events)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "203.0.113.70"
    assert alerts[0]["distinct_ports"] == 5
    assert alerts[0]["destination_ports"] == [22, 80, 443, 3389, 8080]
    assert alerts[0]["severity"] == "Medium"


def test_ignore_repeated_attempts_to_same_port():
    events = [
        create_firewall_event("2026-11-10T10:00:01", 22),
        create_firewall_event("2026-11-10T10:00:02", 22),
        create_firewall_event("2026-11-10T10:00:03", 22),
        create_firewall_event("2026-11-10T10:00:04", 22),
        create_firewall_event("2026-11-10T10:00:05", 22)
    ]

    alerts = detect_port_scan(events)

    assert alerts == []


def test_ignore_fewer_than_five_distinct_ports():
    events = [
        create_firewall_event("2026-11-10T10:00:01", 22),
        create_firewall_event("2026-11-10T10:00:02", 80),
        create_firewall_event("2026-11-10T10:00:03", 443),
        create_firewall_event("2026-11-10T10:00:04", 3389)
    ]

    alerts = detect_port_scan(events)

    assert alerts == []


def test_ignore_ports_outside_time_window():
    events = [
        create_firewall_event("2026-11-10T10:00:00", 22),
        create_firewall_event("2026-11-10T10:01:10", 80),
        create_firewall_event("2026-11-10T10:02:20", 443),
        create_firewall_event("2026-11-10T10:03:30", 3389),
        create_firewall_event("2026-11-10T10:04:40", 8080)
    ]

    alerts = detect_port_scan(events)

    assert alerts == []


def test_detect_port_scans_from_multiple_source_ips():
    events = [
        create_firewall_event(
            "2026-11-10T10:00:01", 22,
            source_ip="203.0.113.70"
        ),
        create_firewall_event(
            "2026-11-10T10:00:02", 80,
            source_ip="203.0.113.70"
        ),
        create_firewall_event(
            "2026-11-10T10:00:03", 443,
            source_ip="203.0.113.70"
        ),
        create_firewall_event(
            "2026-11-10T10:00:04", 3389,
            source_ip="203.0.113.70"
        ),
        create_firewall_event(
            "2026-11-10T10:00:05", 8080,
            source_ip="203.0.113.70"
        ),
        create_firewall_event(
            "2026-11-10T10:01:01", 22,
            source_ip="203.0.113.80"
        ),
        create_firewall_event(
            "2026-11-10T10:01:02", 80,
            source_ip="203.0.113.80"
        ),
        create_firewall_event(
            "2026-11-10T10:01:03", 443,
            source_ip="203.0.113.80"
        ),
        create_firewall_event(
            "2026-11-10T10:01:04", 3389,
            source_ip="203.0.113.80"
        ),
        create_firewall_event(
            "2026-11-10T10:01:05", 8080,
            source_ip="203.0.113.80"
        )
    ]

    alerts = detect_port_scan(events)

    assert len(alerts) == 2
    assert {alert["source_ip"] for alert in alerts} == {
        "203.0.113.70",
        "203.0.113.80"
    }


def test_detect_port_scans_against_multiple_destinations():
    events = []

    for destination_ip in ["192.168.1.100", "192.168.1.101"]:
        for index, port in enumerate([22, 80, 443, 3389, 8080]):
            events.append(
                create_firewall_event(
                    f"2026-11-10T10:00:0{index + 1}",
                    port,
                    destination_ip=destination_ip
                )
            )

    alerts = detect_port_scan(events)

    assert len(alerts) == 2
    assert {
        alert["destination_ip"] for alert in alerts
    } == {"192.168.1.100", "192.168.1.101"}


def test_detect_port_scan_at_exact_window_boundary():
    events = [
        create_firewall_event("2026-11-10T10:00:00", 22),
        create_firewall_event("2026-11-10T10:00:15", 80),
        create_firewall_event("2026-11-10T10:00:30", 443),
        create_firewall_event("2026-11-10T10:00:45", 3389),
        create_firewall_event("2026-11-10T10:01:00", 8080)
    ]

    alerts = detect_port_scan(
        events,
        threshold=5,
        window_seconds=60
    )

    assert len(alerts) == 1
    assert alerts[0]["distinct_ports"] == 5


def test_port_scan_alert_records_block_and_allow_actions():
    events = [
        create_firewall_event("2026-11-10T10:00:01", 22, action="BLOCK"),
        create_firewall_event("2026-11-10T10:00:02", 80, action="BLOCK"),
        create_firewall_event("2026-11-10T10:00:03", 443, action="ALLOW"),
        create_firewall_event("2026-11-10T10:00:04", 3389, action="BLOCK"),
        create_firewall_event("2026-11-10T10:00:05", 8080, action="ALLOW")
    ]

    alerts = detect_port_scan(events)

    assert len(alerts) == 1
    assert alerts[0]["actions"] == ["ALLOW", "BLOCK"]
