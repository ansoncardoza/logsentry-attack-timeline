
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
