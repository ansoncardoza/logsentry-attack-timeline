
from src.parsers.firewall_parser import parse_firewall_log
from src.detection.port_scan_detector import detect_port_scan


log_file = "data/raw/firewall.log"

firewall_events = []

# Parse the original firewall log.
with open(log_file, "r", encoding="utf-8-sig") as file:
    for line in file:
        if line.strip():
            try:
                event = parse_firewall_log(line)
                firewall_events.append(event)
            except ValueError as error:
                print(f"Skipping invalid log entry: {error}")


# Run port-scan detection.
alerts = detect_port_scan(firewall_events)

print("\nLOGSENTRY – PORT-SCAN DETECTION")
print("=" * 50)

print(f"Firewall events analyzed: {len(firewall_events)}")
print(f"Security alerts generated: {len(alerts)}")

for alert in alerts:
    print("\nALERT DETAILS")
    print("-" * 50)

    for key, value in alert.items():
        print(f"{key}: {value}")
