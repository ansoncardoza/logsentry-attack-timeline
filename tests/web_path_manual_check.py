
from src.parsers.apache_parser import parse_apache_log
from src.detection.web_path_detector import detect_suspicious_web_paths


log_file = "data/raw/apache_access.log"

apache_events = []

# Parse the original Apache access log.
with open(log_file, "r", encoding="utf-8-sig") as file:
    for line in file:
        if line.strip():
            try:
                event = parse_apache_log(line)
                apache_events.append(event)
            except ValueError as error:
                print(f"Skipping invalid log entry: {error}")


# Run suspicious web path detection.
alerts = detect_suspicious_web_paths(apache_events)

print("\nLOGSENTRY – SUSPICIOUS WEB PATH DETECTION")
print("=" * 50)

print(f"Apache events analyzed: {len(apache_events)}")
print(f"Security alerts generated: {len(alerts)}")

for alert in alerts:
    print("\nALERT DETAILS")
    print("-" * 50)

    for key, value in alert.items():
        print(f"{key}: {value}")
