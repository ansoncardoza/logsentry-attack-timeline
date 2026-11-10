
from src.parsers.auth_parser import parse_auth_log
from src.detection.brute_force_detector import detect_brute_force


log_file = "data/raw/auth.log"

auth_events = []

# Parse the original authentication log.
with open(log_file, "r", encoding="utf-8-sig") as file:
    for line in file:
        if line.strip():
            try:
                event = parse_auth_log(line)
                auth_events.append(event)
            except ValueError as error:
                print(f"Skipping invalid log entry: {error}")


# Run brute-force detection.
alerts = detect_brute_force(auth_events)

print("\nLOGSENTRY – SSH BRUTE-FORCE DETECTION")
print("=" * 50)

print(f"Authentication events analyzed: {len(auth_events)}")
print(f"Security alerts generated: {len(alerts)}")

for alert in alerts:
    print("\nALERT DETAILS")
    print("-" * 50)

    for key, value in alert.items():
        print(f"{key}: {value}")
