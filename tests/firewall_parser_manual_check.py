
from src.parsers.firewall_parser import parse_firewall_log


log_file = "data/raw/firewall.log"

with open(log_file, "r", encoding="utf-8") as file:
    lines = file.readlines()


print("\nFIREWALL LOG PARSER RESULTS")
print("=" * 50)

for number, line in enumerate(lines, start=1):
    try:
        result = parse_firewall_log(line)
        print(f"\nLog entry {number}")
        print(result)

    except ValueError as error:
        print(f"\nLog entry {number} failed: {error}")
