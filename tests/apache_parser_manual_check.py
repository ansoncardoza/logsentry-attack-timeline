
from pathlib import Path

from src.parsers.apache_parser import parse_apache_log


log_file = Path("data/raw/apache_access.log")

with log_file.open("r", encoding="utf-8-sig") as file:
    for line_number, line in enumerate(file, start=1):
        try:
            parsed = parse_apache_log(line)
            print(f"\nLog entry {line_number}")
            print(parsed)

        except ValueError as error:
            print(f"Log entry {line_number} failed: {error}")