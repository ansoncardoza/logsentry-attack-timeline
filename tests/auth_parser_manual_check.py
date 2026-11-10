
from pathlib import Path

from src.parsers.auth_parser import parse_auth_log


log_file = Path("data/raw/auth.log")

with log_file.open("r", encoding="utf-8-sig") as file:
    for line_number, line in enumerate(file, start=1):
        try:
            parsed = parse_auth_log(line)

            print(f"\nLog entry {line_number}")
            print(parsed)

        except ValueError as error:
            print(f"Log entry {line_number} failed: {error}")
