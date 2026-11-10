
import re
from datetime import datetime


FIREWALL_LOG_PATTERN = re.compile(
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) '
    r'(?P<hostname>\S+) '
    r'kernel: \[UFW (?P<action>BLOCK|ALLOW)\] '
    r'IN=(?P<interface>\S+) '
    r'OUT=\S* '
    r'SRC=(?P<source_ip>\S+) '
    r'DST=(?P<destination_ip>\S+) '
    r'PROTO=(?P<protocol>\S+) '
    r'SPT=(?P<source_port>\d+) '
    r'DPT=(?P<destination_port>\d+)'
)


def parse_firewall_log(line, year=2026):
    """
    Parse one UFW firewall log entry.

    Returns structured firewall information.
    Raises ValueError if the entry is malformed.
    """

    match = FIREWALL_LOG_PATTERN.fullmatch(line.lstrip("\ufeff").strip())

    if not match:
        raise ValueError("Invalid firewall log format")

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(
            data["timestamp"],
            "%b %d %H:%M:%S"
        ).replace(year=year)

    except ValueError as error:
        raise ValueError("Invalid firewall timestamp") from error

    return {
        "timestamp": timestamp.isoformat(),
        "hostname": data["hostname"],
        "action": data["action"],
        "interface": data["interface"],
        "source_ip": data["source_ip"],
        "destination_ip": data["destination_ip"],
        "protocol": data["protocol"],
        "source_port": int(data["source_port"]),
        "destination_port": int(data["destination_port"])
    }
