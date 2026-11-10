
import re
from datetime import datetime


AUTH_LOG_PATTERN = re.compile(
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) '
    r'(?P<hostname>\S+) '
    r'sshd\[(?P<process_id>\d+)\]: '
    r'(?P<result>Accepted|Failed) '
    r'(?P<method>\S+) '
    r'for '
    r'(?:(?P<invalid_user>invalid user) )?'
    r'(?P<username>\S+) '
    r'from (?P<source_ip>\S+) '
    r'port (?P<source_port>\d+) '
    r'ssh2'
)


def parse_auth_log(line, year=2026):
    """
    Parse one Linux SSH authentication log entry.

    Returns structured authentication information.
    Raises ValueError if the entry is malformed.
    """

    match = AUTH_LOG_PATTERN.fullmatch(line.strip())

    if not match:
        raise ValueError("Invalid authentication log format")

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(
            data["timestamp"],
            "%b %d %H:%M:%S"
        ).replace(year=year)

    except ValueError as error:
        raise ValueError("Invalid authentication timestamp") from error

    return {
        "timestamp": timestamp.isoformat(),
        "hostname": data["hostname"],
        "process_id": int(data["process_id"]),
        "result": data["result"],
        "method": data["method"],
        "username": data["username"],
        "invalid_user": data["invalid_user"] is not None,
        "source_ip": data["source_ip"],
        "source_port": int(data["source_port"])
    }
