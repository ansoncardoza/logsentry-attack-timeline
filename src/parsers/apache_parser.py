
import re
from datetime import datetime


APACHE_LOG_PATTERN = re.compile(
    r'(?P<source_ip>\S+) '
    r'\S+ '
    r'\S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) '
    r'(?P<path>\S+) '
    r'(?P<protocol>HTTP/\d\.\d)" '
    r'(?P<status_code>\d{3}) '
    r'(?P<response_size>\d+|-)'
)


def parse_apache_log(line):
    """
    Parse one Apache access log entry.

    Returns a dictionary containing structured log fields.
    Raises ValueError if the log entry is malformed.
    """

    match = APACHE_LOG_PATTERN.match(line.strip())

    if not match:
        raise ValueError("Invalid Apache access log format")

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(
            data["timestamp"],
            "%d/%b/%Y:%H:%M:%S %z"
        )
    except ValueError as error:
        raise ValueError("Invalid Apache timestamp") from error

    response_size = data["response_size"]

    return {
        "source_ip": data["source_ip"],
        "timestamp": timestamp.isoformat(),
        "method": data["method"],
        "path": data["path"],
        "protocol": data["protocol"],
        "status_code": int(data["status_code"]),
        "response_size": (
            int(response_size) if response_size != "-" else None
        )
    }
