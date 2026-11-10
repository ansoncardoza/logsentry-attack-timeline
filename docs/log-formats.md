# LogSentry – Security Log Fundamentals

## 1. Authentication Logs

Source: Linux SSH authentication logs.

Important fields:
- Timestamp
- Hostname
- SSH process ID
- Authentication result
- Username
- Source IP address
- Source port

Investigation objective:
Identify repeated failed authentication attempts.

Detection scenario:
Five failed login attempts from the same source IP within
a defined time window may indicate brute-force activity.

MITRE ATT&CK reference: T1110 – Brute Force.

## 2. Apache Access Logs

Source: Apache HTTP server access logs.

Important fields:
- Client IP address
- Timestamp
- HTTP method
- Requested path
- HTTP response status
- Response size

Investigation objective:
Identify suspicious requests to sensitive paths.

Detection scenario:
Repeated requests for paths such as /.env, /admin,
and /wp-config.php may indicate web reconnaissance.

Possible MITRE ATT&CK reference:
T1595 – Active Scanning.

## 3. Firewall Logs

Source: Linux UFW firewall logs.

Important fields:
- Timestamp
- Source IP address (SRC)
- Destination IP address (DST)
- Protocol (PROTO)
- Source port (SPT)
- Destination port (DPT)
- Firewall action

Investigation objective:
Identify repeated connection attempts against
different destination ports.

Detection scenario:
Multiple distinct destination ports targeted by the
same source IP within a short time window may indicate
port scanning.

Possible MITRE ATT&CK references:
T1595 – Active Scanning.
T1046 – Network Service Discovery.

## 4. Investigation Principles

- Preserve original log files.
- Treat alerts as indicators requiring investigation.
- Do not equate failed requests with successful access.
- Correlate timestamps, IP addresses, and usernames.
- Record evidence separately from analytical conclusions.
- Use only synthetic or authorized log data.

## 5. Important Limitations

A log entry alone rarely proves compromise.

Missing logs, clock differences, incomplete records,
and shared IP addresses can affect investigation accuracy.
