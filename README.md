# LogSentry – Log Analysis & Attack Timeline Reconstruction

LogSentry is a Python-based security investigation platform that analyzes
system, authentication, web server, and firewall logs to identify suspicious
activity and reconstruct potential attack timelines.

## Project Objectives

- Parse Apache access, Linux authentication, and firewall logs.
- Detect brute-force login attempts.
- Identify possible port scanning activity.
- Detect suspicious web path requests.
- Correlate related security events.
- Reconstruct chronological incident timelines.
- Map relevant detections to MITRE ATT&CK.
- Present investigation results through a Streamlit dashboard.
- Generate JSON and PDF investigation reports.

## Technology Stack

- Python 3.12
- Streamlit
- Pytest
- ReportLab
- Regular Expressions
- JSON
- Git and GitHub

## Project Scope

LogSentry is a local, educational SIEM-style investigation tool.
It uses synthetic or authorized log data and applies rule-based detection.

Alerts indicate suspicious activity requiring investigation. They do not
independently prove that a system has been compromised.

## Project Status

Phase 0 – Environment and project foundation: In progress.

## Intended Audience

Cybersecurity learners, security analysts, and technical evaluators.

## Disclaimer

This project is intended for defensive security analysis and educational use.
Only analyze logs that you are authorized to access.
