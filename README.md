# LogSentry – Log Analysis & Attack Timeline Reconstruction

**LogSentry** is a Python-based security log analysis and investigation platform designed to identify suspicious activity, correlate security alerts, reconstruct chronological attack timelines, and map relevant detections to the MITRE ATT&CK framework.

It provides a local Streamlit dashboard and generates JSON and PDF investigation reports.

## Project Overview

Security teams investigate activity across different log sources, including authentication systems, web servers, and firewalls. Examining these records separately can make it difficult to identify suspicious patterns and understand the sequence of events.

LogSentry addresses this challenge through rule-based log parsing, security detection, event correlation, timeline reconstruction, and investigation reporting.

## Key Features

- **Log Parsing:** Processes Apache access logs, Linux authentication logs, and UFW firewall logs.
- **Brute-Force Detection:** Identifies repeated failed SSH authentication attempts within a configurable threshold.
- **Port-Scan Detection:** Identifies activity involving multiple destination ports within a defined time window.
- **Web Path Reconnaissance Detection:** Identifies requests for multiple potentially sensitive web paths.
- **Event Correlation:** Groups related alerts using source IP addresses and time windows.
- **Attack Timeline Reconstruction:** Organizes correlated events chronologically.
- **MITRE ATT&CK Mapping:** Associates recognized detections with relevant ATT&CK techniques.
- **Streamlit Dashboard:** Provides an interactive interface for reviewing alerts, parsed logs, incidents, timelines, and ATT&CK mappings.
- **Investigation Reports:** Exports analysis results as JSON and PDF files.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.12 | Core application and analysis engine |
| Regular Expressions | Log parsing |
| Streamlit | Interactive dashboard |
| Pandas | Tabular data presentation |
| ReportLab | PDF report generation |
| JSON | Data exchange and investigation reports |
| Pytest | Automated testing |
| Git and GitHub | Version control and project collaboration |

## Project Architecture

```text
LogSentry/
├── config/
├── dashboard/
│   └── app.py
├── data/
│   ├── raw/
│   │   ├── auth.log
│   │   ├── apache_access.log
│   │   └── firewall.log
│   ├── processed/
│   └── scenarios/
├── docs/
│   └── log-formats.md
├── reports/
│   ├── logsentry_report.json
│   └── logsentry_report.pdf
├── src/
│   ├── parsers/
│   ├── detection/
│   ├── correlation/
│   ├── timeline/
│   ├── mitre/
│   ├── reporting/
│   └── analysis_pipeline.py
├── tests/
├── requirements.txt
└── README.md
```

## Detection Methodology

LogSentry uses rule-based detection rather than machine learning.

| Detection | Detection logic | MITRE ATT&CK reference |
|---|---|---|
| SSH Brute Force | Five or more failed SSH login attempts from one source IP within 60 seconds by default | T1110.001 – Password Guessing |
| Possible Port Scan | Five or more distinct destination ports accessed from one source IP to one destination IP within 60 seconds by default | T1046 – Network Service Discovery |
| Possible Web Path Reconnaissance | Three or more distinct suspicious web paths requested from one source IP within 60 seconds by default | T1595.003 – Wordlist Scanning |

Detection thresholds can be configured through the analysis pipeline.

These mappings provide behavioral context. They do not independently establish attacker identity, intent, or successful compromise.

## Installation and Setup

### Prerequisites

- Windows, Linux, or macOS
- Python 3.12 recommended
- Git
- Internet access for installing Python dependencies

### 1. Clone the repository

```bash
git clone https://github.com/ansoncardoza/logsentry-attack-timeline.git
cd logsentry-attack-timeline
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
```

Linux/macOS:

```bash
python3 -m venv .venv
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Run the integrated analysis pipeline

```bash
python -m src.analysis_pipeline
```

The pipeline parses the available sample logs, runs the detection rules, correlates alerts, and produces investigation results.

### 5. Launch the dashboard

```bash
python -m streamlit run dashboard/app.py
```

Open the local URL displayed in the terminal, normally:

```text
http://localhost:8501
```

The dashboard provides:

- Overview
- Security Alerts
- Incident Investigation
- Attack Timeline
- MITRE ATT&CK
- Parsed Logs

JSON and PDF report downloads are available from the dashboard sidebar.

### 6. Run automated tests

```bash
python -m pytest -v
```

The project currently has **101 passing automated tests** covering parsers, detection rules, correlation, timeline reconstruction, ATT&CK mapping, the integrated pipeline, and report generation.

## Sample Data and Demonstration

The repository includes synthetic sample logs in `data/raw/`:

- `auth.log` – Linux SSH authentication activity.
- `apache_access.log` – Apache web server requests.
- `firewall.log` – UFW firewall events.

The current sample data contains:

| Log source | Records |
|---|---:|
| Authentication | 7 |
| Apache | 7 |
| Firewall | 6 |
| **Total** | **20** |

The sample analysis produces three medium-severity alerts:

1. Possible SSH brute-force activity from `203.0.113.50`.
2. Possible port scanning from `203.0.113.70`.
3. Possible web path reconnaissance from `203.0.113.60`.

The sample produces zero correlated incidents because the three detections have different source IP addresses. LogSentry deliberately keeps them separate rather than assuming they represent the same actor.

The IP addresses used in these examples belong to documentation-only address ranges and are synthetic.

## Investigation Reports

LogSentry generates:

- `reports/logsentry_report.json`
- `reports/logsentry_report.pdf`

Reports contain analysis metadata, event summaries, security alerts, MITRE ATT&CK mappings, and incident investigation results.

The PDF report also includes an executive summary and investigation limitations.

## Security Considerations and Limitations

- Alerts indicate potentially suspicious activity; they do not prove compromise.
- Source IP addresses do not necessarily identify individual users or devices.
- NAT gateways, proxies, and shared networks can complicate event correlation.
- Missing, incomplete, or incorrectly timestamped logs can affect analysis.
- Detection rules may produce false positives or miss activity outside their defined patterns.
- MITRE ATT&CK mappings provide context, not proof of malicious behavior.
- The application analyzes supplied logs and is not a real-time monitoring or enterprise SIEM platform.

Only synthetic logs or records that you are authorized to access should be analyzed.

## Project Status

**Core implementation and quality assurance completed.**

Implemented components include log parsers, rule-based detection, event correlation, timeline reconstruction, MITRE ATT&CK mapping, an interactive dashboard, and JSON/PDF reporting.

The latest full automated regression run completed with **101 tests passed**.

Documentation and final project presentation are being prepared for the internship evaluation.

## Intended Audience

- Cybersecurity students and learners
- Aspiring SOC analysts
- Junior security analysts
- Internship evaluators
- Defensive security practitioners

## Disclaimer

LogSentry is an educational defensive security project intended to support log analysis and investigation workflows. Its findings should be validated against additional authorized evidence before drawing conclusions.
