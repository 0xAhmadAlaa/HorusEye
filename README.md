# HorusEye - Security Log Analysis Tool

HorusEye is a Python-based security log analysis tool designed to monitor, detect, and report suspicious activities from various log sources. It can identify Indicators of Compromise (IOCs) and enrich them with external threat intelligence.

## Features

*   **Log Parsing**: Supports `auth.log` (SSH, sudo), Apache access logs, and generic JSON logs.
*   **Rule-Based Detection**: Identifies suspicious patterns using customizable rules (keywords or regex) with thresholds and time windows.
*   **IOC Extraction & Enrichment**: Extracts IP addresses, domains, and file hashes, and enriches them using AbuseIPDB and VirusTotal APIs.
*   **Alerting**: Sends alerts to console , email, and Slack.
*   **Reporting**: Generates comprehensive incident reports in Markdown and JSON formats, including MITRE ATT&CK mappings and remediation recommendations.
*   **Real-time Monitoring**: Continuously monitors log files for new entries.

## Project Structure

```
HorusEye/
├── main.py             # Main orchestration script
├── parser.py           # Log parsing module
├── detector.py         # Rule engine and detection logic
├── ioc_extractor.py    # IOC extraction and enrichment
├── alert.py            # Alerting module
├── reporter.py         # Report generation
├── utils.py            # Helper functions
├── config.yaml         # Configuration file
├── requirements.txt    # Python dependencies
├── logs/               # Directory for log files 
│   
├── rules/              # Directory for detection rules
│   └── rules.json
├── testss/              # Directory for pytest unit tests
│   
└── reports/            # Directory for generated reports
    
```

## Setup and Installation
look here This document covers how to test **all parts** of HorusEye: parser, detector, IOC extractor, reporter, real-time monitoring, configuration, and unit tests.

[View test details](test.md)


## Configuration

The `config.yaml` file is central to configuring HorusEye. You **MUST** update this file with your specific settings, especially your API keys for threat intelligence enrichment.

```yaml
log_file_path: logs/auth.log
rules_file_path: rules/rules.json
report_output_path: reports/incident_report
realtime_mode: False
realtime_interval_seconds: 5

api_keys:
  abuseipdb: ABUSEIPDB_API_KEY  # Replace with your AbuseIPDB API key
  virustotal: VIRUSTOTAL_API_KEY # Replace with your VirusTotal API key

alerting:
  email:
    enabled: False
    to_email: email@any.com
    smtp_server: smtp.any.com
    smtp_port: 587
    smtp_user: your_smtp_user
    smtp_pass: your_smtp_password
  slack:
    enabled: False
    webhook_url: YOUR_SLACK_WEBHOOK_URL # Replace with your actual Slack webhook URL
```

### API Key Configuration

To enable full IOC enrichment, you need API keys for AbuseIPDB and VirusTotal:

*   **AbuseIPDB**: Register at [https://www.abuseipdb.com/](https://www.abuseipdb.com/) to obtain your API key. Replace `ABUSEIPDB_API_KEY` in `config.yaml`.
*   **VirusTotal**: Register at [https://www.virustotal.com/](https://www.virustotal.com/) to obtain your API key. Replace `VIRUSTOTAL_API_KEY` in `config.yaml`.



### Alerting Configuration

If you wish to receive email or Slack alerts, enable them in `config.yaml` and provide the necessary details (e.g., SMTP server settings for email, webhook URL for Slack).

## Usage

HorusEye can be run in two primary modes: one-time scan or real-time monitoring.

### One-Time Scan

To perform a one-time scan of a log file and generate reports:

```bash
python main.py -l logs/auth.log -r rules/rules.json -o reports/incident_report
```

*   `-l <log_file_path>`: Path to the log file to analyze.
*   `-r <rules_file_path>`: Path to the JSON file containing detection rules.
*   `-o <output_base_path>`: Base path for the generated Markdown and JSON reports.

### Real-time Monitoring

To continuously monitor a log file for new entries:

```bash
python main.py --config config.yaml --realtime
```

*   `--config <config_file_path>`: (Optional) Path to your `config.yaml` file. Defaults to `config.yaml`.
*   `--realtime`: Activates real-time monitoring mode.

In real-time mode, HorusEye will periodically check the specified log file for new lines and process them. You can adjust the `realtime_interval_seconds` in `config.yaml`.

## Providing Real Log Data

HorusEye is designed to work with your actual system logs. You can place your log files (`/var/log/auth.log`) into the `logs/` directory or specify their absolute paths using the `-l` argument. Ensure the user running HorusEye has read permissions for these log files.

## Customizing Detection Rules

Detection rules are defined in `rules/rules.json`. You can modify existing rules or add new ones to tailor HorusEye to your specific security monitoring needs. Each rule defines:

*   `name`: A descriptive name for the rule.
*   `log_type`: The type of log the rule applies to (e.g., `auth.log`, `apache`, `json`).
*   `pattern_type`: Either `keyword` or `regex`.
*   `pattern`: The keyword or regular expression to match.
*   `threshold`: The number of occurrences within `window_seconds` to trigger a detection.
*   `window_seconds`: The time window (in seconds) for thresholding (optional).
*   `priority`: The severity of the alert (e.g., `high`, `medium`, `low`).
*   `enabled`: `true` or `false` to enable/disable the rule.
*   `mitre_attack`: Corresponding MITRE ATT&CK ID (optional).

Example `rules.json`:

```json
[
  {
    "name": "SSH Brute Force",
    "log_type": "auth.log",
    "pattern_type": "keyword",
    "pattern": "Failed password",
    "threshold": 5,
    "window_seconds": 60,
    "priority": "high",
    "enabled": true,
    "mitre_attack": "T1110.001"
  },
  {
    "name": "Successful SSH Login",
    "log_type": "auth.log",
    "pattern_type": "keyword",
    "pattern": "Accepted password",
    "threshold": 1,
    "priority": "medium",
    "enabled": true,
    "mitre_attack": "T1078"
  }
]
```

## Testing with pytest testss/test_parser.py

HorusEye includes unit tests for its core modules (`parser.py`, `detector.py`, `ioc_extractor.py`) using `pytest`. It is highly recommended to run these tests to ensure the integrity and correctness of the codebase, especially after making modifications.

### Installation

First, ensure `pytest` is installed in your virtual environment:

```bash
pip install pytest
```

### Running Tests

To run all tests, navigate to the project root directory and execute:

```bash
pytest
```

To run tests for a specific module (e.g., `parser.py`):

```bash
pytest tests/test_parser.py
```

## Contributing

Fork, tweak, submit PRs. Issues welcome!

## License

MIT License. Built by [0xAhmadAlaa](https://github.com/0xAhmadAlaa).