import argparse
import logging
import os
import time
import yaml
from typing import Dict, Any, List, Optional

from parser import detect_log_format, parse_auth_log, parse_apache_log, parse_json_log
from detector import load_rules, detect_events, RuleError
from ioc_extractor import extract_ips, extract_domains, extract_hashes
from alert import send_console_alert, send_email, send_slack_alert
from reporter import generate_markdown_report, generate_json_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

ASCII_BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⣤⣶⠾⠿⠿⠿⠿⢶⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣤⠾⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠻⠷⣶⣤⣤⣤⣀⣀⣀⣀⣀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠀⠀
⠀⠀⠀⠀⣠⡾⢛⣽⣿⣿⣏⠙⠛⠻⠷⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀
⠀⠀⢠⣾⣋⡀⢸⣿⣿⣿⣿⠀⠀⢀⣀⣤⣽⡿⠿⠛⠿⠿⠷⠾⠿⠿⠛⠋⠀⠀
⠀⠀⠻⠛⠛⠻⣶⣽⣿⣿⣿⡶⠿⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣿⡏⠻⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣶⠶⢶⣤⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢹⣯⠁⠀⠈⠛⢷⣤⡀⠀⠀⠀⠀⠀⠀⠀⠸⠧⠀⠀⢹⡇⠀⠀
⠀⠀⠀⠀⠀⠀⠈⣿⠀⠀⠀⠀⠀⠉⠻⠷⣦⣤⣤⣀⣀⣀⣀⣠⣤⡶⠟⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
HorusEye - Developed by 0xAhmadAlaa
"""


class ConfigError(Exception):
    pass


def load_config(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f)
    except (IOError, yaml.YAMLError) as e:
        raise ConfigError(f"Failed to load config {path}: {e}")


def parse_logs(path: str, log_type: Optional[str]) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        logging.error(f"Log file not found: {path}")
        return []

    if not log_type:
        log_type = detect_log_format(path) or "auth.log"
        logging.info(f"Detected log type: {log_type}")

    parser_map = {
        "auth.log": parse_auth_log,
        "apache": parse_apache_log,
        "json": parse_json_log
    }

    parser_func = parser_map.get(log_type)
    if not parser_func:
        logging.error(f"Unsupported log type: {log_type}")
        return []

    return parser_func(path)


def analyze(logs: List[Dict[str, Any]], rules: List[Dict[str, Any]], config: Dict[str, Any], output_base: str):
    detections = detect_events(logs, rules)

    api_keys = config.get("api_keys", {})
    iocs = {
        "ips": extract_ips(logs, api_keys.get("abuseipdb")),
        "domains": extract_domains(logs),
        "hashes": extract_hashes(logs, api_keys.get("virustotal"))
    }

    for det in detections:
        send_console_alert(f"Rule: {det['rule_name']} | Priority: {det['priority']} | Count: {det['count']}", priority=det["priority"])
        if det.get("mitre_attack"):
            send_console_alert(f"MITRE ATT&CK: {det['mitre_attack']}")

        # Optional alerts via email/slack
        if config.get("alerting", {}).get("email", {}).get("enabled"):
            email_cfg = config["alerting"]["email"]
            send_email(
                subject=f"HorusEye Alert: {det['rule_name']}",
                body=f"Detection: {det['rule_name']}\nLogs: {det['matching_logs']}",
                **email_cfg
            )

        if config.get("alerting", {}).get("slack", {}).get("enabled"):
            send_slack_alert(
                msg=f"HorusEye Alert: {det['rule_name']} - Count: {det['count']}",
                webhook_url=config["alerting"]["slack"]["webhook_url"]
            )

    generate_markdown_report(detections, iocs, f"{output_base}.md")
    generate_json_report(detections, iocs, f"{output_base}.json")


def main():
    print(ASCII_BANNER)

    parser = argparse.ArgumentParser(description="HorusEye CLI tool")
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("-l", "--log")
    parser.add_argument("-r", "--rules")
    parser.add_argument("-o", "--output")
    parser.add_argument("--log-type")
    parser.add_argument("--realtime", action="store_true")

    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except ConfigError as err:
        logging.critical(err)
        return

    log_path = args.log or config.get("log_file_path")
    rules_path = args.rules or config.get("rules_file_path")

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    base_output = args.output or config.get("report_output_path", "reports/incident_report")
    output_path = f"{base_output}_{timestamp}"
    
    log_type = args.log_type
    realtime = args.realtime or config.get("realtime_mode", False)

    if not log_path or not os.path.exists(log_path):
        logging.critical("Missing or invalid log file path.")
        return
    if not rules_path or not os.path.exists(rules_path):
        logging.critical("Missing or invalid rules file.")
        return

    try:
        rules = load_rules(rules_path)
    except RuleError as err:
        logging.critical(f"Rule loading failed: {err}")
        return

    if realtime:
        logging.info(f"Watching {log_path} in real-time...")

        if not os.path.exists(log_path):
            logging.critical("Log file not found.")
            return

        with open(log_path, "r") as f:
            f.seek(0, os.SEEK_END)  # Skip existing logs

            while True:
                new_lines = f.readlines()
                if new_lines:
                    with open("/tmp/horuseye_live.log", "w") as tmp:
                        tmp.writelines(new_lines)
                    logs = parse_logs("/tmp/horuseye_live.log", log_type)
                    analyze(logs, rules, config, output_path)

                time.sleep(config.get("realtime_interval_seconds", 5))
    else:
        logs = parse_logs(log_path, log_type)
        analyze(logs, rules, config, output_path)

    logging.info("Done.")


if __name__ == "__main__":
    main()
