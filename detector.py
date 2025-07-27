
## HorusEye - Detector Module ## s

## Loads detection rules and matches them against parsed logs. ##


import json
import yaml
import re
from datetime import timedelta
from typing import List, Dict, Any

class RuleError(Exception):
    pass


def load_rules(path: str) -> List[Dict[str, Any]]:
    """
    Load and validate detection rules from JSON or YAML.
    """
    try:
        with open(path, "r") as f:
            rules = json.load(f) if path.endswith(".json") else yaml.safe_load(f)
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as err:
        raise RuleError(f"Could not load rule file: {err}")

    valid_rules = []
    for rule in rules:
        if not all(k in rule for k in ("name", "log_type", "pattern_type", "pattern", "threshold", "priority", "enabled")):
            raise RuleError(f"Missing keys in rule: {rule.get('name', 'unknown')}")

        if rule["pattern_type"] not in ("keyword", "regex"):
            raise RuleError(f"Invalid pattern_type in rule: {rule['name']}")

        if not isinstance(rule["enabled"], bool):
            raise RuleError(f"'enabled' must be boolean: {rule['name']}")

        if rule["enabled"]:
            valid_rules.append(rule)

    return valid_rules


def detect_events(logs: List[Dict[str, Any]], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run detection rules on parsed logs.
    """
    detections = []

    for rule in rules:
        matches = []

        for log in logs:
            if log["log_type"] != rule["log_type"]:
                continue

            log_line = log["raw_log"]

            if rule["pattern_type"] == "keyword" and rule["pattern"] in log_line:
                matches.append(log)
            elif rule["pattern_type"] == "regex" and re.search(rule["pattern"], log_line):
                matches.append(log)

        if len(matches) < rule["threshold"]:
            continue

        if rule.get("window_seconds"):
            first = matches[0]["timestamp"]
            last = matches[-1]["timestamp"]
            delta = timedelta(seconds=rule["window_seconds"])

            if last - first > delta:
                continue

        detections.append({
            "rule_name": rule["name"],
            "count": len(matches),
            "matching_logs": matches,
            "priority": rule["priority"],
            "mitre_attack": rule.get("mitre_attack", "N/A")
        })

    return detections

