
## HorusEye - Log Parser ##

## Auto-detects and parses log formats into structured entries. ## 


import re
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from utils import parse_timestamp


def detect_log_format(path: str) -> Optional[str]:
    try:
        with open(path, "r") as file:
            lines = [file.readline() for _ in range(5)]
    except FileNotFoundError:
        return None

    patterns = {
        "auth.log": re.compile(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:"),
        "apache": re.compile(r"^\S+ \S+ \S+ \[.+?\] \".+?\" \d+ \d+"),
        "json": None  # special handling
    }

    for name, pattern in patterns.items():
        if name != "json" and any(pattern.match(line) for line in lines):
            return name
        if name == "json" and any(is_json(line) for line in lines):
            return "json"

    return None


def is_json(line: str) -> bool:
    try:
        json.loads(line)
        return True
    except json.JSONDecodeError:
        return False


def parse_auth_log(path: str) -> List[Dict[str, Any]]:
    entries = []
    regex = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w.-]+)\s+([\w./-]+)(?:\[(\d+)\])?:\s+(.*)$"
    )
    ip_matcher = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    year = datetime.now().year

    with open(path, "r") as file:
        for line in file:
            match = regex.match(line)
            if not match:
                continue

            ts_raw, host, proc, pid, msg = match.groups()
            ts = parse_timestamp(ts_raw, year)
            ip = ip_matcher.search(msg)

            entries.append({
                "timestamp": ts,
                "source_ip": ip.group(0) if ip else "N/A",
                "raw_log": line.strip(),
                "log_type": "auth.log"
            })

    return entries


def parse_apache_log(path: str) -> List[Dict[str, Any]]:
    entries = []
    regex = re.compile(r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+ \S+ \S+)" (\d+) (\d+|-)')

    with open(path, "r") as file:
        for line in file:
            match = regex.match(line)
            if not match:
                continue

            ip, ts_str, req, status, size = match.groups()

            try:
                ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                ts = None

            entries.append({
                "timestamp": ts,
                "source_ip": ip,
                "raw_log": line.strip(),
                "log_type": "apache"
            })

    return entries


def parse_json_log(path: str) -> List[Dict[str, Any]]:
    entries = []

    with open(path, "r") as file:
        for line in file:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts_raw = data.get("timestamp")
            ts = None

            if ts_raw:
                try:
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except ValueError:
                    pass

            entries.append({
                "timestamp": ts,
                "source_ip": data.get("source_ip", "N/A"),
                "raw_log": line.strip(),
                "log_type": "json",
                "parsed_json": data
            })

    return entries

