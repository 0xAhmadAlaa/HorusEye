
## HorusEye - IOC Extractor ##

## Extracts and optionally enriches IPs, domains, and hashes. ## 


import re
import requests
from typing import List, Dict, Any, Optional


class IOCExtractorError(Exception):
    pass


def extract_ips(logs: List[Dict[str, Any]], abuseipdb_key: Optional[str] = None) -> List[Dict[str, Any]]:
    ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    seen = set()
    results = []

    for log in logs:
        for ip in ip_regex.findall(log["raw_log"]):
            if ip in seen:
                continue
            seen.add(ip)
            entry = {"ip": ip, "enrichment": {}}

            if abuseipdb_key:
                try:
                    r = requests.get(
                        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                        headers={"Key": abuseipdb_key, "Accept": "application/json"},
                        timeout=5,
                    )
                    r.raise_for_status()
                    entry["enrichment"]["abuseipdb"] = r.json().get("data", {})
                except requests.RequestException as err:
                    print(f"[!] Failed AbuseIPDB for {ip}: {err}")

            results.append(entry)

    return results


def extract_domains(logs: List[Dict[str, Any]]) -> List[str]:
    domain_regex = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b")
    found = set()

    for log in logs:
        for d in domain_regex.findall(log["raw_log"]):
            if not re.match(r"\d+\.\d+\.\d+\.\d+", d):
                found.add(d)

    return sorted(found)


def extract_hashes(logs: List[Dict[str, Any]], virustotal_key: Optional[str] = None) -> List[Dict[str, Any]]:
    hash_regex = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
    seen = set()
    results = []

    for log in logs:
        for h in hash_regex.findall(log["raw_log"]):
            if h in seen:
                continue
            seen.add(h)
            entry = {"hash": h, "enrichment": {}}

            if virustotal_key:
                try:
                    r = requests.get(
                        f"https://www.virustotal.com/api/v3/files/{h}",
                        headers={"x-apikey": virustotal_key, "Accept": "application/json"},
                        timeout=5,
                    )
                    r.raise_for_status()
                    entry["enrichment"]["virustotal"] = r.json().get("data", {})
                except requests.RequestException as err:
                    print(f"[!] Failed VirusTotal for {h}: {err}")

            results.append(entry)

    return results

