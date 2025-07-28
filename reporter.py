
## HorusEye - Report Generator ##

## Generates Markdown and JSON reports based on detections and IOCs. ##

import json
import os
from typing import List, Dict, Any
from datetime import datetime


def generate_markdown_report(
    detections: List[Dict[str, Any]],
    iocs: Dict[str, Any],
    output_path: str
):
    lines = [f"# Incident Report - {datetime.now():%Y-%m-%d %H:%M:%S}\n"]

    # Detections Section
    if detections:
        lines.append("## Detections\n")
        for d in detections:
            lines.append(f"### Rule Triggered: {d['rule_name']}")
            lines.append(f"- **Priority**: {d['priority'].upper()}")
            lines.append(f"- **Count**: {d['count']}")
            lines.append(f"- **MITRE ATT&CK**: {d.get('mitre_attack', 'N/A')}")
            lines.append("- **Matching Logs:**")
            for log in d["matching_logs"]:
                timestamp = log["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(log["timestamp"], datetime) else str(log["timestamp"])
                lines.append(f"  - `{log['raw_log']}` (Timestamp: {timestamp})")
            lines.append("")
    else:
        lines.append("## No Detections Found\n")

    # IOCs Section
    lines.append("## Indicators of Compromise (IOCs)\n")
    if iocs.get("ips"):
        lines.append("### IP Addresses")
        for ip in iocs["ips"]:
            lines.append(f"- `{ip['ip']}`")
            for src, data in ip.get("enrichment", {}).items():
                lines.append(f"  - Enrichment ({src}): {json.dumps(data, indent=2)}")
    if iocs.get("domains"):
        lines.append("### Domains")
        for domain in iocs["domains"]:
            lines.append(f"- `{domain}`")
    if iocs.get("hashes"):
        lines.append("### Hashes")
        for h in iocs["hashes"]:
            lines.append(f"- `{h['hash']}`")
            for src, data in h.get("enrichment", {}).items():
                lines.append(f"  - Enrichment ({src}): {json.dumps(data, indent=2)}")

    # Recommendations
    lines += [
        "\n## Recommendations",
        "- Review matched logs and IOCs.",
        "- Block malicious IPs/domains at perimeter devices.",
        "- Update SIEM and firewall rules.",
        "- Conduct deeper forensic analysis if needed."
    ]

    with open(output_path, "a") as file:
        file.write("\n".join(lines))

    print(f"[+] Markdown report written to: {output_path}")


def generate_json_report(
    detections: List[Dict[str, Any]],
    iocs: Dict[str, Any],
    output_path: str
):
    report = {
        "generated_at": datetime.now().isoformat(),
        "detections": [],
        "iocs": iocs,
        "recommendations": [
            "Review matched logs and IOCs.",
            "Block malicious IPs/domains at perimeter devices.",
            "Update SIEM and firewall rules.",
            "Conduct deeper forensic analysis if needed."
        ]
    }

    for d in detections:
        clean_logs = []
        for log in d["matching_logs"]:
            item = dict(log)
            if isinstance(item.get("timestamp"), datetime):
                item["timestamp"] = item["timestamp"].isoformat()
            clean_logs.append(item)

        report["detections"].append({
            "rule_name": d["rule_name"],
            "priority": d["priority"],
            "count": d["count"],
            "mitre_attack": d.get("mitre_attack", "N/A"),
            "matching_logs": clean_logs
        })

    
    existing_reports = []
    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as file:
                existing_reports = json.load(file)
        except Exception:
            existing_reports = []

    
    existing_reports.append(report)


    with open(output_path, "w") as file:
        json.dump(existing_reports, file, indent=2)

    print(f"[+] JSON report written to: {output_path}")
