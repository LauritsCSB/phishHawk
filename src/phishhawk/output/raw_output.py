"""
PhishHawk Raw Output Module
Exports enriched IOC data to JSON, CSV, and defanged IOC list
"""

import json
import csv
from dataclasses import asdict
from pathlib import Path
from datetime import datetime

from src.phishhawk.parser.eml_parser import ParsedEmail
from src.phishhawk.enrichment.whois_lookup import WhoisResult
from src.phishhawk.enrichment.dns_lookup import DnsResult
from src.phishhawk.enrichment.crtsh_lookup import CrtshResult
from src.phishhawk.enrichment.abuseipdb_lookup import AbuseIPDBResult
from src.phishhawk.enrichment.urlscan_lookup import URLScanResult

class RawOutput:
    """Exports enriched IOC data to various formats"""

    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _timestamp(self) -> str:
        """Generate a timestamp for filenames"""
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def _defang(self, value: str) -> str:
        """Defang a URL, IP or domain to make it safe for sharing"""
        return (
            value
            .replace("http://", "hxxp://")
            .replace("https://", "hxxps://")
            .replace(".", "[.]")
        )
    
    def export_json(self, parsed: ParsedEmail, enrichment: dict):
        """Export all IOC data to a JSON file"""
        timestamp = self._timestamp()
        output_path = self.output_dir / f"phishhawk_report_{timestamp}.json"

        data = {
            "metadata": {
                "generated": timestamp,
                "tool": "PhishHawk",
            },
            "email": asdict(parsed),
            "enrichment": {
                key: asdict(value) 
                for key, value in enrichment.items()
            }
        }

        output_path.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8"
        )

        return output_path
    
    def export_csv(self, parsed: ParsedEmail) -> Path:
        """Export extracted IOCs to a CSV file"""
        timestamp = self._timestamp()
        output_path = self.output_dir / f"phishhawk_{timestamp}.csv"

        rows = []

        for ip in parsed.ips:
            rows.append({"type": "IP", "value": ip, "defanged": self._defang(ip)})

        for domain in parsed.domains:
            rows.append({"type": "Domain", "value": domain, "defanged": self._defang(domain)})

        for url in parsed.urls:
            rows.append({"type": "URL", "value": url, "defanged": self._defang(url)})

        with output_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["type", "value", "defanged"])
            writer.writeheader()
            writer.writerows(rows)

        return output_path
    
    def export_ioc_list(self, parsed: ParsedEmail) -> Path:
        """Export defanged IOC list as plain text"""
        timestamp = self._timestamp()
        output_path = self.output_dir / f"phishhawk_{timestamp}_iocs.txt"

        lines = []

        lines.append("# PhishHawk IOC List")
        lines.append(f"# Generated: {timestamp}")
        lines.append("")

        lines.append("# IPs")
        for ip in parsed.ips:
            lines.append(self._defang(ip))

        lines.append("")
        lines.append("# Domains")
        for domain in parsed.domains:
            lines.append(self._defang(domain))

        lines.append("")
        lines.append("# URLs")
        for url in parsed.urls:
            lines.append(self._defang(url))

        output_path.write_text("\n".join(lines), encoding="utf-8")

        return output_path