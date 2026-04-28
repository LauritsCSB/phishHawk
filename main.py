"""
PhishHawk - Phishing Analysis Pipeline
"""

import argparse
from pathlib import Path

from src.phishhawk.parser.eml_parser import EmlParser
from src.phishhawk.enrichment.whois_lookup import WhoisLookup
from src.phishhawk.enrichment.dns_lookup import DnsLookup
from src.phishhawk.enrichment.crtsh_lookup import CrtshLookup
from src.phishhawk.output.raw_output import RawOutput

def main():
    parser = argparse.ArgumentParser(
        description="PhishHawk - Phishing Analysis Pipeline"
    )
    parser.add_argument("eml", help="Path to .eml file")
    args = parser.parse_args()

    eml_path = Path(args.eml)
    if not eml_path.exists():
        print(f"Error: file not found: {eml_path}")
        return

    print(f"\n🦅 PhishHawk — analysing {eml_path.name}\n")

    # Parse
    print("→ Parsing email...")
    eml_parser = EmlParser()
    parsed = eml_parser.parse(eml_path)

    print(f"    Subject:    {parsed.subject}")
    print(f"    Sender:     {parsed.sender}")
    print(f"    IPs:        {parsed.ips}")
    print(f"    Domains:    {parsed.domains}")
    print(f"    URLs:       {parsed.urls[:3]}{'...' if len(parsed.urls) > 3 else ''}")

    # Enrich
    enrichment = {}

    if parsed.domains:
        doamain = parsed.domains[0]
        print(f"\n→ Enriching {doamain}...")

        print(" whois...")
        enrichment["whois"] = WhoisLookup().lookup(doamain)

        print(" dns...")
        enrichment["dns"] = DnsLookup().lookup(doamain)

        print(" crtsh...")
        enrichment["crtsh"] = CrtshLookup().lookup(doamain)

    # Output
    print("\n→ Exporting results...")
    output = RawOutput()
    json_path = output.export_json(parsed, enrichment)
    csv_path = output.export_csv(parsed)
    ioc_path = output.export_ioc_list(parsed)

    print(f"    JSON: {json_path}")
    print(f"    CSV:  {csv_path}")
    print(f"    IOC:  {ioc_path}")
    print("\n✅ Done\n")

if __name__ == "__main__":
    main() 