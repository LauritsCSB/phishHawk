"""
PhishHawk - Phishing Analysis Pipeline
"""

import argparse
from pathlib import Path

from src.phishhawk.parser.eml_parser import EmlParser
from src.phishhawk.enrichment.iterative_enricher import IterativeEnricher
from src.phishhawk.output.raw_output import RawOutput

def main():
    parser = argparse.ArgumentParser(
        description="PhishHawk - Phishing Analysis Pipeline"
    )
    parser.add_argument("eml", help="Path to the .eml file")
    parser.add_argument(
        "--output",
        default="./reports",
        help="Output directory for reports (default: ./reports)"
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Max enrchment depth (default: 2)"
    )
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

    print(f"  Subject:  {parsed.subject}")
    print(f"  Sender:   {parsed.sender}")
    print(f"  IPs:      {parsed.ips}")
    print(f"  Domains:  {parsed.domains}")
    print(f"  URLs:     {parsed.urls[:3]}{'...' if len(parsed.urls) > 3 else ''}")

    # Iterative enrichment
    print(f"\n→ Starting iterative enrichment (max depth: {args.depth})...")
    enricher = IterativeEnricher(max_depth=args.depth)
    enrichment = enricher.enrich(parsed)

    # Output
    print("\n→ Exporting results...")
    output = RawOutput(output_dir=args.output)
    json_path = output.export_json(parsed, {
        "whois": enrichment.whois,
        "dns": enrichment.dns,
        "crtsh": enrichment.crtsh,
        "redirect_chains": enrichment.redirect_chains,
    })
    csv_path = output.export_csv(parsed)
    ioc_path = output.export_ioc_list(parsed)

    print(f"  JSON:     {json_path}")
    print(f"  CSV:      {csv_path}")
    print(f"  IOC list: {ioc_path}")
    print("\n✅ Done\n")


if __name__ == "__main__":
    main()    