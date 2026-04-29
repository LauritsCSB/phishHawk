"""
PhishHawk Iterative IOC Enrichment
Rercursively enriches newly discovered IOCs up to a configurable max depth
"""

from dataclasses import dataclass, field
from src.phishhawk.parser.eml_parser import ParsedEmail
from src.phishhawk.enrichment.whois_lookup import WhoisLookup
from src.phishhawk.enrichment.dns_lookup import DnsLookup
from src.phishhawk.enrichment.crtsh_lookup import CrtshLookup
from src.phishhawk.enrichment.redirect_chain import RedirectChainTracer

@dataclass
class EnrichmentResults:
    """Holds all enrichment results across all depths"""
    whois: dict = field(default_factory=dict)
    dns: dict = field(default_factory=dict)
    crtsh: dict = field(default_factory=dict)
    redirect_chains: dict = field(default_factory=dict)

class IterativeEnricher:
    """Enriches IOCs recursively up to a max_depth"""

    def __init__(self, max_depth=2):
        self.max_depth = max_depth
        self.whois = WhoisLookup()
        self.dns = DnsLookup()
        self.crtsh = CrtshLookup()
        self.tracer = RedirectChainTracer()
    
    def enrich(self, parsed: ParsedEmail) -> EnrichmentResults:
        """Run iterative enrichment on all IOCs from parsed email"""
        results = EnrichmentResults()
        
        # Seen sets - prevent infinite loops
        seen_domains = set()
        seen_ips = set()
        seen_urls = set()

        # Initial queues from parser
        domain_queue = list(parsed.domains)
        ip_queue = list(parsed.ips)
        url_queue = list(parsed.urls)

        for depth in range(self.max_depth + 1):
            if not any([domain_queue, ip_queue, url_queue]):
                break

            print(f"\n  [depth {depth}] enriching {len(domain_queue)} domain(s), "
                  f"{len(ip_queue)} IP(s), {len(url_queue)} URL(s)...")
            
            new_domains = set()
            new_ips = set()
            new_urls = set()

            # Enrich domains
            for domain in domain_queue:
                if domain in seen_domains:
                    continue
                seen_domains.add(domain)

                print(f"   whois: {domain}")
                results.whois[domain] = self.whois.lookup(domain)

                print(f"   dns: {domain}")
                dns_result = self.dns.lookup(domain)
                results.dns[domain] = self.dns.lookup(domain)

                print(f"   crtsh: {domain}")
                crtsh_result = self.crtsh.lookup(domain)
                results.crtsh[domain] = self.crtsh.lookup(domain)

                # Harvest IOCs from DNS results
                new_ips.update(dns_result.a_records)

                # Harvest new domains from crtsh subdomains
                new_domains.update(crtsh_result.subdomains)

            # Enrich IPs
            for ip in ip_queue:
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                # AbuseIPDB og URLScan to be added here in M2/M3

            # Enrich URLs
            for url in url_queue:
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                print(f"   redirect: {url[:60]}")
                chain_result = self.tracer.trace(url)
                results.redirect_chains[url] = chain_result

                # Harvest final URL as new domain
                if chain_result.final_url and chain_result.final_url != url:
                    new_urls.add(chain_result.final_url)

            # Build next iteration queues - only unseen IOCs
            domain_queue = list(new_domains - seen_domains)
            ip_queue = list(new_ips - seen_ips)
            url_queue = list(new_urls - seen_urls)

        return results