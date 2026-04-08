"""
PhishHawk DNS Lookup
Retrieves DNS records for domains
"""

import dns.resolver
from dataclasses import dataclass, field

@dataclass
class DnsResult:
    """Structured DNS data for a domain"""
    query: str = ""
    a_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    error: str = ""

class DnsLookup:
    """Performs DNS lookups against domains"""

    RECORD_TYPES = ['A', 'MX', 'TXT', 'NS']

    def lookup(self, domain: str) -> DnsResult:
        """Look up DNS records for a domain"""
        result = DnsResult(query=domain)

        for record_type in self.RECORD_TYPES:
            self._query_record(result, record_type, result)
        
        return result
    
    def _query_record(self, domain: str, record_type: str, result: DnsResult):
        """Query a single DNS record type and store in result"""
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = [str(r) for r in answers]

            if record_type == 'A':
                result.a_records = records
            elif record_type == 'MX':
                result.mx_records = records
            elif record_type == 'TXT':
                result.txt_records = records
            elif record_type == 'NS':
                result.ns_records = records

        except Exception as e:
            if not result.error:
                result.error = f"{record_type}: {str(e)}"

                