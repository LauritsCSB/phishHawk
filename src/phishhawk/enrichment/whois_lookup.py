"""
PhishHawk WHOIS Lookup
Retrieves registration data for domains and IPs
"""

import whois
from dataclasses import dataclass, field

@dataclass
class WhoisResult:
    """Structured WHOIS data for domain or IP"""
    query: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    country: str = ""
    name_servers: list[str] = field(default_factory=list)
    raw: str = ""
    error: str = ""

class WhoisLookup:
    """Peforms WJOIS lookups against domains and IPs"""

    def lookup(self, query: str) -> WhoisResult:
        """Look up WHOIS data for a domain or IP"""
        result = WhoisResult(query=query)
        
        try:
            w = whois.whois(query)

            result.registrar = str(w.registrar or "")
            result.creation_date = str(w.creation_date or "")
            result.expiration_date = str(w.expiration_date or "")
            result.country = str(w.country or "")
            result.name_servers = w.name_servers or []
            result.raw = str(w)

        except Exception as e:
            result.error = str(e)

        return result