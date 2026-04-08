"""
PhishHawk crt.sh Lookup
Retrieves certificate transparecncy logs for domains
"""

import requests
from dataclasses import dataclass, field

@dataclass
class CrtshResult:
    """Structured certificate transparency data for domain"""
    query: str = ""
    subdomains: list[str] = field(default_factory=list)
    certificates: list[dict] = field(default_factory=list)
    error: str = ""

class CrtshLookup:
    """Performs certificate transparency lookups via crt.sh"""

    BASE_URL = "https://crt.sh/"

    def lookup(self, domain: str) -> CrtshResult:
        """Lookup certificate transparency logs for a domain"""
        result = CrtshResult(query=domain)
        
        try:
            response = requests.get(
                self.BASE_URL,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            for cert in data:
                name = cert.get("name_value", "")
                issued = cert.get("not_before", "")
                issuer = cert.get("issuer_name", "")

                result.certificates.append({
                    "name": name,
                    "issued": issued,
                    "issuer": issuer
                })

                for subdomain in name.splitlines():
                    subdomain = subdomain.strip()
                    if subdomain and subdomain not in result.subdomains:
                        result.subdomains.append(subdomain)
        
        except Exception as e:
            result.error = str(e)
        
        return result