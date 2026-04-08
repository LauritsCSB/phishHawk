"""
PhishHawk AbuseIPDB Lookup
Retrieves abuse reports and confidence scores for IP addresses
"""

import requests
from dataclasses import dataclass

@dataclass
class AbuseIPDBResult:
    """Structured AbuseIPDB data for an IP address"""
    query: str = ""
    abuse_score: int = 0
    total_reports: int = 0
    country: str = ""
    isp: str = ""
    domain: str = ""
    is_tor: bool = False
    error: str = ""

class AbuseIPDBLookup:
    """Performs IP reputation lookups via AbuseIPDB"""

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup(self, ip: str) -> AbuseIPDBResult:
        """Look up abuse reports for an IP address"""
        result = AbuseIPDBResult(query=ip)
        
        try:
            response = requests.get(
                self.BASE_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10
            )
            response.raise_for_status()
            data = response.json().get("data", {})
        
            result.abuse_score = data.get("abuseConfidenceScore", 0)
            result.total_reports = data.get("totalReports", 0)
            result.country = data.get("countryCode", "")
            result.isp = data.get("isp", "")
            result.domain = data.get("domain", "")
            result.is_tor = data.get("isTor", False)

        except Exception as e:
            result.error = str(e)

        return result

    