"""
PhishHawk URLScan Lookup
Submits URLs for scanning and retrieves analysis results
"""

from time import time
import requests
from dataclasses import dataclass, field

@dataclass
class URLScanResult:
    """Structured URLScan data for a URL"""
    query: str = ""
    scan_id: str = ""
    screenshot_url: str = ""
    final_url: str = ""
    ip: str = ""
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    malicious: bool = False
    error: str = ""

class URLScanLookup:
    """Submits URLs to URLScan.io and retrieves results"""

    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def lookup(self, url: str) -> URLScanResult:
        """Submit a URL for scanning and return results"""
        result = URLScanResult(query=url)
        
        try:
            scan_id = self._submit(url)
            if not scan_id:
                result.error = "Failed to submit URL for scanning"
                return result
            
            result.scan_id = scan_id
            time.sleep(10)
            self._fetch_results(scan_id, result)

        except Exception as e:
            result.error = str(e)

        return result
    
    def _submit(self, url: str) -> str:
        """Submit a URL to URLScan.io for scanning"""
        response = requests.post(
            f"{self.BASE_URL}/scan/",
            headers={
                "API-Key": self.api_key,
                "Content-Type": "application/json"
            },
            json={"url": url, "visibility": "private"},
            timeout=10
        )
        response.raise_for_status()
        return response.json().get("uuid", "")
    
    def _fetch_results(self, scan_id: str, result: URLScanResult):
        """Fetch scan results from URLScan.io"""
        response = requests.get(
            f"{self.BASE_URL}/result/{scan_id}/",
            timeout=10
        )
        response.raise_for_status()
        data = response.json()

        page = data.get("page", {})
        verdicts = data.get("verdicts", {})
        meta = data.get("meta", {})

        result.final_url = page.get("url", "")
        result.ip = page.get("ip", "")
        result.server = page.get("server", "")
        result.screenshot_url = f"https://urlscan.io/screenshots/{scan_id}.png"
        result.malicious = verdicts.get("overall", {}).get("malicious", False)
        result.technologies = [
            tech.get("name", "") 
            for tech in meta.get("processors", {})
            .get("wappa", {})
            .get("data", [])
        ]