"""
PhishHawk Riderect Chain Tracer
Passively traces URL redirect chains and logs each hop
"""

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from dataclasses import dataclass, field

@dataclass
class Hop:
    """A single hop in a riderect chain"""
    url: str = ""
    status_code: int = 0
    server: str = ""
    location: str = ""

@dataclass
class RedirectChainResult:
    """Structured redirect chain data for a URL"""
    query: str = ""
    hops: list = field(default_factory=list)
    final_url: str = ""
    total_hops: int = 0
    error: str = ""

class RedirectChainTracer:
    """Passively traces URL redirect chains"""

    def __init__(self, max_hops=10, timeout: int = 10):
        self.max_hops = max_hops
        self.timeout = timeout

    def trace(self, url: str) -> RedirectChainResult:
        """Trace redirect chain for a URL"""
        result = RedirectChainResult(query=url)

        try:
            session = requests.Session()
            session.max_redirects = self.max_hops

            response = session.get(
                url,
                allow_redirects=True,
                timeout=self.timeout,
                headers={"User-Agent": "Mozilla/5.0"},
                verify=False
            )

            for r in response.history:
                hop = Hop(
                    url=r.url,
                    status_code=r.status_code,
                    server=r.headers.get("Server", ""),
                    location=r.headers.get("Location", "")
                )
                result.hops.append(hop)

            result.hops.append(Hop(
                url=response.url,
                status_code=response.status_code,
                server=response.headers.get("Server", ""),
                location=""
            ))

            result.final_url = response.url
            result.total_hops = len(result.hops)
        
        except Exception as e:
            result.error = str(e)

        return result 