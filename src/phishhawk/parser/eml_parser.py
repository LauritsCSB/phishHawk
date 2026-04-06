"""
PhishHawk EML Parser
Extracts IOC's from .eml files (headers and body)
"""

import email
import re
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class ParsedEmail:
    """Structured representation from a parsed .eml file"""
    subject: str = ""
    sender: str = ""
    reply_to: str = ""
    recipient: str = ""
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    recieved_headers: list[str] = field(default_factory=list)
    raw_headears: dict = field(default_factory=dict)

class EmlParser:
    """Parses .eml files and extracts IOCs"""

    IP_REGEX = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )

    URL_REGEX = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )

    DOMAIN_REGEX = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}\b'
    )

    def parse(self, path: str | Path) -> ParsedEmail:
        """Parse a .eml file and return extracted IOCs"""
        raw = Path(path).read_text(encoding='utf-8', errors='replace')
        msg = email.message_from_string(raw)
        result = ParsedEmail()

        self._extract_headers(msg, result)
        self._extract_body(msg, result)
        self._depublicize(result)

        return result
    
    def _extract_headers(self, msg, result: ParsedEmail):
        """Extract IOCs from email headers"""
        result.subject = msg.get("Subject", "")
        result.sender = msg.get("From", "")
        result.reply_to = msg.get("Reply-To", "")
        result.recipient = msg.get("To", "")
        result.recieved_headers = msg.get_all("Received") or []

        #Store all headers for reference
        result.raw_headears = dict(msg.items())

        #Extract IPs from Received headers
        for received in result.received_headers:
            result.ips += self.IP_REGEX.findall(received)

        #Extract IP from X-Originating-IP header if present
        x_orig = msg.get("X-Originating-IP", "")
        if x_orig:
            result.ips += self.IP_REGEX.findall(x_orig)
        
        #Extract domain from sender
        if sender_domain := self._extract_domain_from_adress(result.reply_to):
            result.domains.append(sender_domain)

        if reply_domain := self._extract_domain_from_adress(result.reply_to):
            result.domains.append(reply_domain)
    
    def _extract_body(self, msg, result: ParsedEmail):
        """Extract IOCs from email body"""
        body = self._get_body(msg)

        result.urls = self.URL_REGEX.findall(body)

        #Extract domains from URLs
        for url in result.urls:
            if domains := self.DOMAIN_REGEX.findall(url):
                result.domains += domains
    
    def _get_body(self, msg) -> str:
        """Extract plain text and HTML body from email"""
        body_parts = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_parts.append(payload.decode("utf-8", errors="replace"))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_parts.append(payload.decode("utf-8", errors="replace"))

        return "\n".join(body_parts)
    
    def _extract_domain_from_address(self, address: str) -> str:
        """Extract domain from email address like 'Name <user@domain.com>'"""
        match = re.search(r'@([\w\.\-]+)', address)
        return match.group(1) if match else ""
    
    def _depublicate(self, result: ParsedEmail):
        """Remove duplicate IOCs while preserving order"""
        result.ips = list(dict.fromkeys(result.ips))
        result.domains = list(dict.fromkeys(result.domains))
        result.urls = list(dict.fromkeys(result.urls))