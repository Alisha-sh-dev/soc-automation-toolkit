"""
Phishing Analyzer Module

Extracts URLs from .eml email files, checks them against URLhaus
and PhishTank databases, and generates threat reports.
"""

import email
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Optional

import requests
import yaml


@dataclass
class URLCheckResult:
    """Result of checking a single URL against threat databases."""
    url: str
    is_malicious: bool = False
    is_phishing: bool = False
    threat_score: float = 0.0
    sources: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "is_malicious": self.is_malicious,
            "is_phishing": self.is_phishing,
            "threat_score": round(self.threat_score, 2),
            "sources": self.sources,
            "errors": self.errors,
        }


@dataclass
class PhishingReport:
    """Comprehensive phishing analysis report."""
    email_subject: str = ""
    email_from: str = ""
    email_to: str = ""
    date: str = ""
    extracted_urls: list[str] = field(default_factory=list)
    url_results: list[URLCheckResult] = field(default_factory=list)
    risk_score: float = 0.0
    is_suspicious: bool = False
    indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "email_subject": self.email_subject,
            "email_from": self.email_from,
            "email_to": self.email_to,
            "date": self.date,
            "extracted_urls": self.extracted_urls,
            "url_results": [r.to_dict() for r in self.url_results],
            "risk_score": round(self.risk_score, 2),
            "is_suspicious": self.is_suspicious,
            "indicators": self.indicators,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON."""
        return json.dumps(self.to_dict(), indent=indent)


class EMLOParser:
    """Parser for .eml email files."""

    # URL regex pattern
    URL_PATTERN = re.compile(
        r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
        re.IGNORECASE
    )

    @classmethod
    def parse_file(cls, filepath: str) -> EmailMessage:
        """
        Parse an .eml file into an EmailMessage.

        Args:
            filepath: Path to the .eml file.

        Returns:
            Parsed EmailMessage object.
        """
        path = Path(filepath)
        with open(path, "rb") as f:
            msg = email.message_from_binary_file(f)
        return msg

    @classmethod
    def extract_urls(cls, msg: EmailMessage) -> list[str]:
        """
        Extract all URLs from an email message.

        Args:
            msg: The email message to parse.

        Returns:
            List of unique URLs found in the email.
        """
        urls = set()

        # Extract from subject
        subject = msg.get("Subject", "")
        urls.update(cls.URL_PATTERN.findall(subject))

        # Extract from body
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ("text/plain", "text/html"):
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            text = payload.decode("utf-8", errors="ignore")
                            urls.update(cls.URL_PATTERN.findall(text))
                    except Exception:
                        continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    text = payload.decode("utf-8", errors="ignore")
                    urls.update(cls.URL_PATTERN.findall(text))
            except Exception:
                pass

        # Clean and deduplicate
        cleaned = []
        for url in urls:
            # Remove trailing punctuation
            url = url.rstrip(".,;:!?)")
            # Normalize
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme and parsed.netloc:
                cleaned.append(url)

        return list(set(cleaned))

    @classmethod
    def extract_metadata(cls, msg: EmailMessage) -> dict[str, str]:
        """
        Extract metadata from email.

        Args:
            msg: The email message.

        Returns:
            Dictionary with email metadata.
        """
        return {
            "subject": msg.get("Subject", ""),
            "from": msg.get("From", ""),
            "to": msg.get("To", ""),
            "date": msg.get("Date", ""),
            "reply_to": msg.get("Reply-To", ""),
            "return_path": msg.get("Return-Path", ""),
        }


class URLChecker:
    """
    Checks URLs against threat intelligence sources.

    Args:
        config_path: Path to configuration YAML.
    """

    def __init__(self, config_path: str = "config.yaml") -> None:
        """Initialize URL checker."""
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.timeout = self.config["settings"]["request_timeout"]

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for API queries."""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def check_urlhaus(self, url: str) -> dict[str, Any]:
        """
        Check URL against URLhaus database.

        Args:
            url: The URL to check.

        Returns:
            Dictionary with URLhaus results.
        """
        urlhaus_config = self.config["apis"]["urlhaus"]
        base_url = urlhaus_config["base_url"]

        try:
            response = requests.post(
                f"{base_url}/url",
                data={"url": url},
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()

            result = {"source": "urlhaus", "found": False}

            if data.get("query_status") == "ok":
                result["found"] = True
                result["threat"] = data.get("threat", "")
                result["tags"] = data.get("tags", [])
                result["url_status"] = data.get("url_status", "")
                result["date_added"] = data.get("date_added", "")

            return result
        except requests.exceptions.RequestException as e:
            return {"source": "urlhaus", "error": str(e)}

    def check_phishtank(self, url: str) -> dict[str, Any]:
        """
        Check URL against PhishTank database.

        Args:
            url: The URL to check.

        Returns:
            Dictionary with PhishTank results.
        """
        phishtank_config = self.config["apis"]["phishtank"]
        api_key = phishtank_config.get("api_key", "")
        base_url = phishtank_config["base_url"]

        if api_key == "YOUR_PHISHTANK_API_KEY":
            # PhishTank allows limited queries without API key
            api_key = ""

        try:
            # PhishTank uses URL-encoded POST data
            params = {
                "url": url,
                "format": "json",
                "app_key": api_key,
            }

            response = requests.post(
                base_url,
                data=params,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()

            result = {"source": "phishtank", "found": False}

            if data.get("results", {}).get("valid") == "true":
                result["found"] = True
                result["verified"] = data["results"].get("verified", "")
                result["verified_at"] = data["results"].get("verified_at", "")
                result["phish_detail_page"] = data["results"].get("phish_detail_page", "")

            return result
        except requests.exceptions.RequestException as e:
            return {"source": "phishtank", "error": str(e)}

    def check_url(self, url: str) -> URLCheckResult:
        """
        Check a URL against all configured sources.

        Args:
            url: The URL to check.

        Returns:
            URLCheckResult with aggregated findings.
        """
        result = URLCheckResult(url=url)

        # Check URLhaus
        urlhaus_result = self.check_urlhaus(url)
        if "error" not in urlhaus_result:
            result.sources["urlhaus"] = urlhaus_result
            if urlhaus_result.get("found"):
                result.is_malicious = True
                result.threat_score += 50
        else:
            result.errors.append(f"URLhaus: {urlhaus_result['error']}")

        # Check PhishTank
        phishtank_result = self.check_phishtank(url)
        if "error" not in phishtank_result:
            result.sources["phishtank"] = phishtank_result
            if phishtank_result.get("found"):
                result.is_phishing = True
                result.threat_score += 50
        else:
            result.errors.append(f"PhishTank: {phishtank_result['error']}")

        result.threat_score = min(100, result.threat_score)

        return result


class PhishingAnalyzer:
    """
    Main analyzer for phishing emails.

    Args:
        config_path: Path to configuration YAML.
    """

    def __init__(self, config_path: str = "config.yaml") -> None:
        """Initialize the phishing analyzer."""
        self.url_checker = URLChecker(config_path)

    def _check_suspicious_indicators(self, msg: EmailMessage, urls: list[str]) -> list[str]:
        """
        Check for common phishing indicators.

        Args:
            msg: The email message.
            urls: Extracted URLs.

        Returns:
            List of detected indicators.
        """
        indicators = []

        # Check for display name spoofing
        from_header = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        if reply_to and reply_to != from_header:
            indicators.append(f"Reply-To mismatch: From={from_header}, Reply-To={reply_to}")

        # Check for suspicious TLDs
        suspicious_tlds = ".tk|.ml|.ga|.cf|.top|.xyz|.click|.link"
        for url in urls:
            if re.search(suspicious_tlds, url, re.IGNORECASE):
                indicators.append(f"Suspicious TLD in URL: {url}")

        # Check for IP-based URLs
        for url in urls:
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                indicators.append(f"IP-based URL detected: {url}")

        # Check for URL shorteners
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link"]
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            if any(s in parsed.netloc.lower() for s in shorteners):
                indicators.append(f"URL shortener detected: {url}")

        # Check for suspicious keywords in subject
        subject = msg.get("Subject", "").lower()
        suspicious_keywords = [
            "urgent", "verify", "suspend", "account", "login", "password",
            "bank", "payment", "invoice", "security alert", "unusual activity",
        ]
        for keyword in suspicious_keywords:
            if keyword in subject:
                indicators.append(f"Suspicious keyword in subject: '{keyword}'")
                break

        # Check for HTML-only content (common in phishing)
        if msg.is_multipart():
            has_text = any(
                part.get_content_type() == "text/plain"
                for part in msg.walk()
            )
            has_html = any(
                part.get_content_type() == "text/html"
                for part in msg.walk()
            )
            if has_html and not has_text:
                indicators.append("HTML-only email (no plain text alternative)")

        return indicators

    def analyze(self, filepath: str) -> PhishingReport:
        """
        Analyze an .eml file for phishing indicators.

        Args:
            filepath: Path to the .eml file.

        Returns:
            PhishingReport with analysis results.
        """
        report = PhishingReport()

        # Parse email
        msg = EMLOParser.parse_file(filepath)
        metadata = EMLOParser.extract_metadata(msg)

        report.email_subject = metadata["subject"]
        report.email_from = metadata["from"]
        report.email_to = metadata["to"]
        report.date = metadata["date"]

        # Extract URLs
        report.extracted_urls = EMLOParser.extract_urls(msg)

        # Check indicators
        report.indicators = self._check_suspicious_indicators(msg, report.extracted_urls)

        # Check each URL
        for url in report.extracted_urls:
            url_result = self.url_checker.check_url(url)
            report.url_results.append(url_result)

            if url_result.is_malicious or url_result.is_phishing:
                report.is_suspicious = True

        # Calculate overall risk score
        if report.url_results:
            avg_url_score = sum(r.threat_score for r in report.url_results) / len(report.url_results)
        else:
            avg_url_score = 0

        indicator_score = min(len(report.indicators) * 10, 50)
        report.risk_score = min(100, avg_url_score + indicator_score)

        if report.risk_score >= 50:
            report.is_suspicious = True

        return report
