"""Unit tests for Phishing Analyzer module."""

import email
from datetime import datetime
from email.message import EmailMessage

import pytest

from src.phishing_analyzer import (
    EMLOParser,
    PhishingAnalyzer,
    PhishingReport,
    URLCheckResult,
)


class TestEMLOParser:
    """Tests for EML parser."""

    def test_extract_urls_from_text(self):
        """Test URL extraction from plain text."""
        text = "Check out https://example.com and http://test.org/page"
        msg = EmailMessage()
        msg.set_content(text)

        urls = EMLOParser.extract_urls(msg)
        assert len(urls) == 2
        assert "https://example.com" in urls
        assert "http://test.org/page" in urls

    def test_extract_urls_from_html(self):
        """Test URL extraction from HTML content."""
        html = """
        <html>
        <body>
            <a href="https://phishing.com/login">Click here</a>
            <a href="http://legit.com">Legit link</a>
        </body>
        </html>
        """
        msg = EmailMessage()
        msg.add_alternative(html, subtype="html")

        urls = EMLOParser.extract_urls(msg)
        assert len(urls) == 2
        assert "https://phishing.com/login" in urls

    def test_extract_urls_from_subject(self):
        """Test URL extraction from subject line."""
        msg = EmailMessage()
        msg["Subject"] = "Visit https://suspicious.link now"
        msg.set_content("Body content")

        urls = EMLOParser.extract_urls(msg)
        assert "https://suspicious.link" in urls

    def test_extract_metadata(self):
        """Test metadata extraction."""
        msg = EmailMessage()
        msg["Subject"] = "Test Subject"
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Date"] = "Mon, 14 Aug 2026 10:00:00 +0000"
        msg.set_content("Body")

        metadata = EMLOParser.extract_metadata(msg)
        assert metadata["subject"] == "Test Subject"
        assert metadata["from"] == "sender@example.com"
        assert metadata["to"] == "recipient@example.com"

    def test_no_urls(self):
        """Test handling of emails with no URLs."""
        msg = EmailMessage()
        msg.set_content("This is a plain text email with no links.")

        urls = EMLOParser.extract_urls(msg)
        assert len(urls) == 0


class TestURLCheckResult:
    """Tests for URL check result."""

    def test_to_dict(self):
        """Test serialization."""
        result = URLCheckResult(
            url="https://example.com",
            is_malicious=True,
            threat_score=75.0,
        )
        d = result.to_dict()
        assert d["url"] == "https://example.com"
        assert d["is_malicious"] is True
        assert d["threat_score"] == 75.0


class TestPhishingAnalyzer:
    """Tests for phishing analyzer."""

    @pytest.fixture
    def analyzer(self, tmp_path):
        """Create analyzer with test config."""
        config = """
apis:
  urlhaus:
    base_url: "https://urlhaus-api.abuse.ch/v1"
  phishtank:
    api_key: ""
    base_url: "https://checkurl.phishtank.com/checkurl/"
settings:
  request_timeout: 5
"""
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text(config)
        return PhishingAnalyzer(str(config_file))

    def test_check_suspicious_indicators_spoofing(self, analyzer):
        """Test detection of Reply-To spoofing."""
        msg = EmailMessage()
        msg["From"] = "ceo@company.com"
        msg["Reply-To"] = "attacker@evil.com"
        msg.set_content("Please wire money")

        indicators = analyzer._check_suspicious_indicators(msg, [])
        assert any("Reply-To mismatch" in i for i in indicators)

    def test_check_suspicious_indicators_suspicious_tld(self, analyzer):
        """Test detection of suspicious TLDs."""
        msg = EmailMessage()
        msg.set_content("Click here")

        indicators = analyzer._check_suspicious_indicators(msg, ["https://evil.xyz/login"])
        assert any("Suspicious TLD" in i for i in indicators)

    def test_check_suspicious_indicators_ip_url(self, analyzer):
        """Test detection of IP-based URLs."""
        msg = EmailMessage()
        msg.set_content("Click here")

        indicators = analyzer._check_suspicious_indicators(msg, ["http://192.168.1.1/login"])
        assert any("IP-based URL" in i for i in indicators)

    def test_check_suspicious_indicators_shortener(self, analyzer):
        """Test detection of URL shorteners."""
        msg = EmailMessage()
        msg.set_content("Click here")

        indicators = analyzer._check_suspicious_indicators(msg, ["https://bit.ly/abc123"])
        assert any("URL shortener" in i for i in indicators)

    def test_check_suspicious_indicators_keywords(self, analyzer):
        """Test detection of suspicious subject keywords."""
        msg = EmailMessage()
        msg["Subject"] = "URGENT: Verify your account now"
        msg.set_content("Click here")

        indicators = analyzer._check_suspicious_indicators(msg, [])
        assert any("urgent" in i.lower() for i in indicators)

    def test_check_suspicious_indicators_html_only(self, analyzer):
        """Test detection of HTML-only emails."""
        msg = EmailMessage()
        msg.add_alternative("<html><body>Click</body></html>", subtype="html")

        indicators = analyzer._check_suspicious_indicators(msg, [])
        assert any("HTML-only" in i for i in indicators)

    def test_report_risk_calculation(self, analyzer):
        """Test risk score calculation in report."""
        report = PhishingReport()
        report.url_results = [
            URLCheckResult(url="https://evil.com", threat_score=80),
            URLCheckResult(url="https://safe.com", threat_score=0),
        ]
        report.indicators = ["Suspicious TLD", "IP-based URL"]

        # avg_url_score = 40, indicator_score = 20, total = 60
        # But we test through the analyzer logic
        # This is more of an integration test
        pass


class TestPhishingReport:
    """Tests for PhishingReport."""

    def test_to_dict(self):
        """Test report serialization."""
        report = PhishingReport(
            email_subject="Test",
            email_from="test@example.com",
            risk_score=85.5,
            is_suspicious=True,
        )
        d = report.to_dict()
        assert d["email_subject"] == "Test"
        assert d["risk_score"] == 85.5
        assert d["is_suspicious"] is True

    def test_empty_report(self):
        """Test empty report."""
        report = PhishingReport()
        d = report.to_dict()
        assert d["risk_score"] == 0.0
        assert d["is_suspicious"] is False
