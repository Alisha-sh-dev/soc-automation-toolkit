"""Unit tests for IOC Enricher module."""

import pytest

from src.ioc_enricher import IOCEnricher, IOCType, RiskLevel, EnrichmentResult


class TestIOCClassification:
    """Tests for IOC type classification."""

    def test_classify_ipv4(self):
        """Test IPv4 address classification."""
        assert IOCEnricher.classify_ioc("8.8.8.8") == IOCType.IP
        assert IOCEnricher.classify_ioc("192.168.1.1") == IOCType.IP

    def test_classify_ipv6(self):
        """Test IPv6 address classification."""
        assert IOCEnricher.classify_ioc("::1") == IOCType.IP
        assert IOCEnricher.classify_ioc("2001:db8::1") == IOCType.IP

    def test_classify_md5(self):
        """Test MD5 hash classification."""
        assert IOCEnricher.classify_ioc("d41d8cd98f00b204e9800998ecf8427e") == IOCType.HASH

    def test_classify_sha1(self):
        """Test SHA1 hash classification."""
        assert IOCEnricher.classify_ioc("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IOCType.HASH

    def test_classify_sha256(self):
        """Test SHA256 hash classification."""
        hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert IOCEnricher.classify_ioc(hash_val) == IOCType.HASH

    def test_classify_domain(self):
        """Test domain classification."""
        assert IOCEnricher.classify_ioc("example.com") == IOCType.DOMAIN
        assert IOCEnricher.classify_ioc("sub.domain.co.uk") == IOCType.DOMAIN

    def test_classify_unknown(self):
        """Test unknown IOC classification."""
        assert IOCEnricher.classify_ioc("not_an_ioc") == IOCType.UNKNOWN
        assert IOCEnricher.classify_ioc("") == IOCType.UNKNOWN


class TestRiskScoring:
    """Tests for risk score calculation."""

    @pytest.fixture
    def enricher(self, tmp_path):
        """Create enricher with test config."""
        config = """
apis:
  virustotal:
    api_key: "TEST_KEY"
    base_url: "https://www.virustotal.com/api/v3"
  abuseipdb:
    api_key: "TEST_KEY"
    base_url: "https://api.abuseipdb.com/api/v2"
  alienvault_otx:
    api_key: "TEST_KEY"
    base_url: "https://otx.alienvault.com/api/v1"
settings:
  request_timeout: 5
  max_retries: 1
  retry_delay: 0
  risk_thresholds:
    low: 25
    medium: 50
    high: 75
"""
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text(config)
        return IOCEnricher(str(config_file))

    def test_calculate_risk_score_single_source(self, enricher):
        """Test score with single source."""
        sources = {
            "virustotal": {"score": 50},
        }
        score = enricher._calculate_risk_score(sources)
        assert score == 50.0

    def test_calculate_risk_score_multiple_sources(self, enricher):
        """Test weighted score with multiple sources."""
        sources = {
            "virustotal": {"score": 100},
            "abuseipdb": {"score": 0},
            "alienvault_otx": {"score": 50},
        }
        score = enricher._calculate_risk_score(sources)
        # (100 * 0.4 + 0 * 0.3 + 50 * 0.3) = 40 + 0 + 15 = 55
        assert score == 55.0

    def test_calculate_risk_score_no_sources(self, enricher):
        """Test score with no sources."""
        score = enricher._calculate_risk_score({})
        assert score == 0.0

    def test_risk_level_critical(self, enricher):
        """Test critical risk level."""
        assert enricher._determine_risk_level(90) == RiskLevel.CRITICAL
        assert enricher._determine_risk_level(75) == RiskLevel.CRITICAL

    def test_risk_level_high(self, enricher):
        """Test high risk level."""
        assert enricher._determine_risk_level(74) == RiskLevel.HIGH
        assert enricher._determine_risk_level(50) == RiskLevel.HIGH

    def test_risk_level_medium(self, enricher):
        """Test medium risk level."""
        assert enricher._determine_risk_level(49) == RiskLevel.MEDIUM
        assert enricher._determine_risk_level(25) == RiskLevel.MEDIUM

    def test_risk_level_low(self, enricher):
        """Test low risk level."""
        assert enricher._determine_risk_level(24) == RiskLevel.LOW
        assert enricher._determine_risk_level(0) == RiskLevel.LOW


class TestEnrichmentResult:
    """Tests for EnrichmentResult dataclass."""

    def test_to_dict(self):
        """Test dictionary conversion."""
        er = EnrichmentResult(
            ioc="8.8.8.8",
            ioc_type=IOCType.IP,
            risk_score=75.5,
            risk_level=RiskLevel.HIGH,
        )
        d = er.to_dict()
        assert d["ioc"] == "8.8.8.8"
        assert d["risk_score"] == 75.5
        assert d["risk_level"] == "high"

    def test_to_json(self):
        """Test JSON serialization."""
        er = EnrichmentResult(
            ioc="test.com",
            ioc_type=IOCType.DOMAIN,
        )
        json_str = er.to_json()
        assert "test.com" in json_str
        assert "domain" in json_str
