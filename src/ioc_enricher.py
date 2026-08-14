"""
IOC Enricher Module

Queries VirusTotal, AbuseIPDB, and AlienVault OTX APIs to enrich
Indicators of Compromise (IOCs) and calculate a composite risk score.

Supports: IPv4 addresses, MD5/SHA1/SHA256 hashes, and domains.
"""

import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import requests
import yaml


class IOCType(Enum):
    """Enumeration of supported IOC types."""
    IP = "ip"
    HASH = "hash"
    DOMAIN = "domain"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk level classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class EnrichmentResult:
    """Result container for IOC enrichment."""
    ioc: str
    ioc_type: IOCType
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    sources: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "ioc": self.ioc,
            "ioc_type": self.ioc_type.value,
            "risk_score": round(self.risk_score, 2),
            "risk_level": self.risk_level.value,
            "sources": self.sources,
            "errors": self.errors,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize result to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class IOCEnricher:
    """
    Enrich IOCs using multiple threat intelligence sources.

    Args:
        config_path: Path to the configuration YAML file.
    """

    def __init__(self, config_path: str = "config.yaml") -> None:
        """Initialize the enricher with configuration."""
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.timeout = self.config["settings"]["request_timeout"]
        self.max_retries = self.config["settings"]["max_retries"]
        self.retry_delay = self.config["settings"]["retry_delay"]

        # Thresholds
        thresholds = self.config["settings"]["risk_thresholds"]
        self.low_threshold = thresholds["low"]
        self.medium_threshold = thresholds["medium"]
        self.high_threshold = thresholds["high"]

    def _make_request(
        self,
        url: str,
        headers: dict[str, str],
        params: Optional[dict[str, Any]] = None,
    ) -> Optional[dict[str, Any]]:
        """
        Make an HTTP GET request with retry logic.

        Args:
            url: The URL to request.
            headers: HTTP headers.
            params: Optional query parameters.

        Returns:
            JSON response as dictionary, or None on failure.
        """
        for attempt in range(self.max_retries):
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=self.timeout,
                )
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
                else:
                    return None
        return None

    @staticmethod
    def classify_ioc(ioc: str) -> IOCType:
        """
        Classify an IOC string into its type.

        Args:
            ioc: The indicator string to classify.

        Returns:
            The classified IOCType.
        """
        # IPv4 address
        try:
            ipaddress.ip_address(ioc)
            return IOCType.IP
        except ValueError:
            pass

        # Domain
        domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$"
        )
        if domain_pattern.match(ioc):
            return IOCType.DOMAIN

        # Hash (MD5, SHA1, SHA256)
        if re.match(r"^[a-fA-F0-9]{32}$", ioc):
            return IOCType.HASH
        if re.match(r"^[a-fA-F0-9]{40}$", ioc):
            return IOCType.HASH
        if re.match(r"^[a-fA-F0-9]{64}$", ioc):
            return IOCType.HASH

        return IOCType.UNKNOWN

    def _query_virustotal(self, ioc: str, ioc_type: IOCType) -> dict[str, Any]:
        """
        Query VirusTotal API for IOC information.

        Args:
            ioc: The indicator to query.
            ioc_type: Type of the IOC.

        Returns:
            Dictionary with VT analysis results.
        """
        vt_config = self.config["apis"]["virustotal"]
        api_key = vt_config["api_key"]
        base_url = vt_config["base_url"]

        if api_key == "YOUR_VIRUSTOTAL_API_KEY":
            return {"error": "VirusTotal API key not configured"}

        headers = {"x-apikey": api_key}

        if ioc_type == IOCType.IP:
            url = f"{base_url}/ip_addresses/{ioc}"
        elif ioc_type == IOCType.DOMAIN:
            url = f"{base_url}/domains/{ioc}"
        elif ioc_type == IOCType.HASH:
            url = f"{base_url}/files/{ioc}"
        else:
            return {"error": "Unsupported IOC type for VirusTotal"}

        data = self._make_request(url, headers)

        if data is None:
            return {"error": "VirusTotal request failed"}

        # Extract relevant fields
        result = {
            "source": "virustotal",
            "malicious_votes": 0,
            "suspicious_votes": 0,
            "harmless_votes": 0,
            "reputation": 0,
        }

        if "data" in data and "attributes" in data["data"]:
            attrs = data["data"]["attributes"]
            last_analysis = attrs.get("last_analysis_stats", {})
            result["malicious_votes"] = last_analysis.get("malicious", 0)
            result["suspicious_votes"] = last_analysis.get("suspicious", 0)
            result["harmless_votes"] = last_analysis.get("harmless", 0)
            result["reputation"] = attrs.get("reputation", 0)

            # Calculate VT score (0-100)
            total = result["malicious_votes"] + result["suspicious_votes"] + result["harmless_votes"]
            if total > 0:
                result["score"] = ((result["malicious_votes"] + result["suspicious_votes"]) / total) * 100
            else:
                result["score"] = 0

        return result

    def _query_abuseipdb(self, ioc: str) -> dict[str, Any]:
        """
        Query AbuseIPDB for IP reputation.

        Args:
            ioc: The IP address to query.

        Returns:
            Dictionary with AbuseIPDB results.
        """
        abuse_config = self.config["apis"]["abuseipdb"]
        api_key = abuse_config["api_key"]
        base_url = abuse_config["base_url"]

        if api_key == "YOUR_ABUSEIPDB_API_KEY":
            return {"error": "AbuseIPDB API key not configured"}

        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ioc,
            "maxAgeInDays": 90,
            "verbose": "",
        }

        url = f"{base_url}/check"
        data = self._make_request(url, headers, params)

        if data is None:
            return {"error": "AbuseIPDB request failed"}

        result = {"source": "abuseipdb"}

        if "data" in data:
            result["abuse_confidence_score"] = data["data"].get("abuseConfidencePercentage", 0)
            result["total_reports"] = data["data"].get("totalReports", 0)
            result["country"] = data["data"].get("countryCode", "Unknown")
            result["isp"] = data["data"].get("isp", "Unknown")
            result["score"] = result["abuse_confidence_score"]

        return result

    def _query_otx(self, ioc: str, ioc_type: IOCType) -> dict[str, Any]:
        """
        Query AlienVault OTX for threat intelligence.

        Args:
            ioc: The indicator to query.
            ioc_type: Type of the IOC.

        Returns:
            Dictionary with OTX results.
        """
        otx_config = self.config["apis"]["alienvault_otx"]
        api_key = otx_config["api_key"]
        base_url = otx_config["base_url"]

        if api_key == "YOUR_OTX_API_KEY":
            return {"error": "AlienVault OTX API key not configured"}

        headers = {"X-OTX-API-KEY": api_key}

        if ioc_type == IOCType.IP:
            url = f"{base_url}/indicators/IPv4/{ioc}/general"
        elif ioc_type == IOCType.DOMAIN:
            url = f"{base_url}/indicators/domain/{ioc}/general"
        elif ioc_type == IOCType.HASH:
            url = f"{base_url}/indicators/file/{ioc}/general"
        else:
            return {"error": "Unsupported IOC type for OTX"}

        data = self._make_request(url, headers)

        if data is None:
            return {"error": "OTX request failed"}

        result = {
            "source": "alienvault_otx",
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "reputation": data.get("reputation", 0),
        }

        # Calculate OTX score based on pulse count
        pulse_count = result["pulse_count"]
        if pulse_count >= 10:
            result["score"] = 100
        elif pulse_count >= 5:
            result["score"] = 75
        elif pulse_count >= 2:
            result["score"] = 50
        elif pulse_count >= 1:
            result["score"] = 25
        else:
            result["score"] = 0

        return result

    def _calculate_risk_score(self, sources: dict[str, Any]) -> float:
        """
        Calculate composite risk score from multiple sources.

        Weights: VirusTotal 40%, AbuseIPDB 30%, OTX 30%

        Args:
            sources: Dictionary of source results.

        Returns:
            Composite risk score (0-100).
        """
        scores = []
        weights = []

        if "virustotal" in sources and "score" in sources["virustotal"]:
            scores.append(sources["virustotal"]["score"])
            weights.append(0.40)

        if "abuseipdb" in sources and "score" in sources["abuseipdb"]:
            scores.append(sources["abuseipdb"]["score"])
            weights.append(0.30)

        if "alienvault_otx" in sources and "score" in sources["alienvault_otx"]:
            scores.append(sources["alienvault_otx"]["score"])
            weights.append(0.30)

        if not scores:
            return 0.0

        # Normalize weights
        total_weight = sum(weights)
        normalized_weights = [w / total_weight for w in weights]

        weighted_score = sum(s * w for s, w in zip(scores, normalized_weights))
        return min(100.0, max(0.0, weighted_score))

    def _determine_risk_level(self, score: float) -> RiskLevel:
        """
        Determine risk level from score.

        Args:
            score: The risk score (0-100).

        Returns:
            The corresponding RiskLevel.
        """
        if score >= self.high_threshold:
            return RiskLevel.CRITICAL
        elif score >= self.medium_threshold:
            return RiskLevel.HIGH
        elif score >= self.low_threshold:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def enrich(self, ioc: str) -> EnrichmentResult:
        """
        Enrich a single IOC across all configured sources.

        Args:
            ioc: The indicator of compromise to enrich.

        Returns:
            EnrichmentResult with aggregated intelligence.
        """
        ioc_type = self.classify_ioc(ioc)
        result = EnrichmentResult(ioc=ioc, ioc_type=ioc_type)

        if ioc_type == IOCType.UNKNOWN:
            result.errors.append(f"Unable to classify IOC: {ioc}")
            return result

        # Query VirusTotal (all types)
        vt_result = self._query_virustotal(ioc, ioc_type)
        if "error" not in vt_result:
            result.sources["virustotal"] = vt_result
        else:
            result.errors.append(f"VirusTotal: {vt_result['error']}")

        # Query AbuseIPDB (IP only)
        if ioc_type == IOCType.IP:
            abuse_result = self._query_abuseipdb(ioc)
            if "error" not in abuse_result:
                result.sources["abuseipdb"] = abuse_result
            else:
                result.errors.append(f"AbuseIPDB: {abuse_result['error']}")

        # Query OTX (all types)
        otx_result = self._query_otx(ioc, ioc_type)
        if "error" not in otx_result:
            result.sources["alienvault_otx"] = otx_result
        else:
            result.errors.append(f"OTX: {otx_result['error']}")

        # Calculate composite score
        result.risk_score = self._calculate_risk_score(result.sources)
        result.risk_level = self._determine_risk_level(result.risk_score)

        return result

    def enrich_batch(self, iocs: list[str]) -> list[EnrichmentResult]:
        """
        Enrich multiple IOCs.

        Args:
            iocs: List of indicators to enrich.

        Returns:
            List of EnrichmentResult objects.
        """
        return [self.enrich(ioc) for ioc in iocs]
