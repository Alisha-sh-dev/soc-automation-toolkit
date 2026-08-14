"""
Log Triage Module

Parses Windows Event Logs and Apache access logs to detect anomalies
including failed login attempts, 404 spikes, and suspicious patterns.
Generates summary reports with flagged events.
"""

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class Anomaly:
    """Represents a detected anomaly in log data."""
    anomaly_type: str
    severity: str
    description: str
    source_ip: Optional[str] = None
    count: int = 0
    timestamp: Optional[datetime] = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert anomaly to dictionary."""
        return {
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description,
            "source_ip": self.source_ip,
            "count": self.count,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "details": self.details,
        }


@dataclass
class TriageReport:
    """Summary report from log triage analysis."""
    log_type: str
    total_events: int = 0
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    anomalies: list[Anomaly] = field(default_factory=list)
    top_source_ips: list[tuple[str, int]] = field(default_factory=list)
    status_code_distribution: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "log_type": self.log_type,
            "total_events": self.total_events,
            "time_range": {
                "start": self.time_range_start.isoformat() if self.time_range_start else None,
                "end": self.time_range_end.isoformat() if self.time_range_end else None,
            },
            "anomaly_count": len(self.anomalies),
            "anomalies": [a.to_dict() for a in self.anomalies],
            "top_source_ips": self.top_source_ips,
            "status_code_distribution": self.status_code_distribution,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize report to JSON."""
        return json.dumps(self.to_dict(), indent=indent)


class ApacheLogParser:
    """
    Parser for Apache/Nginx access logs.

    Supports common log format:
    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
    """

    # Common log format regex
    LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'           # IP address
        r'(?P<identd>\S+)\s+'        # identd
        r'(?P<user>\S+)\s+'          # user
        r'\[(?P<time>[^\]]+)\]\s+' # timestamp
        r'"(?P<request>[^"]*)"\s+'     # request line
        r'(?P<status>\d{3})\s+'       # status code
        r'(?P<size>\S+)\s+'           # response size
        r'"(?P<referer>[^"]*)"\s+'     # referer
        r'"(?P<user_agent>[^"]*)"'      # user agent
    )

    TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

    @classmethod
    def parse_line(cls, line: str) -> Optional[dict[str, Any]]:
        """
        Parse a single Apache log line.

        Args:
            line: Raw log line.

        Returns:
            Dictionary with parsed fields, or None if parsing fails.
        """
        match = cls.LOG_PATTERN.match(line.strip())
        if not match:
            return None

        data = match.groupdict()

        # Parse timestamp
        try:
            data["timestamp"] = datetime.strptime(data["time"], cls.TIME_FORMAT)
        except ValueError:
            data["timestamp"] = None

        # Parse status code
        try:
            data["status_code"] = int(data["status"])
        except ValueError:
            data["status_code"] = 0

        # Parse request
        request_parts = data["request"].split()
        data["method"] = request_parts[0] if len(request_parts) > 0 else ""
        data["path"] = request_parts[1] if len(request_parts) > 1 else ""
        data["protocol"] = request_parts[2] if len(request_parts) > 2 else ""

        return data

    @classmethod
    def parse_file(cls, filepath: str) -> list[dict[str, Any]]:
        """
        Parse an entire Apache log file.

        Args:
            filepath: Path to the log file.

        Returns:
            List of parsed log entries.
        """
        entries = []
        path = Path(filepath)

        if not path.exists():
            return entries

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parsed = cls.parse_line(line)
                if parsed:
                    entries.append(parsed)

        return entries


class WindowsEventParser:
    """
    Parser for Windows Event Log exports (EVTX or text format).

    For text exports, expects format with Event ID, Time, Source, etc.
    """

    # Simple pattern for Windows Security log text exports
    EVENT_PATTERN = re.compile(
        r'Event ID:\s*(?P<event_id>\d+).*?'
        r'Time:\s*(?P<time>[^\n]+).*?'
        r'Source:\s*(?P<source>[^\n]+).*?'
        r'(?P<body>.*?)(?=Event ID:|$)',
        re.DOTALL | re.IGNORECASE
    )

    # Failed login Event IDs
    FAILED_LOGIN_EVENTS = {4625, 4648}
    SUCCESS_LOGIN_EVENTS = {4624}

    @classmethod
    def parse_line_based(cls, line: str) -> Optional[dict[str, Any]]:
        """
        Parse a simplified Windows event log line.

        Expected format: timestamp,event_id,source,message

        Args:
            line: Raw log line.

        Returns:
            Dictionary with parsed fields, or None.
        """
        parts = line.strip().split(",", 3)
        if len(parts) < 3:
            return None

        try:
            timestamp = datetime.fromisoformat(parts[0])
        except ValueError:
            timestamp = None

        try:
            event_id = int(parts[1])
        except ValueError:
            return None

        return {
            "timestamp": timestamp,
            "event_id": event_id,
            "source": parts[2],
            "message": parts[3] if len(parts) > 3 else "",
        }

    @classmethod
    def parse_file(cls, filepath: str) -> list[dict[str, Any]]:
        """
        Parse Windows event log file.

        Args:
            filepath: Path to the log file.

        Returns:
            List of parsed events.
        """
        entries = []
        path = Path(filepath)

        if not path.exists():
            return entries

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parsed = cls.parse_line_based(line)
                if parsed:
                    entries.append(parsed)

        return entries


class LogTriageEngine:
    """
    Engine for analyzing parsed logs and detecting anomalies.

    Args:
        config_path: Path to configuration YAML.
    """

    def __init__(self, config_path: str = "config.yaml") -> None:
        """Initialize the triage engine."""
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        triage_config = config["settings"]["log_triage"]
        self.failed_login_threshold = triage_config["failed_login_threshold"]
        self.not_found_threshold = triage_config["not_found_threshold"]
        self.time_window_minutes = triage_config["time_window_minutes"]

    def analyze_apache_logs(self, entries: list[dict[str, Any]]) -> TriageReport:
        """
        Analyze Apache log entries for anomalies.

        Args:
            entries: List of parsed Apache log entries.

        Returns:
            TriageReport with detected anomalies.
        """
        report = TriageReport(log_type="apache")
        report.total_events = len(entries)

        if not entries:
            return report

        # Time range
        timestamps = [e["timestamp"] for e in entries if e.get("timestamp")]
        if timestamps:
            report.time_range_start = min(timestamps)
            report.time_range_end = max(timestamps)

        # Source IP distribution
        ip_counter = Counter(e["ip"] for e in entries if e.get("ip"))
        report.top_source_ips = ip_counter.most_common(10)

        # Status code distribution
        status_counter = Counter(str(e.get("status_code", 0)) for e in entries)
        report.status_code_distribution = dict(status_counter)

        # Detect 404 spikes
        not_found_entries = [e for e in entries if e.get("status_code") == 404]
        if len(not_found_entries) >= self.not_found_threshold:
            report.anomalies.append(
                Anomaly(
                    anomaly_type="404_spike",
                    severity="medium",
                    description=f"High volume of 404 errors detected: {len(not_found_entries)} requests",
                    count=len(not_found_entries),
                    details={"threshold": self.not_found_threshold},
                )
            )

        # Detect scanning behavior (rapid 404s from single IP)
        nf_ip_counter = Counter(e["ip"] for e in not_found_entries if e.get("ip"))
        for ip, count in nf_ip_counter.most_common(5):
            if count >= self.not_found_threshold // 2:
                report.anomalies.append(
                    Anomaly(
                        anomaly_type="potential_scanning",
                        severity="high",
                        description=f"Possible scanning activity from {ip}",
                        source_ip=ip,
                        count=count,
                        details={"404_count": count},
                    )
                )

        # Detect 5xx errors
        server_errors = [e for e in entries if e.get("status_code", 0) >= 500]
        if len(server_errors) >= 10:
            report.anomalies.append(
                Anomaly(
                    anomaly_type="server_errors",
                    severity="medium",
                    description=f"Server error spike: {len(server_errors)} 5xx responses",
                    count=len(server_errors),
                )
            )

        # Detect suspicious user agents
        suspicious_ua_patterns = [
            r"sqlmap",
            r"nikto",
            r"nmap",
            r"masscan",
            r"gobuster",
            r"dirbuster",
            r"wget",
            r"curl",
        ]

        for pattern in suspicious_ua_patterns:
            matches = [e for e in entries if re.search(pattern, e.get("user_agent", ""), re.IGNORECASE)]
            if len(matches) >= 3:
                report.anomalies.append(
                    Anomaly(
                        anomaly_type="suspicious_user_agent",
                        severity="high",
                        description=f"Suspicious user agent pattern '{pattern}' detected",
                        count=len(matches),
                        details={"pattern": pattern, "matching_ips": list(set(e["ip"] for e in matches))},
                    )
                )

        return report

    def analyze_windows_events(self, entries: list[dict[str, Any]]) -> TriageReport:
        """
        Analyze Windows event log entries for anomalies.

        Args:
            entries: List of parsed Windows event entries.

        Returns:
            TriageReport with detected anomalies.
        """
        report = TriageReport(log_type="windows")
        report.total_events = len(entries)

        if not entries:
            return report

        # Time range
        timestamps = [e["timestamp"] for e in entries if e.get("timestamp")]
        if timestamps:
            report.time_range_start = min(timestamps)
            report.time_range_end = max(timestamps)

        # Count failed logins by time window
        failed_logins = [e for e in entries if e.get("event_id") in WindowsEventParser.FAILED_LOGIN_EVENTS]

        # Group by time window
        window_events = defaultdict(list)
        for entry in failed_logins:
            if entry.get("timestamp"):
                window_key = entry["timestamp"].replace(
                    minute=(entry["timestamp"].minute // self.time_window_minutes) * self.time_window_minutes,
                    second=0,
                    microsecond=0,
                )
                window_events[window_key].append(entry)

        for window, events in window_events.items():
            if len(events) >= self.failed_login_threshold:
                report.anomalies.append(
                    Anomaly(
                        anomaly_type="brute_force_attempt",
                        severity="high",
                        description=f"Possible brute force: {len(events)} failed logins in {self.time_window_minutes}min window",
                        count=len(events),
                        timestamp=window,
                        details={"window_minutes": self.time_window_minutes},
                    )
                )

        # Detect account lockouts (Event ID 4740)
        lockouts = [e for e in entries if e.get("event_id") == 4740]
        if lockouts:
            report.anomalies.append(
                Anomaly(
                    anomaly_type="account_lockout",
                    severity="medium",
                    description=f"{len(lockouts)} account lockout(s) detected",
                    count=len(lockouts),
                )
            )

        # Detect privilege escalation attempts (Event ID 4673, 4674)
        priv_events = [e for e in entries if e.get("event_id") in {4673, 4674}]
        if len(priv_events) >= 5:
            report.anomalies.append(
                Anomaly(
                    anomaly_type="privilege_escalation",
                    severity="high",
                    description=f"Multiple privilege escalation attempts: {len(priv_events)}",
                    count=len(priv_events),
                )
            )

        return report

    def analyze_file(self, filepath: str, log_type: Optional[str] = None) -> TriageReport:
        """
        Analyze a log file, auto-detecting type if not specified.

        Args:
            filepath: Path to the log file.
            log_type: "apache" or "windows", or None for auto-detect.

        Returns:
            TriageReport with analysis results.
        """
        path = Path(filepath)

        if not path.exists():
            return TriageReport(log_type="unknown")

        # Auto-detect based on content
        if log_type is None:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                sample = f.read(4096)
                if "GET " in sample or "POST " in sample or "HTTP/" in sample:
                    log_type = "apache"
                elif "Event ID:" in sample or any(eid in sample for eid in ["4625", "4624", "4740"]):
                    log_type = "windows"
                else:
                    log_type = "apache"  # default

        if log_type == "apache":
            entries = ApacheLogParser.parse_file(filepath)
            return self.analyze_apache_logs(entries)
        elif log_type == "windows":
            entries = WindowsEventParser.parse_file(filepath)
            return self.analyze_windows_events(entries)
        else:
            return TriageReport(log_type="unknown")
