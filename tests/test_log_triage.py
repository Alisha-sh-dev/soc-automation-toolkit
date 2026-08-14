"""Unit tests for Log Triage module."""

from datetime import datetime

import pytest

from src.log_triage import (
    Anomaly,
    ApacheLogParser,
    LogTriageEngine,
    TriageReport,
    WindowsEventParser,
)


class TestApacheLogParser:
    """Tests for Apache log parser."""

    def test_parse_valid_line(self):
        """Test parsing a valid Apache log line."""
        line = '192.168.1.1 - - [14/Aug/2026:10:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        result = ApacheLogParser.parse_line(line)

        assert result is not None
        assert result["ip"] == "192.168.1.1"
        assert result["status_code"] == 200
        assert result["method"] == "GET"
        assert result["path"] == "/index.html"
        assert result["user_agent"] == "Mozilla/5.0"

    def test_parse_404_line(self):
        """Test parsing a 404 log line."""
        line = '10.0.0.5 - - [14/Aug/2026:10:31:00 +0000] "GET /admin.php HTTP/1.1" 404 512 "-" "curl/7.68.0"'
        result = ApacheLogParser.parse_line(line)

        assert result is not None
        assert result["status_code"] == 404
        assert result["ip"] == "10.0.0.5"

    def test_parse_invalid_line(self):
        """Test parsing an invalid line."""
        result = ApacheLogParser.parse_line("not a valid log line")
        assert result is None

    def test_parse_empty_line(self):
        """Test parsing empty line."""
        result = ApacheLogParser.parse_line("")
        assert result is None


class TestWindowsEventParser:
    """Tests for Windows event parser."""

    def test_parse_csv_format(self):
        """Test parsing CSV-formatted Windows event."""
        line = "2026-08-14T10:30:00,4625,Security,Failed login attempt"
        result = WindowsEventParser.parse_line_based(line)

        assert result is not None
        assert result["event_id"] == 4625
        assert result["source"] == "Security"
        assert result["message"] == "Failed login attempt"

    def test_parse_invalid_line(self):
        """Test parsing invalid line."""
        result = WindowsEventParser.parse_line_based("invalid")
        assert result is None

    def test_failed_login_event_ids(self):
        """Test that correct event IDs are flagged as failed logins."""
        assert 4625 in WindowsEventParser.FAILED_LOGIN_EVENTS
        assert 4648 in WindowsEventParser.FAILED_LOGIN_EVENTS


class TestLogTriageEngine:
    """Tests for log triage engine."""

    @pytest.fixture
    def engine(self, tmp_path):
        """Create triage engine with test config."""
        config = """
settings:
  log_triage:
    failed_login_threshold: 5
    not_found_threshold: 20
    time_window_minutes: 10
"""
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text(config)
        return LogTriageEngine(str(config_file))

    def test_analyze_apache_no_anomalies(self, engine):
        """Test analysis with clean Apache logs."""
        entries = [
            {
                "ip": "192.168.1.1",
                "status_code": 200,
                "timestamp": datetime(2026, 8, 14, 10, 0, 0),
                "user_agent": "Mozilla/5.0",
            },
            {
                "ip": "192.168.1.2",
                "status_code": 200,
                "timestamp": datetime(2026, 8, 14, 10, 1, 0),
                "user_agent": "Mozilla/5.0",
            },
        ]
        report = engine.analyze_apache_logs(entries)

        assert report.total_events == 2
        assert len(report.anomalies) == 0
        assert report.status_code_distribution["200"] == 2

    def test_detect_404_spike(self, engine):
        """Test detection of 404 spike anomaly."""
        entries = []
        for i in range(25):
            entries.append({
                "ip": f"10.0.0.{i % 5}",
                "status_code": 404,
                "timestamp": datetime(2026, 8, 14, 10, i, 0),
                "user_agent": "Mozilla/5.0",
            })

        report = engine.analyze_apache_logs(entries)

        assert len(report.anomalies) >= 1
        anomaly_types = [a.anomaly_type for a in report.anomalies]
        assert "404_spike" in anomaly_types

    def test_detect_scanning(self, engine):
        """Test detection of scanning behavior."""
        entries = []
        for i in range(15):
            entries.append({
                "ip": "10.0.0.1",
                "status_code": 404,
                "timestamp": datetime(2026, 8, 14, 10, i, 0),
                "user_agent": "Mozilla/5.0",
            })

        report = engine.analyze_apache_logs(entries)

        anomaly_types = [a.anomaly_type for a in report.anomalies]
        assert "potential_scanning" in anomaly_types

    def test_detect_suspicious_user_agent(self, engine):
        """Test detection of suspicious user agents."""
        entries = []
        for i in range(5):
            entries.append({
                "ip": "10.0.0.1",
                "status_code": 200,
                "timestamp": datetime(2026, 8, 14, 10, i, 0),
                "user_agent": "sqlmap/1.0",
            })

        report = engine.analyze_apache_logs(entries)

        anomaly_types = [a.anomaly_type for a in report.anomalies]
        assert "suspicious_user_agent" in anomaly_types

    def test_analyze_windows_brute_force(self, engine):
        """Test detection of brute force attempts."""
        entries = []
        for i in range(10):
            entries.append({
                "timestamp": datetime(2026, 8, 14, 10, i, 0),
                "event_id": 4625,
                "source": "Security",
                "message": "Failed login",
            })

        report = engine.analyze_windows_events(entries)

        assert len(report.anomalies) >= 1
        anomaly_types = [a.anomaly_type for a in report.anomalies]
        assert "brute_force_attempt" in anomaly_types

    def test_empty_log(self, engine):
        """Test handling of empty log."""
        report = engine.analyze_apache_logs([])
        assert report.total_events == 0
        assert len(report.anomalies) == 0


class TestTriageReport:
    """Tests for TriageReport."""

    def test_to_dict(self):
        """Test report serialization."""
        report = TriageReport(log_type="apache", total_events=100)
        report.anomalies.append(
            Anomaly(
                anomaly_type="test",
                severity="low",
                description="Test anomaly",
            )
        )

        d = report.to_dict()
        assert d["log_type"] == "apache"
        assert d["total_events"] == 100
        assert d["anomaly_count"] == 1
