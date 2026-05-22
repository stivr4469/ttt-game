"""Тесты для constants.py — централизованные константы проекта."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from constants import (
    DANGEROUS_PORTS,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_UNKNOWN,
    EVIDENCE_SOURCES,
    CONTROLS_MAP_FILE, HR_ROSTER_FILE,
    AUTO_CONTROLS,
    DORMANT_DAYS, TRAINING_GRACE_DAYS, CI_STALE_DAYS,
    CONTENT_MAX_BYTES, TITLE_MAX_CHARS,
)


class TestDangerousPorts:
    def test_ssh_port_is_critical(self):
        assert DANGEROUS_PORTS[22]["severity"] == SEVERITY_CRITICAL

    def test_rdp_port_is_critical(self):
        assert DANGEROUS_PORTS[3389]["severity"] == SEVERITY_CRITICAL

    def test_database_ports_are_high(self):
        for port in (5432, 3306, 1433, 27017, 6379, 9200):
            assert DANGEROUS_PORTS[port]["severity"] == SEVERITY_HIGH, f"Port {port}"

    def test_all_entries_have_service_and_severity(self):
        for port, info in DANGEROUS_PORTS.items():
            assert "service" in info, f"Port {port} missing 'service'"
            assert "severity" in info, f"Port {port} missing 'severity'"

    def test_severity_values_are_valid(self):
        valid = {SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW}
        for port, info in DANGEROUS_PORTS.items():
            assert info["severity"] in valid, f"Port {port} has invalid severity"


class TestSeverityLevels:
    def test_severity_constants_are_strings(self):
        for sev in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_UNKNOWN):
            assert isinstance(sev, str)

    def test_severity_values(self):
        assert SEVERITY_CRITICAL == "CRITICAL"
        assert SEVERITY_HIGH     == "HIGH"
        assert SEVERITY_MEDIUM   == "MEDIUM"
        assert SEVERITY_LOW      == "LOW"
        assert SEVERITY_UNKNOWN  == "UNKNOWN"


class TestEvidenceSources:
    def test_is_frozenset(self):
        assert isinstance(EVIDENCE_SOURCES, frozenset)

    def test_contains_required_sources(self):
        required = {"AWS_CLI", "OKTA", "GITHUB", "MANUAL", "AI_GENERATED", "SURVEY", "HR_AUDIT", "PROWLER"}
        assert required <= EVIDENCE_SOURCES

    def test_immutable(self):
        with pytest.raises(AttributeError):
            EVIDENCE_SOURCES.add("UNKNOWN_SOURCE")


class TestFilePaths:
    def test_controls_map_file(self):
        assert CONTROLS_MAP_FILE == "controls_map.json"
        assert CONTROLS_MAP_FILE.endswith(".json")

    def test_hr_roster_file(self):
        assert HR_ROSTER_FILE == "hr_roster.json"
        assert HR_ROSTER_FILE.endswith(".json")


class TestAutoControls:
    def test_is_list(self):
        assert isinstance(AUTO_CONTROLS, list)

    def test_contains_key_controls(self):
        for code in ("CC6.1", "CC6.2", "CC6.3", "CC8.1"):
            assert code in AUTO_CONTROLS, f"{code} missing from AUTO_CONTROLS"

    def test_no_duplicates(self):
        assert len(AUTO_CONTROLS) == len(set(AUTO_CONTROLS))

    def test_all_have_correct_format(self):
        import re
        pattern = re.compile(r"^CC\d+\.\d+$")
        for code in AUTO_CONTROLS:
            assert pattern.match(code), f"Malformed control code: {code}"


class TestThresholds:
    def test_dormant_days_positive(self):
        assert DORMANT_DAYS > 0

    def test_training_grace_days_positive(self):
        assert TRAINING_GRACE_DAYS > 0

    def test_ci_stale_days_positive(self):
        assert CI_STALE_DAYS > 0

    def test_content_max_bytes_under_100kb(self):
        assert CONTENT_MAX_BYTES < 100_000

    def test_title_max_chars_under_500(self):
        assert TITLE_MAX_CHARS < 500

    def test_content_larger_than_title(self):
        assert CONTENT_MAX_BYTES > TITLE_MAX_CHARS
