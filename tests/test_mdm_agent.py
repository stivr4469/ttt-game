"""Тесты для MDM Agent — check_device, run_checks, POLICY."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import pytest
from unittest.mock import MagicMock, patch
from mdm_agent import MDMAgent, POLICY, MDM_CONTROLS


@pytest.fixture
def agent():
    with patch("mdm_agent.EvidenceClient"):
        return MDMAgent("http://localhost:8000", None)


def _device(**overrides):
    base = {
        "device_id": "TEST-001", "hostname": "test-host", "owner": "user@acme.com",
        "os": "macOS 14.4", "device_type": "laptop",
        "filevault_enabled": True, "screen_lock_minutes": 5,
        "edr_installed": True, "edr_name": "CrowdStrike",
        "os_up_to_date": True, "compliant": True,
    }
    base.update(overrides)
    return base


class TestPolicy:
    def test_screen_lock_threshold_defined(self):
        assert "screen_lock_max_minutes" in POLICY
        assert POLICY["screen_lock_max_minutes"] > 0

    def test_require_filevault(self):
        assert POLICY["require_filevault"] is True

    def test_require_edr(self):
        assert POLICY["require_edr"] is True

    def test_mdm_controls_has_cc66(self):
        assert "CC6.6" in MDM_CONTROLS

    def test_mdm_controls_has_cc68(self):
        assert "CC6.8" in MDM_CONTROLS


class TestCheckDevice:
    def test_compliant_device_no_violations(self, agent):
        result = agent.check_device(_device())
        assert result["compliant"] is True
        assert result["violations"] == []

    def test_filevault_disabled_creates_violation(self, agent):
        result = agent.check_device(_device(filevault_enabled=False))
        violations = [v["check"] for v in result["violations"]]
        assert "filevault" in violations
        assert result["compliant"] is False

    def test_edr_missing_creates_violation(self, agent):
        result = agent.check_device(_device(edr_installed=False))
        violations = [v["check"] for v in result["violations"]]
        assert "edr" in violations
        assert result["compliant"] is False

    def test_screen_lock_too_long_creates_violation(self, agent):
        too_long = POLICY["screen_lock_max_minutes"] + 5
        result = agent.check_device(_device(screen_lock_minutes=too_long))
        violations = [v["check"] for v in result["violations"]]
        assert "screen_lock" in violations
        assert result["compliant"] is False

    def test_outdated_os_creates_violation(self, agent):
        result = agent.check_device(_device(os_up_to_date=False))
        violations = [v["check"] for v in result["violations"]]
        assert any("os" in v for v in violations)

    def test_multiple_violations_counted(self, agent):
        result = agent.check_device(_device(filevault_enabled=False, edr_installed=False))
        assert len(result["violations"]) >= 2

    def test_result_has_required_keys(self, agent):
        result = agent.check_device(_device())
        for key in ("device_id", "hostname", "owner", "violations", "compliant"):
            assert key in result, f"missing key: {key}"

    def test_violation_has_severity(self, agent):
        result = agent.check_device(_device(filevault_enabled=False))
        for v in result["violations"]:
            assert "severity" in v
            assert v["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_filevault_violation_is_critical(self, agent):
        result = agent.check_device(_device(filevault_enabled=False))
        filevault_violations = [v for v in result["violations"] if v["check"] == "filevault"]
        assert filevault_violations[0]["severity"] == "CRITICAL"


class TestInventory:
    def test_inventory_file_exists(self):
        assert os.path.exists("mdm_device_inventory.json")

    def test_inventory_valid_json(self):
        data = json.load(open("mdm_device_inventory.json"))
        assert "devices" in data
        assert len(data["devices"]) >= 8

    def test_inventory_has_non_compliant(self):
        data = json.load(open("mdm_device_inventory.json"))
        nc = [d for d in data["devices"] if not d.get("compliant", True)]
        assert len(nc) >= 3

    def test_inventory_devices_have_required_fields(self):
        data = json.load(open("mdm_device_inventory.json"))
        required = {"device_id", "hostname", "owner", "filevault_enabled",
                    "screen_lock_minutes", "edr_installed", "os_up_to_date"}
        for device in data["devices"]:
            missing = required - set(device.keys())
            assert not missing, f"Device {device.get('device_id')} missing: {missing}"


class TestRunChecks:
    def test_returns_summary_keys(self, agent):
        with patch.object(agent, "load_devices", return_value=[_device(), _device()]):
            result = agent.run_checks()
        for key in ("total_devices", "compliant", "non_compliant", "compliance_rate_pct", "devices"):
            assert key in result

    def test_all_compliant_100pct(self, agent):
        with patch.object(agent, "load_devices", return_value=[_device(), _device()]):
            result = agent.run_checks()
        assert result["compliance_rate_pct"] == 100.0
        assert result["non_compliant"] == 0

    def test_one_non_compliant_counts(self, agent):
        devices = [_device(), _device(filevault_enabled=False, compliant=False)]
        with patch.object(agent, "load_devices", return_value=devices):
            result = agent.run_checks()
        assert result["non_compliant"] == 1
        assert result["compliance_rate_pct"] == 50.0
