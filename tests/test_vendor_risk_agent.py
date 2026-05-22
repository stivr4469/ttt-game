"""Тесты для Vendor Risk Agent — загрузка инвентаря, fallback без API-ключа."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import pytest
import inspect
from unittest.mock import MagicMock, patch
from vendor_risk_agent import VendorRiskAgent, main, SOC2_VENDOR_CONTROL


@pytest.fixture
def agent(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with patch("vendor_risk_agent.EvidenceClient"):
        return VendorRiskAgent(api_key=None, model=None)


class TestInventory:
    def test_inventory_file_exists(self):
        assert os.path.exists("vendor_inventory.json")

    def test_inventory_valid_json(self):
        data = json.load(open("vendor_inventory.json"))
        assert "vendors" in data

    def test_inventory_has_5_vendors(self):
        data = json.load(open("vendor_inventory.json"))
        assert len(data["vendors"]) >= 5

    def test_known_vendors_present(self):
        data = json.load(open("vendor_inventory.json"))
        names = {v["name"].lower() for v in data["vendors"]}
        for expected in ("aws", "github", "okta"):
            assert any(expected in n for n in names), f"{expected} not found"

    def test_vendors_have_required_fields(self):
        data = json.load(open("vendor_inventory.json"))
        required = {"name", "category", "data_processed", "soc2_certified"}
        for vendor in data["vendors"]:
            missing = required - set(vendor.keys())
            assert not missing, f"Vendor {vendor.get('name')} missing: {missing}"

    def test_data_processed_is_list(self):
        data = json.load(open("vendor_inventory.json"))
        for vendor in data["vendors"]:
            assert isinstance(vendor["data_processed"], list)


class TestVendorRiskAgent:
    def test_soc2_vendor_control_is_cc92(self):
        assert SOC2_VENDOR_CONTROL == "CC9.2"

    def test_main_accepts_controls_map(self):
        sig = inspect.signature(main)
        assert "controls_map" in sig.parameters

    def test_load_vendors_returns_list(self, agent):
        vendors = agent.load_vendors()
        assert isinstance(vendors, list)
        assert len(vendors) >= 5

    def test_no_api_key_graceful(self, monkeypatch):
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        with patch("vendor_risk_agent.EvidenceClient"):
            a = VendorRiskAgent(api_key=None, model=None)
        assert a is not None

    def test_analyze_vendor_fallback_without_key(self, agent):
        vendor = {"name": "TestVendor", "category": "cloud", "soc2_certified": False, "data_processed": []}
        result = agent.analyze_vendor(vendor)
        assert "risk_level" in result
        assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH", "UNKNOWN")

    def test_run_assessment_returns_list(self, agent):
        with patch.object(agent, "load_vendors", return_value=[
            {"name": "TestA", "category": "cloud", "soc2_certified": True, "data_processed": []},
        ]):
            results = agent.run_assessment()
        assert isinstance(results, list)
        assert len(results) == 1

    def test_one_vendor_failure_doesnt_stop_others(self, agent):
        def failing_analyze(vendor):
            if vendor["name"] == "BadVendor":
                raise RuntimeError("API error")
            return {"risk_level": "LOW"}

        with patch.object(agent, "analyze_vendor", side_effect=failing_analyze):
            with patch.object(agent, "load_vendors", return_value=[
                {"name": "BadVendor", "category": "x", "soc2_certified": False, "data_processed": []},
                {"name": "GoodVendor", "category": "y", "soc2_certified": True, "data_processed": []},
            ]):
                results = agent.run_assessment()
        assert len(results) == 2
        good = next(r for r in results if r["name"] == "GoodVendor")
        assert good["risk_level"] == "LOW"
