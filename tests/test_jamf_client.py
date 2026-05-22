"""Тесты для JamfClient — инициализация, маппинг устройств, HTTP методы."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock, call
from jamf_client import JamfClient


# ---------------------------------------------------------------------------
# Вспомогательная фабрика деталей компьютера
# ---------------------------------------------------------------------------

def make_detail(
    name="mac-01",
    managed=True,
    os_ver="14.4",
    profiles=None,
    apps=None,
    computer_id=1,
    mgmt_user="admin",
):
    return {
        "computer": {
            "general": {
                "id": computer_id,
                "name": name,
                "managed": managed,
                "remote_management": {"management_username": mgmt_user},
            },
            "hardware": {"os_version": os_ver},
            "configuration_profiles": profiles or [],
            "software": {"applications": apps or []},
        }
    }


# ---------------------------------------------------------------------------
# Класс 1: инициализация клиента
# ---------------------------------------------------------------------------

class TestJamfClientInit:
    def test_base_url_stored_without_trailing_slash(self):
        client = JamfClient("https://jamf.example.com/", "user", "pass")
        assert client.base_url == "https://jamf.example.com"

    def test_base_url_stored_without_change(self):
        client = JamfClient("https://jamf.example.com", "user", "pass")
        assert client.base_url == "https://jamf.example.com"

    def test_auth_tuple_stored(self):
        client = JamfClient("https://jamf.example.com", "admin", "secret")
        assert client._auth == ("admin", "secret")

    def test_session_accept_header(self):
        client = JamfClient("https://jamf.example.com", "u", "p")
        assert client._session.headers.get("Accept") == "application/json"


# ---------------------------------------------------------------------------
# Класс 2: to_mdm_device маппинг
# ---------------------------------------------------------------------------

class TestToMdmDevice:
    @pytest.fixture
    def client(self):
        return JamfClient("https://jamf.example.com", "admin", "secret")

    # FileVault
    def test_filevault_enabled_when_profile_name_contains_filevault(self, client):
        detail = make_detail(profiles=[{"name": "FileVault Encryption Policy"}])
        device = client.to_mdm_device(detail)
        assert device["filevault_enabled"] is True

    def test_filevault_enabled_case_insensitive(self, client):
        detail = make_detail(profiles=[{"name": "FILEVAULT corporate"}])
        device = client.to_mdm_device(detail)
        assert device["filevault_enabled"] is True

    def test_filevault_disabled_when_no_filevault_profile(self, client):
        detail = make_detail(profiles=[{"name": "Security Baseline"}, {"name": "VPN Profile"}])
        device = client.to_mdm_device(detail)
        assert device["filevault_enabled"] is False

    def test_filevault_disabled_when_profiles_empty(self, client):
        detail = make_detail(profiles=[])
        device = client.to_mdm_device(detail)
        assert device["filevault_enabled"] is False

    # EDR
    def test_edr_installed_true_when_crowdstrike_present(self, client):
        detail = make_detail(apps=[{"name": "CrowdStrike Falcon"}])
        device = client.to_mdm_device(detail)
        assert device["edr_installed"] is True

    def test_edr_installed_true_when_sentinelone_present(self, client):
        detail = make_detail(apps=[{"name": "SentinelOne Agent"}])
        device = client.to_mdm_device(detail)
        assert device["edr_installed"] is True

    def test_edr_installed_true_when_falcon_present(self, client):
        detail = make_detail(apps=[{"name": "falcon sensor"}])
        device = client.to_mdm_device(detail)
        assert device["edr_installed"] is True

    def test_edr_installed_false_when_no_edr_apps(self, client):
        detail = make_detail(apps=[{"name": "Slack"}, {"name": "Chrome"}])
        device = client.to_mdm_device(detail)
        assert device["edr_installed"] is False

    def test_edr_installed_false_when_apps_empty(self, client):
        detail = make_detail(apps=[])
        device = client.to_mdm_device(detail)
        assert device["edr_installed"] is False

    # compliant / managed
    def test_compliant_true_when_managed_true(self, client):
        detail = make_detail(managed=True)
        device = client.to_mdm_device(detail)
        assert device["compliant"] is True

    def test_compliant_false_when_managed_false(self, client):
        detail = make_detail(managed=False)
        device = client.to_mdm_device(detail)
        assert device["compliant"] is False

    # hostname / os / device_id
    def test_hostname_from_general_name(self, client):
        detail = make_detail(name="my-macbook-pro")
        device = client.to_mdm_device(detail)
        assert device["hostname"] == "my-macbook-pro"

    def test_os_includes_macos_prefix_and_version(self, client):
        detail = make_detail(os_ver="14.4.1")
        device = client.to_mdm_device(detail)
        assert device["os"] == "macOS 14.4.1"

    def test_device_id_from_general_id(self, client):
        detail = make_detail(computer_id=42)
        device = client.to_mdm_device(detail)
        assert device["device_id"] == "42"

    def test_owner_from_management_username(self, client):
        detail = make_detail(mgmt_user="john.doe")
        device = client.to_mdm_device(detail)
        assert device["owner"] == "john.doe"


# ---------------------------------------------------------------------------
# Класс 3: get_computers
# ---------------------------------------------------------------------------

class TestGetComputers:
    @pytest.fixture
    def client(self):
        return JamfClient("https://jamf.example.com", "admin", "secret")

    def test_returns_computers_list(self, client):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"computers": [{"id": 1, "name": "mac-01"}]}
        mock_resp.raise_for_status = MagicMock()
        with patch.object(client._session, "get", return_value=mock_resp):
            result = client.get_computers()
        assert result == [{"id": 1, "name": "mac-01"}]

    def test_returns_empty_list_when_key_missing(self, client):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status = MagicMock()
        with patch.object(client._session, "get", return_value=mock_resp):
            result = client.get_computers()
        assert result == []

    def test_calls_correct_endpoint(self, client):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"computers": []}
        mock_resp.raise_for_status = MagicMock()
        with patch.object(client._session, "get", return_value=mock_resp) as mock_get:
            client.get_computers()
        called_url = mock_get.call_args[0][0]
        assert called_url == "https://jamf.example.com/JSSResource/computers"


# ---------------------------------------------------------------------------
# Класс 4: get_all_devices
# ---------------------------------------------------------------------------

class TestGetAllDevices:
    @pytest.fixture
    def client(self):
        return JamfClient("https://jamf.example.com", "admin", "secret")

    def test_combines_computers_and_details(self, client):
        computers = [{"id": 1}, {"id": 2}]
        detail_1 = make_detail(name="mac-01", computer_id=1)
        detail_2 = make_detail(name="mac-02", computer_id=2)

        with patch.object(client, "get_computers", return_value=computers), \
             patch.object(client, "get_computer_detail", side_effect=[detail_1, detail_2]):
            devices = client.get_all_devices()

        assert len(devices) == 2
        assert devices[0]["hostname"] == "mac-01"
        assert devices[1]["hostname"] == "mac-02"

    def test_skips_failed_device_detail(self, client):
        computers = [{"id": 1}, {"id": 2}]
        detail_ok = make_detail(name="mac-ok", computer_id=2)

        with patch.object(client, "get_computers", return_value=computers), \
             patch.object(client, "get_computer_detail", side_effect=[Exception("timeout"), detail_ok]):
            devices = client.get_all_devices()

        assert len(devices) == 1
        assert devices[0]["hostname"] == "mac-ok"

    def test_limits_to_50_computers(self, client):
        computers = [{"id": i} for i in range(100)]
        detail = make_detail()

        with patch.object(client, "get_computers", return_value=computers), \
             patch.object(client, "get_computer_detail", return_value=detail) as mock_detail:
            client.get_all_devices()

        assert mock_detail.call_count == 50
