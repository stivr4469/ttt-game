"""Тесты для IntuneClient — маппинг устройств, токен, пагинация."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock
from intune_client import IntuneClient, GRAPH_URL


# ---------------------------------------------------------------------------
# Вспомогательные фабрики
# ---------------------------------------------------------------------------

def make_intune_device(**overrides):
    base = {
        "id": "device-1",
        "deviceName": "win-pc",
        "userPrincipalName": "alice@co.com",
        "operatingSystem": "Windows",
        "osVersion": "11.0",
        "complianceState": "compliant",
        "isEncrypted": True,
        "managementAgent": "mdm",
    }
    base.update(overrides)
    return base


def make_mock_response(data: dict) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# Класс 1: to_mdm_device маппинг
# ---------------------------------------------------------------------------

class TestToMdmDevice:
    @pytest.fixture
    def client(self):
        return IntuneClient("tenant-id", "client-id", "client-secret")

    def test_filevault_enabled_from_is_encrypted_true(self, client):
        device = client.to_mdm_device(make_intune_device(isEncrypted=True))
        assert device["filevault_enabled"] is True

    def test_filevault_disabled_from_is_encrypted_false(self, client):
        device = client.to_mdm_device(make_intune_device(isEncrypted=False))
        assert device["filevault_enabled"] is False

    def test_compliant_true_when_compliance_state_is_compliant(self, client):
        device = client.to_mdm_device(make_intune_device(complianceState="compliant"))
        assert device["compliant"] is True

    def test_compliant_false_when_compliance_state_is_not_compliant(self, client):
        device = client.to_mdm_device(make_intune_device(complianceState="noncompliant"))
        assert device["compliant"] is False

    def test_edr_installed_true_when_management_agent_is_mdm(self, client):
        device = client.to_mdm_device(make_intune_device(managementAgent="mdm"))
        assert device["edr_installed"] is True

    def test_edr_name_microsoft_defender_when_mdm(self, client):
        device = client.to_mdm_device(make_intune_device(managementAgent="mdm"))
        assert device["edr_name"] == "Microsoft Defender"

    def test_edr_installed_false_when_management_agent_not_mdm(self, client):
        device = client.to_mdm_device(make_intune_device(managementAgent="easMdm"))
        assert device["edr_installed"] is False

    def test_edr_name_empty_when_agent_not_mdm(self, client):
        device = client.to_mdm_device(make_intune_device(managementAgent="eas"))
        assert device["edr_name"] == ""

    def test_hostname_from_device_name(self, client):
        device = client.to_mdm_device(make_intune_device(deviceName="laptop-bob"))
        assert device["hostname"] == "laptop-bob"

    def test_owner_from_user_principal_name(self, client):
        device = client.to_mdm_device(make_intune_device(userPrincipalName="bob@corp.com"))
        assert device["owner"] == "bob@corp.com"

    def test_os_combines_operating_system_and_version(self, client):
        device = client.to_mdm_device(make_intune_device(operatingSystem="macOS", osVersion="14.4"))
        assert device["os"] == "macOS 14.4"

    def test_device_id_from_id_field(self, client):
        device = client.to_mdm_device(make_intune_device(id="abc-123"))
        assert device["device_id"] == "abc-123"


# ---------------------------------------------------------------------------
# Класс 2: _get_token
# ---------------------------------------------------------------------------

class TestGetToken:
    @pytest.fixture
    def client(self):
        return IntuneClient("my-tenant", "my-client", "my-secret")

    def test_posts_to_correct_token_url(self, client):
        mock_resp = make_mock_response({"access_token": "tok-123"})
        with patch("requests.post", return_value=mock_resp) as mock_post:
            token = client._get_token()
        called_url = mock_post.call_args[0][0]
        assert "my-tenant" in called_url
        assert "oauth2/v2.0/token" in called_url

    def test_sends_client_credentials_grant_type(self, client):
        mock_resp = make_mock_response({"access_token": "tok-456"})
        with patch("requests.post", return_value=mock_resp) as mock_post:
            client._get_token()
        sent_data = mock_post.call_args[1]["data"]
        assert sent_data["grant_type"] == "client_credentials"
        assert sent_data["client_id"] == "my-client"
        assert sent_data["client_secret"] == "my-secret"

    def test_returns_access_token(self, client):
        mock_resp = make_mock_response({"access_token": "tok-789"})
        with patch("requests.post", return_value=mock_resp):
            token = client._get_token()
        assert token == "tok-789"

    def test_token_cached_second_call_not_post_again(self, client):
        mock_resp = make_mock_response({"access_token": "cached-tok"})
        with patch("requests.post", return_value=mock_resp) as mock_post:
            client._get_token()
            client._get_token()
        assert mock_post.call_count == 1


# ---------------------------------------------------------------------------
# Класс 3: get_managed_devices с пагинацией
# ---------------------------------------------------------------------------

class TestGetManagedDevices:
    @pytest.fixture
    def client(self):
        c = IntuneClient("tenant", "client", "secret")
        c._token = "fake-token"   # пропускаем авторизацию
        return c

    def test_returns_devices_from_single_page(self, client):
        page = {"value": [make_intune_device(id="d-1"), make_intune_device(id="d-2")]}
        with patch.object(client, "_get", return_value=page):
            devices = client.get_managed_devices()
        assert len(devices) == 2

    def test_follows_next_link_pagination(self, client):
        page1 = {
            "value": [make_intune_device(id="d-1")],
            "@odata.nextLink": f"{GRAPH_URL}/deviceManagement/managedDevices?$skiptoken=abc",
        }
        page2 = {"value": [make_intune_device(id="d-2")]}
        with patch.object(client, "_get", side_effect=[page1, page2]):
            devices = client.get_managed_devices()
        assert len(devices) == 2
        assert devices[0]["id"] == "d-1"
        assert devices[1]["id"] == "d-2"

    def test_returns_empty_list_when_no_devices(self, client):
        with patch.object(client, "_get", return_value={"value": []}):
            devices = client.get_managed_devices()
        assert devices == []
