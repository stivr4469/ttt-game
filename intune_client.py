import os
import requests
from typing import List, Dict, Any
from log_config import get_logger

log = get_logger(__name__)

INTUNE_TENANT_ID     = os.getenv("INTUNE_TENANT_ID", "")
INTUNE_CLIENT_ID     = os.getenv("INTUNE_CLIENT_ID", "")
INTUNE_CLIENT_SECRET = os.getenv("INTUNE_CLIENT_SECRET", "")

GRAPH_URL = "https://graph.microsoft.com/v1.0"


class IntuneClient:
    """Клиент для Microsoft Intune через Graph API."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id     = tenant_id
        self.client_id     = client_id
        self.client_secret = client_secret
        self._token: str | None = None
        self._session = requests.Session()

    def _get_token(self) -> str:
        if self._token:
            return self._token
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        resp = requests.post(url, data={
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "scope":         "https://graph.microsoft.com/.default",
        }, timeout=15)
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        return self._token

    def _get(self, path: str) -> Any:
        headers = {"Authorization": f"Bearer {self._get_token()}"}
        resp = self._session.get(f"{GRAPH_URL}{path}", headers=headers, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def get_managed_devices(self) -> List[Dict]:
        devices = []
        url = (
            "/deviceManagement/managedDevices"
            "?$select=id,deviceName,userPrincipalName,operatingSystem,"
            "osVersion,complianceState,isEncrypted,managementAgent"
        )
        while url:
            data = self._get(url)
            devices.extend(data.get("value", []))
            url = data.get("@odata.nextLink", "").replace(GRAPH_URL, "")
        return devices

    def to_mdm_device(self, d: Dict) -> Dict:
        return {
            "device_id":           d.get("id", ""),
            "hostname":            d.get("deviceName", "unknown"),
            "owner":               d.get("userPrincipalName", "unknown"),
            "os":                  f"{d.get('operatingSystem', '')} {d.get('osVersion', '')}",
            "device_type":         "laptop",
            "filevault_enabled":   d.get("isEncrypted", False),
            "screen_lock_minutes": 5,
            "edr_installed":       d.get("managementAgent") == "mdm",
            "edr_name":            "Microsoft Defender" if d.get("managementAgent") == "mdm" else "",
            "os_up_to_date":       d.get("complianceState") == "compliant",
            "compliant":           d.get("complianceState") == "compliant",
        }
