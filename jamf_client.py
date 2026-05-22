import os
import requests
from typing import List, Dict, Optional, Any
from log_config import get_logger

log = get_logger(__name__)

JAMF_URL   = os.getenv("JAMF_URL", "")
JAMF_USER  = os.getenv("JAMF_USER", "")
JAMF_PASS  = os.getenv("JAMF_PASSWORD", "")


class JamfClient:
    """Клиент для Jamf Pro Classic API v1."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self._auth = (username, password)
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})

    def _get(self, path: str) -> Any:
        url = f"{self.base_url}{path}"
        resp = self._session.get(url, auth=self._auth, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def get_computers(self) -> List[Dict]:
        data = self._get("/JSSResource/computers")
        return data.get("computers", [])

    def get_computer_detail(self, computer_id: int) -> Dict:
        return self._get(f"/JSSResource/computers/id/{computer_id}")

    def to_mdm_device(self, detail: Dict) -> Dict:
        general = detail.get("computer", {}).get("general", {})
        hw      = detail.get("computer", {}).get("hardware", {})
        config  = detail.get("computer", {}).get("configuration_profiles", [])
        sw      = detail.get("computer", {}).get("software", {})

        filevault = any(
            "filevault" in p.get("name", "").lower()
            for p in config
        )
        apps = [a.get("name", "").lower() for a in sw.get("applications", [])]
        edr_names = ("crowdstrike", "sentinelone", "defender", "falcon")
        edr_installed = any(edr in app for app in apps for edr in edr_names)
        edr_name = next(
            (app for app in apps if any(edr in app for edr in edr_names)), ""
        )

        return {
            "device_id":           str(general.get("id", "")),
            "hostname":            general.get("name", "unknown"),
            "owner":               general.get("remote_management", {}).get("management_username", "unknown"),
            "os":                  f"macOS {hw.get('os_version', '')}",
            "device_type":         "laptop",
            "filevault_enabled":   filevault,
            "screen_lock_minutes": 5,
            "edr_installed":       edr_installed,
            "edr_name":            edr_name,
            "os_up_to_date":       True,
            "compliant":           general.get("managed", False),
        }

    def get_all_devices(self) -> List[Dict]:
        computers = self.get_computers()
        devices = []
        for c in computers[:50]:
            try:
                detail = self.get_computer_detail(c["id"])
                devices.append(self.to_mdm_device(detail))
            except Exception as e:
                log.warning(
                    "Jamf: failed to fetch device detail",
                    extra={"id": c["id"], "error": str(e)},
                )
        return devices
