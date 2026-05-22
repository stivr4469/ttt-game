import httpx
import time
import logging
from typing import List, Dict, Optional, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OktaClient:
    def __init__(self, domain: str, api_token: str):
        self.base_url = f"https://{domain}/api/v1"
        self.headers = {
            "Authorization": f"SSWS {api_token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        self.client = httpx.Client(headers=self.headers, timeout=30.0)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self.client.close()

    def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        while True:
            response = self.client.request(method, url, **kwargs)
            
            if response.status_code == 429:
                reset_time = int(response.headers.get("X-Rate-Limit-Reset", time.time() + 1))
                sleep_duration = max(reset_time - int(time.time()), 1)
                logger.warning(f"Rate limited. Sleeping for {sleep_duration} seconds...")
                time.sleep(sleep_duration)
                continue
                
            if response.status_code == 404:
                logger.error(f"Resource not found: {url}")
                raise Exception(f"Okta resource not found: {url}")
                
            if response.status_code >= 400:
                logger.error(f"Okta API error: {response.status_code} - {response.text}")
                response.raise_for_status()
                
            return response

    def _get_all(self, path: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        url = f"{self.base_url}{path}"
        results = []
        
        while url:
            response = self._request("GET", url, params=params if url.endswith(path) else None)
            results.extend(response.json())
            
            # Pagination via Link header
            url = None
            link_header = response.headers.get("Link")
            if link_header:
                links = link_header.split(",")
                for link in links:
                    if 'rel="next"' in link:
                        url = link.split(";")[0].strip("< >")
                        break
        
        return results

    def list_users(self, limit: int = 200) -> List[Dict[str, Any]]:
        params = {"limit": limit, "filter": 'status eq "ACTIVE"'}
        return self._get_all("/users", params=params)

    def list_user_factors(self, user_id: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/users/{user_id}/factors"
        response = self._request("GET", url)
        return response.json()

    def list_user_roles(self, user_id: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/users/{user_id}/roles"
        response = self._request("GET", url)
        return response.json()

    def list_groups(self, limit: int = 200) -> List[Dict[str, Any]]:
        return self._get_all("/groups", params={"limit": limit})

    def get_user_groups(self, user_id: str) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/users/{user_id}/groups"
        response = self._request("GET", url)
        return response.json()

    def create_user(self, profile: Dict[str, Any], activate: bool = False) -> Dict[str, Any]:
        url = f"{self.base_url}/users"
        data = {"profile": profile}
        params = {"activate": str(activate).lower()}
        response = self._request("POST", url, json=data, params=params)
        return response.json()

    def deactivate_user(self, user_id: str) -> None:
        url = f"{self.base_url}/users/{user_id}/lifecycle/deactivate"
        self._request("POST", url)

    def delete_user(self, user_id: str) -> None:
        url = f"{self.base_url}/users/{user_id}"
        self._request("DELETE", url)
