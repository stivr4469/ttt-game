import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Any

import requests

from log_config import get_logger

log = get_logger(__name__)

_REQUEST_TIMEOUT = 30
_MAX_RATE_LIMIT_WAITS = 3


class GitHubClient:
    def __init__(self, token: str):
        self.base_url = "https://api.github.com"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        })

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        self.session.close()

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> Optional[requests.Response]:
        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", _REQUEST_TIMEOUT)

        for attempt in range(_MAX_RATE_LIMIT_WAITS):
            try:
                response = self.session.request(method, url, params=params, **kwargs)

                remaining = int(response.headers.get("X-RateLimit-Remaining", 1))
                if response.status_code == 403 and remaining == 0:
                    reset_time = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
                    wait = max(reset_time - int(time.time()), 1)
                    log.warning(
                        "GitHub primary rate limit hit, waiting",
                        extra={"wait_s": wait, "attempt": attempt + 1},
                    )
                    time.sleep(wait)
                    continue

                if response.status_code == 401:
                    log.error("GitHub token invalid or expired")
                    raise requests.exceptions.HTTPError("GitHub token invalid or expired", response=response)

                if response.status_code == 403:
                    if "secondary rate limit" in response.text.lower():
                        log.warning("GitHub secondary rate limit hit, waiting 60s", extra={"attempt": attempt + 1})
                        time.sleep(60)
                        continue
                    raise requests.exceptions.HTTPError(
                        "GitHub token missing required permissions", response=response
                    )

                if response.status_code == 404:
                    return None

                response.raise_for_status()
                return response

            except requests.exceptions.RequestException as e:
                log.error("GitHub API request failed", extra={"method": method, "url": url, "error": str(e)})
                raise

        log.error("GitHub rate limit retries exhausted", extra={"method": method, "url": url})
        raise requests.exceptions.RetryError(f"Rate limit retries exhausted for {url}")

    def get_branch_protection(self, repo: str, branch: str = "main") -> Optional[Dict[str, Any]]:
        response = self._request("GET", f"/repos/{repo}/branches/{branch}/protection")
        return response.json() if response else None

    def get_recent_commits(self, repo: str, branch: str = "main", days: int = 30) -> List[Dict[str, Any]]:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        params = {"sha": branch, "since": since, "per_page": 100}
        response = self._request("GET", f"/repos/{repo}/commits", params=params)
        return response.json() if response else []

    def get_pull_requests(self, repo: str, state: str = "all", days: int = 30) -> List[Dict[str, Any]]:
        response = self._request("GET", f"/repos/{repo}/pulls", params={"state": state, "per_page": 100})
        if not response:
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        result = []
        for pr in response.json():
            created = datetime.fromisoformat(pr["created_at"].replace("Z", "+00:00"))
            if created >= cutoff:
                result.append(pr)
        return result

    def get_repo_info(self, repo: str) -> Optional[Dict[str, Any]]:
        response = self._request("GET", f"/repos/{repo}")
        return response.json() if response else None

    def get_workflows(self, repo: str) -> List[Dict[str, Any]]:
        response = self._request("GET", f"/repos/{repo}/actions/workflows")
        return response.json().get("workflows", []) if response else []

    def get_workflow_runs(self, repo: str, per_page: int = 10) -> List[Dict[str, Any]]:
        response = self._request("GET", f"/repos/{repo}/actions/runs", params={"per_page": per_page})
        return response.json().get("workflow_runs", []) if response else []

    def get_deploy_keys(self, repo: str) -> List[Dict[str, Any]]:
        response = self._request("GET", f"/repos/{repo}/keys")
        return response.json() if response else []

    def get_environments(self, repo: str) -> List[Dict[str, Any]]:
        response = self._request("GET", f"/repos/{repo}/environments")
        return response.json().get("environments", []) if response else []

    def get_secret_scanning_alerts(self, repo: str) -> Optional[List[Dict[str, Any]]]:
        response = self._request("GET", f"/repos/{repo}/secret-scanning/alerts")
        return response.json() if response else None

    def get_dependabot_alerts(self, repo: str) -> Optional[List[Dict[str, Any]]]:
        try:
            response = self._request("GET", f"/repos/{repo}/dependabot/alerts")
            return response.json() if response else None
        except Exception:
            return None

    def get_code_scanning_alerts(self, repo: str) -> Optional[List[Dict[str, Any]]]:
        response = self._request("GET", f"/repos/{repo}/code-scanning/alerts")
        return response.json() if response else None

    def get_security_advisories(self, repo: str) -> List[Dict[str, Any]]:
        response = self._request("GET", f"/repos/{repo}/security-advisories")
        return response.json() if response else []

    def get_file_content(self, repo: str, path: str) -> Optional[Dict[str, Any]]:
        response = self._request("GET", f"/repos/{repo}/contents/{path}")
        return response.json() if response else None

    def get_issues(self, repo: str, state: str = "open", labels: str = "") -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"state": state, "per_page": 100}
        if labels:
            params["labels"] = labels
        response = self._request("GET", f"/repos/{repo}/issues", params=params)
        return response.json() if response else []

    def create_issue(
        self,
        repo: str,
        title: str,
        body: str,
        labels: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        data: Dict[str, Any] = {"title": title, "body": body}
        if labels:
            data["labels"] = labels
        response = self._request("POST", f"/repos/{repo}/issues", json=data)
        return response.json() if response else None

    def get_repo_teams(self, repo: str) -> List[Dict[str, Any]]:
        response = self._request("GET", f"/repos/{repo}/teams")
        return response.json() if response else []

    def get_commit_signing(self, repo: str, branch: str = "main") -> Optional[Dict[str, Any]]:
        response = self._request(
            "GET",
            f"/repos/{repo}/branches/{branch}/protection/required_signatures",
        )
        return response.json() if response else None
