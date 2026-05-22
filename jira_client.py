import os, requests
from typing import Dict, List, Optional, Any
from log_config import get_logger

log = get_logger(__name__)

JIRA_URL         = os.getenv("JIRA_URL", "")
JIRA_USER        = os.getenv("JIRA_USER", "")
JIRA_TOKEN       = os.getenv("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "SEC")


class JiraClient:
    """Клиент Jira REST API v3."""

    def __init__(self, base_url: str, email: str, api_token: str):
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.auth = (email, api_token)
        self._session.headers.update({
            "Accept":       "application/json",
            "Content-Type": "application/json",
        })

    def _api(self, method: str, path: str, **kwargs) -> Any:
        url = f"{self.base_url}/rest/api/3{path}"
        resp = self._session.request(method, url, timeout=15, **kwargs)
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def create_issue(
        self,
        project_key: str,
        summary: str,
        description: str,
        issue_type: str = "Task",
        priority: str = "High",
        labels: Optional[List[str]] = None,
    ) -> Dict:
        body = {
            "fields": {
                "project":     {"key": project_key},
                "summary":     summary,
                "description": {
                    "type":    "doc",
                    "version": 1,
                    "content": [
                        {
                            "type":    "paragraph",
                            "content": [{"type": "text", "text": description}],
                        }
                    ],
                },
                "issuetype": {"name": issue_type},
                "priority":  {"name": priority},
                "labels":    labels or ["soc2", "compliance", "remediation"],
            }
        }
        result = self._api("POST", "/issue", json=body)
        key = result.get("key", "")
        issue_url = f"{self.base_url}/browse/{key}"
        log.info("Jira issue created", extra={"key": key, "summary": summary})
        return {"key": key, "id": result.get("id", ""), "url": issue_url}

    def get_issue(self, issue_key: str) -> Dict:
        result = self._api("GET", f"/issue/{issue_key}?fields=summary,status,priority,assignee")
        fields = result.get("fields", {})
        return {
            "key":      issue_key,
            "summary":  fields.get("summary", ""),
            "status":   fields.get("status", {}).get("name", ""),
            "priority": fields.get("priority", {}).get("name", ""),
            "assignee": (fields.get("assignee") or {}).get("displayName", "Unassigned"),
        }

    def add_comment(self, issue_key: str, text: str) -> Dict:
        body = {
            "body": {
                "type": "doc", "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}],
            }
        }
        return self._api("POST", f"/issue/{issue_key}/comment", json=body)

    def transition_issue(self, issue_key: str, transition_name: str) -> None:
        transitions = self._api("GET", f"/issue/{issue_key}/transitions")
        target = next(
            (t for t in transitions.get("transitions", [])
             if t["name"].lower() == transition_name.lower()),
            None,
        )
        if not target:
            log.warning("Jira: transition not found", extra={"issue": issue_key, "wanted": transition_name})
            return
        self._api("POST", f"/issue/{issue_key}/transitions", json={"transition": {"id": target["id"]}})
