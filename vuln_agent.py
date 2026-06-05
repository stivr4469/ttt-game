import os
import json
import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional

from log_config import get_logger
from base_http_client import BaseHTTPClient
from base_compliance_agent import BaseComplianceAgent, AgentResult
from evidence_client import EvidenceClient

log = get_logger(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO  = os.getenv("GITHUB_REPO", "stivr4469/compliance-sandbox")
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")

SLA_HOURS = {
    "critical": 24,
    "high":     168,   # 7 дней
    "medium":   720,   # 30 дней
    "low":      2160,  # 90 дней
}

MOCK_DEPENDABOT_ALERTS = [
  {"number": 1, "state": "open", "security_advisory": {"severity": "high", "cve_id": "CVE-2023-32681", "summary": "Unintended leak of Proxy-Authorization header"},
   "dependency": {"package": {"name": "requests"}, "version": "2.25.0"},
   "created_at": (datetime.now(timezone.utc) - timedelta(days=21)).isoformat(), "fixed_in": "2.31.0"},
  {"number": 2, "state": "open", "security_advisory": {"severity": "critical", "cve_id": "CVE-2023-44271", "summary": "Uncontrolled resource consumption in ImageFont"},
   "dependency": {"package": {"name": "pillow"}, "version": "9.0.0"},
   "created_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(), "fixed_in": "10.0.1"},
  {"number": 3, "state": "open", "security_advisory": {"severity": "medium", "cve_id": "CVE-2023-49083", "summary": "NULL pointer dereference in PKCS12 parsing"},
   "dependency": {"package": {"name": "cryptography"}, "version": "38.0.0"},
   "created_at": (datetime.now(timezone.utc) - timedelta(days=40)).isoformat(), "fixed_in": "41.0.6"}
]

class VulnAgent(BaseComplianceAgent):
    CONTROLS = {
        "CC6.8": "Unauthorized Access Detection — dependency vulnerability scanning",
        "CC7.3": "Threat Identification — critical/high CVE alerts",
    }

    def authenticate(self) -> None:
        self.token = GITHUB_TOKEN
        self.repo = GITHUB_REPO
        self.client = BaseHTTPClient(base_url="https://api.github.com")

    @property
    def agent_name(self) -> str:
        return "vuln"

    def _gh_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

    def fetch_dependabot_alerts(self) -> List[Dict]:
        """Получает открытые алерты Dependabot из GitHub API."""
        if not self.token:
            log.warning("GITHUB_TOKEN not set, using mock dependabot alerts")
            return MOCK_DEPENDABOT_ALERTS
            
        try:
            path = f"/repos/{self.repo}/dependabot/alerts?state=open&per_page=100"
            return self.client._get(path, headers=self._gh_headers())
        except Exception as e:
            log.error(f"Failed to fetch dependabot alerts: {e}")
            return MOCK_DEPENDABOT_ALERTS

    def fetch_security_advisories(self) -> List[Dict]:
        """Получает Security Advisories из GitHub API."""
        if not self.token:
            return []
        try:
            path = f"/repos/{self.repo}/security-advisories"
            return self.client._get(path, headers=self._gh_headers())
        except Exception as e:
            log.warning(f"Failed to fetch security advisories: {e}")
            return []

    def calculate_sla_status(self, created_at_str: str, severity: str) -> Dict:
        """Вычисляет статус SLA для уязвимости."""
        created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
            
        sla_h = SLA_HOURS.get(severity.lower(), 720)
        deadline = created_at + timedelta(hours=sla_h)
        now = datetime.now(timezone.utc)
        
        remaining_s = (deadline - now).total_seconds()
        remaining_h = remaining_s / 3600
        
        if remaining_s < 0:
            status = "breached"
        elif remaining_h < (sla_h * 0.2):
            status = "at_risk"
        else:
            status = "on_track"
            
        return {
            "deadline": deadline.isoformat(),
            "remaining_h": round(remaining_h, 1),
            "status": status
        }

    def scan(self) -> Dict:
        """Collect vulnerability data and return raw scan results."""
        alerts = self.fetch_dependabot_alerts()
        self.fetch_security_advisories()

        processed_vulns = []
        stats: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        sla_breached = 0
        sla_at_risk = 0

        for alert in alerts:
            severity = alert.get("security_advisory", {}).get("severity", "medium").lower()
            created_at = alert.get("created_at")
            sla = self.calculate_sla_status(created_at, severity)
            vuln = {
                "id": f"VULN-{str(alert.get('number')).zfill(3)}",
                "source": "dependabot",
                "number": alert.get("number"),
                "cve_id": alert.get("security_advisory", {}).get("cve_id"),
                "severity": severity,
                "package": alert.get("dependency", {}).get("package", {}).get("name"),
                "affected_version": alert.get("dependency", {}).get("version"),
                "fixed_in": alert.get("fixed_in") or "N/A",
                "summary": alert.get("security_advisory", {}).get("summary"),
                "state": alert.get("state", "open"),
                "created_at": created_at,
                "sla_deadline": sla["deadline"],
                "sla_status": sla["status"],
                "hours_remaining": sla["remaining_h"],
                "remediation": f"Update {alert.get('dependency', {}).get('package', {}).get('name')} to version {alert.get('fixed_in') or 'latest'}",
                "jira_ticket": None,
            }
            processed_vulns.append(vuln)
            stats[severity] = stats.get(severity, 0) + 1
            if sla["status"] == "breached":
                sla_breached += 1
            if sla["status"] == "at_risk":
                sla_at_risk += 1

        return {
            "total": len(processed_vulns),
            "by_severity": stats,
            "sla_breached": sla_breached,
            "sla_at_risk": sla_at_risk,
            "vulnerabilities": processed_vulns,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }

    def run_checks(self) -> None:
        result = self.scan()
        stats = result["by_severity"]
        critical_high = [v for v in result["vulnerabilities"] if v["severity"] in ("critical", "high")]

        cc68_fail = stats["critical"] > 0 or stats["high"] > 0
        if cc68_fail:
            self._fail("CC6.8",
                       "Vulnerability Management Scan Summary",
                       result,
                       "CRITICAL" if stats["critical"] > 0 else "HIGH",
                       test_key="vuln.findings.cc6_8_critical_high")
        else:
            self._pass("CC6.8",
                       "Vulnerability Management Scan Summary",
                       result,
                       test_key="vuln.findings.cc6_8_critical_high")

        if critical_high:
            self._fail("CC7.3",
                       f"Critical and High Vulnerability Alerts ({len(critical_high)} open)",
                       {"critical_high": critical_high},
                       "CRITICAL" if stats["critical"] > 0 else "HIGH")
        else:
            self._pass("CC7.3",
                       "No critical/high vulnerability alerts",
                       {"total_open": result["total"]})
