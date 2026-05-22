#!/usr/bin/env python3
"""
github_agent.py — SOC 2 GitHub Compliance Scanner
Покрывает: CC4.2, CC5.3, CC6.4, CC6.8, CC7.3, CC7.5
"""

import os
import json
import logging
import requests
from datetime import datetime, timezone
from typing import Optional
from dotenv import load_dotenv
from evidence_client import EvidenceClient
from github_client import GitHubClient
from slack_notifier import SlackNotifier
from constants import CONTROLS_MAP_FILE, CI_STALE_DAYS

load_dotenv()

logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO  = os.getenv("GITHUB_REPO")          # owner/repo
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
SLACK_WEBHOOK_URL    = os.getenv("SLACK_WEBHOOK_URL")
COMPANY_NAME         = os.getenv("COMPANY_NAME", "Marineso")

# Контроли, которые этот агент закрывает
GITHUB_CONTROLS = {
    "CC4.2": "Deficiency Communication — GitHub Issues for FAIL findings",
    "CC5.3": "Change Management — CI/CD, branch protection, CODEOWNERS",
    "CC6.4": "Logical Access Restrictions — deploy keys, environments",
    "CC6.8": "Unauthorized Access Detection — secret scanning, dependabot",
    "CC7.3": "Threat Identification — security advisories, dependabot alerts",
    "CC7.5": "Breach Disclosure — security advisories process",
}

def _days_ago(iso: Optional[str]) -> Optional[int]:
    if not iso:
        return None
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - dt).days


class GitHubAgent:
    def __init__(self, controls_map: dict):
        self.controls_map = controls_map
        self.client  = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="github_agent")
        self.gh      = GitHubClient(GITHUB_TOKEN)
        self.notifier = SlackNotifier(SLACK_WEBHOOK_URL) if SLACK_WEBHOOK_URL else None
        self.findings = []
        self.results  = {code: "PASS" for code in GITHUB_CONTROLS}

    def _fail(self, code: str, title: str, content: dict, severity: str):
        ctrl_id = self.controls_map.get(code)
        if ctrl_id:
            self.client.create_evidence(
                control_id=ctrl_id,
                title=title,
                content=json.dumps({**content, "control": code, "severity": severity}),
                source="GITHUB",
            )
            self.client.update_control_status(ctrl_id, "FAIL")
        self.results[code] = "FAIL"
        self.findings.append({"control": code, "title": title, "severity": severity})
        icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
        print(f"  {icon} [{code}] {title} ({severity})")

    def _pass(self, code: str, title: str, content: dict):
        ctrl_id = self.controls_map.get(code)
        if ctrl_id:
            self.client.create_evidence(
                control_id=ctrl_id,
                title=title,
                content=json.dumps({**content, "control": code, "status": "PASS"}),
                source="GITHUB",
            )
            self.client.update_control_status(ctrl_id, "PASS")
        print(f"  ✅ [{code}] {title}")

    # ──────────────────────────────────────────
    # 1. CI/CD Workflows → CC5.3
    # ──────────────────────────────────────────
    def check_ci_cd(self):
        print("── Проверка 1: CI/CD Workflows (CC5.3) ──")
        workflows = self.gh.get_workflows(GITHUB_REPO)
        runs      = self.gh.get_workflow_runs(GITHUB_REPO, per_page=20)

        if not workflows:
            self._fail("CC5.3", "[GH] No CI/CD workflows found",
                       {"repo": GITHUB_REPO, "finding": "Repository has no GitHub Actions workflows"},
                       "HIGH")
            return

        recent_runs = [r for r in runs if (_days_ago(r.get("created_at")) or 999) <= CI_STALE_DAYS]
        failed_runs = [r for r in recent_runs if r.get("conclusion") == "failure"]

        if not recent_runs:
            self._fail("CC5.3", f"[GH] CI/CD not triggered in last {CI_STALE_DAYS} days",
                       {"repo": GITHUB_REPO, "workflows": len(workflows),
                        "finding": f"No workflow runs in last {CI_STALE_DAYS} days"},
                       "HIGH")
        elif failed_runs:
            self._fail("CC5.3", f"[GH] {len(failed_runs)} failed CI/CD runs in last {CI_STALE_DAYS}d",
                       {"repo": GITHUB_REPO, "failed": len(failed_runs), "total_recent": len(recent_runs),
                        "finding": "Recent CI/CD failures indicate broken change-management pipeline"},
                       "MEDIUM")
        else:
            self._pass("CC5.3", f"CI/CD active: {len(workflows)} workflows, {len(recent_runs)} runs",
                       {"workflows": len(workflows), "recent_runs": len(recent_runs)})

    # ──────────────────────────────────────────
    # 2. CODEOWNERS → CC5.3
    # ──────────────────────────────────────────
    def check_codeowners(self):
        print("── Проверка 2: CODEOWNERS (CC5.3) ──")
        found = (
            self.gh.get_file_content(GITHUB_REPO, "CODEOWNERS") or
            self.gh.get_file_content(GITHUB_REPO, ".github/CODEOWNERS") or
            self.gh.get_file_content(GITHUB_REPO, "docs/CODEOWNERS")
        )
        if not found:
            self._fail("CC5.3", "[GH] CODEOWNERS file missing",
                       {"repo": GITHUB_REPO,
                        "finding": "No CODEOWNERS — code reviews are not enforced by ownership rules"},
                       "MEDIUM")
        else:
            self._pass("CC5.3", "CODEOWNERS file present",
                       {"path": found.get("path"), "size": found.get("size")})

    # ──────────────────────────────────────────
    # 3. Deploy Keys → CC6.4
    # ──────────────────────────────────────────
    def check_deploy_keys(self):
        print("── Проверка 3: Deploy Keys (CC6.4) ──")
        keys = self.gh.get_deploy_keys(GITHUB_REPO)
        rw_keys = [k for k in keys if not k.get("read_only", True)]

        if rw_keys:
            for key in rw_keys:
                self._fail("CC6.4",
                           f"[GH] Read-write deploy key: {key.get('title', 'unknown')}",
                           {"id": key["id"], "title": key.get("title"),
                            "created_at": key.get("created_at"),
                            "finding": "Write-enabled deploy key bypasses PR/review process"},
                           "HIGH")
        elif not keys:
            self._pass("CC6.4", "No deploy keys (access via user tokens only)",
                       {"deploy_keys": 0})
        else:
            self._pass("CC6.4", f"All {len(keys)} deploy key(s) are read-only",
                       {"keys": [k.get("title") for k in keys]})

    # ──────────────────────────────────────────
    # 4. Environments + Protection Rules → CC6.4
    # ──────────────────────────────────────────
    def check_environments(self):
        print("── Проверка 4: Environments & protection (CC6.4) ──")
        envs = self.gh.get_environments(GITHUB_REPO)

        if not envs:
            self._fail("CC6.4", "[GH] No deployment environments configured",
                       {"repo": GITHUB_REPO,
                        "finding": "No environments means no deployment approval gates"},
                       "MEDIUM")
            return

        unprotected = []
        for env in envs:
            rules = env.get("protection_rules", [])
            has_review = any(r.get("type") == "required_reviewers" for r in rules)
            if not has_review:
                unprotected.append(env.get("name"))

        if unprotected:
            self._fail("CC6.4",
                       f"[GH] Environments without required reviewers: {', '.join(unprotected)}",
                       {"unprotected": unprotected,
                        "finding": "Deployments can run without human approval"},
                       "HIGH")
        else:
            self._pass("CC6.4",
                       f"All {len(envs)} environment(s) require reviewers",
                       {"environments": [e.get("name") for e in envs]})

    # ──────────────────────────────────────────
    # 5. Secret Scanning → CC6.8
    # ──────────────────────────────────────────
    def check_secret_scanning(self):
        print("── Проверка 5: Secret Scanning (CC6.8) ──")
        repo_info = self.gh.get_repo_info(GITHUB_REPO)
        ss = repo_info.get("security_and_analysis", {}).get("secret_scanning", {}) if repo_info else {}
        enabled = ss.get("status") == "enabled"

        if not enabled:
            self._fail("CC6.8", "[GH] Secret scanning not enabled",
                       {"repo": GITHUB_REPO,
                        "finding": "Secrets committed to repo will not be automatically detected"},
                       "HIGH")
            return

        alerts = self.gh.get_secret_scanning_alerts(GITHUB_REPO)
        open_alerts = [a for a in (alerts or []) if a.get("state") == "open"]
        if open_alerts:
            self._fail("CC6.8",
                       f"[GH] {len(open_alerts)} open secret scanning alert(s)",
                       {"open_count": len(open_alerts),
                        "types": list({a.get("secret_type") for a in open_alerts}),
                        "finding": "Active exposed secrets detected in repository"},
                       "CRITICAL")
        else:
            self._pass("CC6.8", "Secret scanning enabled, no open alerts",
                       {"enabled": True, "open_alerts": 0})

    # ──────────────────────────────────────────
    # 6. Dependabot → CC6.8, CC7.3
    # ──────────────────────────────────────────
    def check_dependabot(self):
        print("── Проверка 6: Dependabot alerts (CC6.8 / CC7.3) ──")
        alerts = self.gh.get_dependabot_alerts(GITHUB_REPO)

        if alerts is None:
            self._fail("CC6.8", "[GH] Dependabot alerts not enabled",
                       {"repo": GITHUB_REPO,
                        "finding": "Vulnerable dependencies will not be automatically flagged"},
                       "HIGH")
            self._fail("CC7.3", "[GH] No automated vulnerability scanning (Dependabot disabled)",
                       {"repo": GITHUB_REPO,
                        "finding": "Without Dependabot, threat identification for dependencies is manual"},
                       "HIGH")
            return

        critical = [a for a in alerts if a.get("security_advisory", {}).get("severity") == "critical"
                    and a.get("state") == "open"]
        high     = [a for a in alerts if a.get("security_advisory", {}).get("severity") == "high"
                    and a.get("state") == "open"]

        if critical:
            self._fail("CC7.3",
                       f"[GH] {len(critical)} CRITICAL dependency vulnerability alert(s)",
                       {"critical": len(critical), "high": len(high),
                        "packages": [a.get("dependency", {}).get("package", {}).get("name") for a in critical[:5]],
                        "finding": "Critical CVEs in dependencies — patching SLA breach risk"},
                       "CRITICAL")
        elif high:
            self._fail("CC7.3",
                       f"[GH] {len(high)} HIGH dependency vulnerability alert(s)",
                       {"high": len(high),
                        "finding": "High-severity CVEs in dependencies unresolved"},
                       "HIGH")
        else:
            open_total = len([a for a in alerts if a.get("state") == "open"])
            self._pass("CC7.3", f"Dependabot: no critical/high alerts ({open_total} total open)",
                       {"total_open": open_total})
            self._pass("CC6.8", "Dependabot enabled and no critical vulnerabilities",
                       {"total_open": open_total})

    # ──────────────────────────────────────────
    # 7. Security Advisories → CC7.3, CC7.5
    # ──────────────────────────────────────────
    def check_security_advisories(self):
        print("── Проверка 7: Security Advisories (CC7.3 / CC7.5) ──")
        advisories = self.gh.get_security_advisories(GITHUB_REPO)

        # Наличие процесса disclosure проверяем через SECURITY.md
        security_md = self.gh.get_file_content(GITHUB_REPO, "SECURITY.md")

        if not security_md:
            self._fail("CC7.5", "[GH] SECURITY.md not found",
                       {"repo": GITHUB_REPO,
                        "finding": "No vulnerability disclosure policy — breaches have no defined response path"},
                       "HIGH")
        else:
            self._pass("CC7.5", "SECURITY.md (disclosure policy) present",
                       {"path": "SECURITY.md", "size": security_md.get("size")})

        published = [a for a in advisories if a.get("state") == "published"]
        if published:
            self._pass("CC7.3", f"{len(published)} published security advisory/advisories",
                       {"count": len(published),
                        "latest": published[0].get("ghsa_id") if published else None})
        else:
            # Отсутствие advisories — не FAIL, а информационно
            self._pass("CC7.3", "No published security advisories (clean history)",
                       {"count": 0, "note": "No CVEs disclosed for this repo"})

    # ──────────────────────────────────────────
    # 8. GitHub Issues для FAIL → CC4.2
    # ──────────────────────────────────────────
    def create_fail_issues(self):
        print("── Проверка 8: FAIL → GitHub Issues (CC4.2) ──")
        # Берём FAIL контроли из Evidence Tracker
        try:
            api_key = os.getenv("EVIDENCE_API_KEY", "soc2-dev-key")
            resp = requests.get(
                f"{EVIDENCE_TRACKER_URL}/api/v1/controls/",
                headers={"X-API-Key": api_key},
                timeout=10,
            )
            controls = resp.json()
            if not isinstance(controls, list):
                print(f"  ⚠️  Unexpected response: {controls}")
                return
        except Exception as e:
            print(f"  ⚠️  Не удалось получить контроли: {e}")
            return

        fail_controls = [c for c in controls if c.get("status") == "FAIL"]
        if not fail_controls:
            self._pass("CC4.2", "No FAIL controls — no issues to create",
                       {"fail_count": 0})
            return

        # Существующие тикеты (чтобы не дублировать)
        existing = self.gh.get_issues(GITHUB_REPO, state="open", labels="soc2-finding")
        existing_titles = {i["title"] for i in existing}

        created = 0
        for ctrl in fail_controls:
            code  = ctrl.get("code", "UNKNOWN")
            title = f"[SOC2-FAIL] {code}: {ctrl.get('title', '')[:60]}"
            if title in existing_titles:
                continue

            body = (
                f"## SOC 2 Control Failure\n\n"
                f"**Control:** `{code}`  \n"
                f"**Title:** {ctrl.get('title')}  \n"
                f"**Status:** FAIL  \n\n"
                f"Автоматически создано `github_agent.py` по результатам сканирования.  \n"
                f"Необходимо расследование и план устранения.\n\n"
                f"---\n"
                f"_Evidence Tracker: {EVIDENCE_TRACKER_URL}/docs_"
            )
            issue = self.gh.create_issue(
                GITHUB_REPO, title, body, labels=["soc2-finding"]
            )
            if issue:
                created += 1
                print(f"  📋 Issue #{issue['number']}: {code}")

        if created:
            self._pass("CC4.2",
                       f"Created {created} GitHub Issue(s) for FAIL controls",
                       {"created": created, "total_fail": len(fail_controls)})
        else:
            self._pass("CC4.2", "All FAIL issues already tracked in GitHub",
                       {"existing": len(existing_titles)})

    # ──────────────────────────────────────────
    def notify_slack(self):
        if not self.notifier:
            return
        total   = len(self.findings)
        crit    = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high    = sum(1 for f in self.findings if f["severity"] == "HIGH")
        fail_cc = [c for c, s in self.results.items() if s == "FAIL"]

        lines = [
            f"🐙 *GitHub Compliance Scan — {COMPANY_NAME}*",
            f"Findings: {total} total | 🔴 CRITICAL: {crit} | 🟠 HIGH: {high}",
        ]
        if fail_cc:
            lines.append(f"Failed controls: {', '.join(fail_cc)}")
        else:
            lines.append("✅ All GitHub controls PASS")
        for f in self.findings[:8]:
            icon = "🔴" if f["severity"] == "CRITICAL" else "🟠"
            lines.append(f"  {icon} {f['title']}")
        self.notifier.send({"text": "\n".join(lines)})


def main(controls_map: dict | None = None):
    if not GITHUB_TOKEN:
        print("[ERROR] GITHUB_TOKEN не задан в .env")
        return
    if not GITHUB_REPO:
        print("[ERROR] GITHUB_REPO не задан в .env")
        return

    # Load controls_map.json if not provided
    if controls_map is None:
        if not os.path.exists(CONTROLS_MAP_FILE):
            print(f"Error: {CONTROLS_MAP_FILE} not found. Run controls_seed.py first.")
            return
        with open(CONTROLS_MAP_FILE) as f:
            controls_map = json.load(f)

    print(f"\n{'='*60}")
    print(f" SOC 2 GITHUB COMPLIANCE SCAN — {COMPANY_NAME}")
    print(f" Repo: {GITHUB_REPO}")
    print(f"{'='*60}\n")

    agent = GitHubAgent(controls_map)

    agent.check_ci_cd()
    print()
    agent.check_codeowners()
    print()
    agent.check_deploy_keys()
    print()
    agent.check_environments()
    print()
    agent.check_secret_scanning()
    print()
    agent.check_dependabot()
    print()
    agent.check_security_advisories()
    print()
    agent.create_fail_issues()
    print()

    print(f"{'='*60}")
    print(f" ИТОГ GITHUB AUDIT")
    print(f"{'='*60}")
    for code, status in agent.results.items():
        icon = "✅" if status == "PASS" else "❌"
        print(f"  {icon} {code}: {status} — {GITHUB_CONTROLS[code]}")

    total = len(agent.findings)
    crit  = sum(1 for f in agent.findings if f["severity"] == "CRITICAL")
    high  = sum(1 for f in agent.findings if f["severity"] == "HIGH")
    print(f"\n  Всего нарушений: {total}")
    if agent.findings:
        print(f"  CRITICAL: {crit} | HIGH: {high}")
    print(f"\n  Evidence → {EVIDENCE_TRACKER_URL}/docs (source=GITHUB)")
    print(f"{'='*60}")

    agent.notify_slack()


if __name__ == "__main__":
    main()
