import os
import sys
import json
import logging
import requests
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader
from dotenv import load_dotenv

# Import agents directly
from scanner import main as run_scanner
from hr_agent import main as run_hr
from github_agent import main as run_github
from survey_agent import main as run_survey
from prowler_runner import main as run_prowler
from policy_agent import main as run_policies
from controls_seed import main as seed_controls_logic
from seed_infrastructure import main as seed_infra_logic
from seed_okta import main as seed_okta_logic
from seed_github import main as seed_github_logic

# Import constants
from constants import (
    CONTROLS_MAP_FILE,
    PIPELINE_SEEDED_FILE,
    REPORTS_DIR,
    AUTO_CONTROLS
)

load_dotenv()

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Constants
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
LOCALSTACK_ENDPOINT = os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

WORKDIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(WORKDIR, "templates")

class Orchestrator:
    def __init__(self, force_seed: bool = False):
        self.force_seed = force_seed
        self.controls_map = self._load_controls_map()

    def _load_controls_map(self) -> dict:
        path = os.path.join(WORKDIR, CONTROLS_MAP_FILE)
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {}

    def health_check(self) -> bool:
        print(f"{'='*60}\n COMPLIANCE SANDBOX — PIPELINE START\n{'='*60}")
        
        # Evidence Tracker (Mandatory)
        try:
            resp = requests.get(f"{EVIDENCE_TRACKER_URL}/health", timeout=5)
            if resp.status_code == 200:
                print(f"[HEALTH] Evidence Tracker: OK ({EVIDENCE_TRACKER_URL})")
            else:
                print(f"[ERROR] Evidence Tracker returned {resp.status_code}")
                return False
        except Exception as e:
            print(f"[ERROR] Evidence Tracker: DOWN ({str(e)})")
            return False

        # AWS Mode Health Check
        if os.getenv("AWS_USE_LOCALSTACK", "true").lower() == "false":
            self.check_aws_real()
        else:
            # LocalStack (Optional)
            try:
                resp = requests.get(f"{LOCALSTACK_ENDPOINT}/_localstack/health", timeout=5)
                if resp.status_code == 200:
                    print(f"[HEALTH] LocalStack: OK ({LOCALSTACK_ENDPOINT})")
                else:
                    print(f"[WARN] LocalStack: UNHEALTHY ({resp.status_code})")
            except Exception as e:
                print(f"[WARN] LocalStack: DOWN ({str(e)})")

        # Okta (Optional)
        if OKTA_DOMAIN and OKTA_API_TOKEN:
            try:
                headers = {"Authorization": f"SSWS {OKTA_API_TOKEN}"}
                resp = requests.get(f"https://{OKTA_DOMAIN}/api/v1/users?limit=1", headers=headers, timeout=5)
                if resp.status_code == 200:
                    print(f"[HEALTH] Okta: OK ({OKTA_DOMAIN})")
                else:
                    print(f"[WARN] Okta: UNHEALTHY ({resp.status_code})")
            except Exception as e:
                print(f"[WARN] Okta: DOWN ({str(e)})")
        else:
            print("[WARN] Okta: NOT CONFIGURED (Skipping health check)")

        # GitHub (Optional)
        GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
        GITHUB_REPO = os.getenv("GITHUB_REPO")
        if GITHUB_TOKEN and GITHUB_REPO:
            try:
                headers = {
                    "Authorization": f"token {GITHUB_TOKEN}",
                    "Accept": "application/vnd.github.v3+json"
                }
                resp = requests.get(f"https://api.github.com/repos/{GITHUB_REPO}", headers=headers, timeout=5)
                if resp.status_code == 200:
                    print(f"[HEALTH] GitHub: OK ({GITHUB_REPO})")
                else:
                    print(f"[WARN] GitHub: UNHEALTHY ({resp.status_code})")
            except Exception as e:
                print(f"[WARN] GitHub: DOWN ({str(e)})")
        else:
            print("[WARN] GitHub: NOT CONFIGURED (Skipping health check)")
            
        return True

    def check_aws_real(self) -> bool:
        """Проверяет доступность реального AWS через boto3 STS."""
        import boto3
        try:
            sts = boto3.client("sts",
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1")
            )
            identity = sts.get_caller_identity()
            print(f"[HEALTH] Real AWS: OK (account={identity['Account']}, user={identity['UserId']})")
            return True
        except Exception as e:
            print(f"[WARN] Real AWS: {str(e)}")
            return False

    def seed_controls(self):
        if not self.controls_map:
            print("[SEED] controls_map.json not found — starting controls seed")
            seed_controls_logic()
            self.controls_map = self._load_controls_map()
        else:
            print("[SEED] controls_map.json found — skipping controls seed")

    def seed_infrastructure(self):
        path = os.path.join(WORKDIR, PIPELINE_SEEDED_FILE)
        should_seed = self.force_seed or not os.path.exists(path)
        
        if should_seed:
            print("[SEED] Starting infrastructure seeding...")
            seed_infra_logic()
            
            if OKTA_DOMAIN and OKTA_API_TOKEN:
                print("[SEED] Starting Okta seeding...")
                seed_okta_logic()
            
            GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
            GITHUB_REPO = os.getenv("GITHUB_REPO")
            if GITHUB_TOKEN and GITHUB_REPO:
                print("[SEED] Starting GitHub seeding...")
                seed_github_logic()

            with open(path, "w") as f:
                f.write(datetime.now().isoformat())
            print("[SEED] Infrastructure seeding complete")
        else:
            print(f"[SEED] {PIPELINE_SEEDED_FILE} found — skipping infrastructure seed")

    def run_scanner(self):
        print("[SCANNER] Starting tech scanner...")
        run_scanner(controls_map=self.controls_map)

    def run_hr_audit(self):
        print("[HR] Starting HR audit...")
        run_hr(controls_map=self.controls_map)

    def run_github_audit(self):
        print("[GITHUB] Starting GitHub agent audit...")
        run_github(controls_map=self.controls_map)

    def run_survey_audit(self):
        print("[SURVEY] Starting Personnel Awareness Survey...")
        run_survey(controls_map=self.controls_map)

    def generate_policies(self):
        if not os.getenv("OPENROUTER_API_KEY"):
            print("[POLICIES] OPENROUTER_API_KEY not set — skipping policy generation")
            return
        print("[POLICIES] Starting AI policy generation (context-aware)...")
        run_policies(controls_map=self.controls_map)
        print("[POLICIES] Policy generation complete")

    def run_prowler(self):
        if os.getenv("AWS_USE_LOCALSTACK", "true").lower() == "false":
            print("[PROWLER] Starting Prowler scan against real AWS...")
            run_prowler(controls_map=self.controls_map)
        else:
            print("[PROWLER] Skipping: AWS_USE_LOCALSTACK=true. Set to false for real AWS.")

    def generate_report(self):
        print(f"[REPORT] Fetching data from {EVIDENCE_TRACKER_URL}...")
        try:
            # Add API Key to headers for internal requests
            headers = {"X-API-Key": os.getenv("EVIDENCE_API_KEY", "soc2-dev-key")}
            controls_resp = requests.get(f"{EVIDENCE_TRACKER_URL}/api/v1/controls/?limit=100", headers=headers)
            evidence_resp = requests.get(f"{EVIDENCE_TRACKER_URL}/api/v1/evidence/?limit=200", headers=headers)
            
            controls = controls_resp.json()
            evidence_list = evidence_resp.json()
            
            # Aggregate stats
            summary = {"total_controls": len(controls), "pass": 0, "fail": 0, "pending": 0}
            auto_controls = {}
            
            for ctrl in controls:
                status = ctrl["status"].lower()
                if status == "pass":
                    summary["pass"] += 1
                elif status == "fail":
                    summary["fail"] += 1
                else:
                    summary["pending"] += 1
                
                if ctrl["code"] in AUTO_CONTROLS:
                    auto_controls[ctrl["code"]] = ctrl["status"]

            # Prepare violations
            violations = []
            for ev in evidence_list:
                control_code = "UNKNOWN"
                for ctrl in controls:
                    if str(ctrl["id"]) == str(ev["control_id"]):
                        control_code = ctrl["code"]
                        break
                
                # Extract severity and finding from content (JSON string)
                severity = "UNKNOWN"
                finding = ev["title"]
                try:
                    content = json.loads(ev["content"])
                    severity = content.get("severity", "MEDIUM")
                    finding = content.get("finding", ev["title"])
                except:
                    pass

                violations.append({
                    "control_code": control_code,
                    "title": ev["title"],
                    "finding": finding,
                    "severity": severity,
                    "source": ev["source"],
                    "created_at": ev["collected_at"]
                })

            report_data = {
                "generated_at": datetime.now().isoformat() + "Z",
                "framework": "SOC 2 Type II",
                "summary": summary,
                "auto_controls": auto_controls,
                "violations": violations
            }

            reports_path = os.path.join(WORKDIR, REPORTS_DIR)
            if not os.path.exists(reports_path):
                os.makedirs(reports_path)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path = os.path.join(reports_path, f"report_{timestamp}.json")
            html_path = os.path.join(reports_path, f"report_{timestamp}.html")

            with open(json_path, "w") as f:
                json.dump(report_data, f, indent=2)
            print(f"[REPORT] Saved: {REPORTS_DIR}/report_{timestamp}.json")

            self._save_html_report(report_data, html_path)
            print(f"[REPORT] Saved: {REPORTS_DIR}/report_{timestamp}.html")

            return summary, violations

        except Exception as e:
            print(f"[ERROR] Failed to generate report: {str(e)}")
            return None

    def _save_html_report(self, data: Dict[str, Any], path: str):
        try:
            env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)
            template = env.get_template("report.html.j2")
            html_content = template.render(**data)
            with open(path, "w") as f:
                f.write(html_content)
        except Exception as e:
            print(f"[ERROR] Jinja2 rendering failed: {e}")
            # Fallback to old f-string method if template missing (not ideal but safe)
            pass

    def notify_slack(self, summary: dict, violations: list):
        if not SLACK_WEBHOOK_URL:
            print("[SLACK] SLACK_WEBHOOK_URL not set — skipping notification")
            return
        
        try:
            from slack_notifier import SlackNotifier
            notifier = SlackNotifier(SLACK_WEBHOOK_URL)
            success = notifier.send_scan_summary(summary, violations)
            if success:
                print(f"[SLACK] Notification sent to Slack")
            else:
                print(f"[SLACK] Failed to send Slack notification")
        except Exception as e:
            print(f"[ERROR] Slack notification failed: {str(e)}")

    def run_full_pipeline(self, generate_policies_flag: bool = False, run_prowler_flag: bool = False):
        if not self.health_check():
            sys.exit(1)
            
        self.seed_controls()
        self.seed_infrastructure()
        
        # Technical Scan
        self.run_scanner()
        
        # GitHub Audit
        self.run_github_audit()
        
        # HR Audit
        self.run_hr_audit()
        
        # Personnel Survey
        self.run_survey_audit()
        
        # Report & Notify
        result = self.generate_report()
        
        if result:
            summary, violations = result
            self.notify_slack(summary, violations)
            
            if generate_policies_flag:
                self.generate_policies()
            
            if run_prowler_flag:
                self.run_prowler()
                
            print(f"{'='*60}\n PIPELINE COMPLETE\n PASS: {summary['pass']} | FAIL: {summary['fail']} | PENDING: {summary['pending']}\n{'='*60}")

def main():
    parser = argparse.ArgumentParser(description="Compliance Sandbox Orchestrator")
    parser.add_argument("--seed", action="store_true", help="Force re-seed infrastructure")
    parser.add_argument("--report", action="store_true", help="Generate report only")
    parser.add_argument("--check-only", action="store_true", help="Run health checks only")
    parser.add_argument("--policies", action="store_true", help="Generate AI policy drafts")
    parser.add_argument("--prowler", action="store_true", help="Run Prowler against real AWS after scan")
    parser.add_argument("--stack", nargs="+", help="Explicit list of client services (e.g. aws github okta)")
    parser.add_argument("--framework", default="soc2", choices=["soc2", "iso27001"], help="Framework to audit against")
    
    args = parser.parse_args()
    
    orchestrator = Orchestrator(force_seed=args.seed)
    
    if args.stack:
        from registry import get_controls_for_stack
        report = get_controls_for_stack(args.stack, args.framework)
        print(f"\n{'='*60}")
        print(f" STACK COVERAGE ANALYSIS ({args.framework.upper()})")
        print(f"{'='*60}")
        print(f" Services:    {args.stack}")
        print(f" Coverage:    {report['coverage_pct']}%")
        print(f" Covered:     {len(report['covered'])} controls")
        print(f" Gap (Gaps):  {len(report['not_covered'])} controls")
        print(f"{'='*60}\n")
    
    if args.check_only:
        if orchestrator.health_check():
            sys.exit(0)
        else:
            sys.exit(1)
            
    if args.report:
        orchestrator.generate_report()
        return

    orchestrator.run_full_pipeline(
        generate_policies_flag=args.policies,
        run_prowler_flag=args.prowler
    )

if __name__ == "__main__":
    main()
