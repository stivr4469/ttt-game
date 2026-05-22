import os
import json
import time
import argparse
import logging
import requests
import subprocess
from typing import Optional, Dict, List, Union
from openai import OpenAI, RateLimitError
from dotenv import load_dotenv
from evidence_client import EvidenceClient
from slack_notifier import SlackNotifier
from constants import CONTROLS_MAP_FILE

# OpenRouter free tier: 16 req/min → пауза 4 сек между запросами
_INTER_REQUEST_DELAY = float(os.getenv("POLICY_REQUEST_DELAY", "4.0"))
_RATE_LIMIT_RETRIES  = 4
_RATE_LIMIT_BACKOFF  = [10, 30, 60, 120]  # секунды ожидания при 429

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku")
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# Тип для sections: имя раздела → строка или список строк
SectionMap = Dict[str, Union[str, List[str]]]

POLICY_CONTROLS: Dict[str, Dict] = {
    "CC1.1": {
        "title": "Information Security and Ethical Values Policy",
        "description": "Commitment to integrity and ethical values by management",
        "audience": "All employees, management, board",
        "sections": {
            "Purpose": "Codify management's commitment to integrity and ethical behaviour per SOC 2 CC1.1",
            "Scope": "All employees, contractors, board members; all systems (Okta, AWS, GitHub, Slack)",
            "Tone at the Top": "CEO/CISO public commitment statement; mandatory code-of-conduct adoption for all staff",
            "Core Ethical Obligations": [
                "Prohibition on unauthorised access, data misuse, or misrepresentation of compliance status",
                "Mandatory disclosure of conflicts of interest (vendor relationships, personal financial interests)",
                "Zero tolerance for circumventing technical or procedural controls",
            ],
            "Training and Acknowledgement": "Annual code-of-conduct sign-off tracked in LMS; completion gates Okta activation for new hires",
            "Responsibilities": "Management sets example; HR enforces and tracks acknowledgements; CISO defines security obligations",
            "Enforcement": "Violations categorised as minor / moderate / severe; progressive discipline up to termination and legal action",
            "Review Cycle": "Annual; immediate update after significant leadership change or confirmed ethical violation",
        },
    },
    "CC1.2": {
        "title": "Corporate Governance and Board Oversight Policy",
        "description": "Board independence, oversight structure, and governance responsibilities for security",
        "audience": "Board of Directors, C-suite, Legal",
        "sections": {
            "Purpose": "Define the board's role in information-security governance per SOC 2 CC1.2",
            "Scope": "Board of Directors, Audit Committee, C-suite, Legal",
            "Board Structure and Independence": "Majority-independent board; Audit Committee includes at least one member with security/technology expertise",
            "Oversight Responsibilities": [
                "Quarterly security briefing by CISO covering control status and material incidents",
                "Annual review and approval of the SOC 2 audit scope and auditor engagement",
                "Formal risk acceptance for residual risks above the HIGH threshold",
            ],
            "Reporting to the Board": "CISO presents quarterly: failed controls, open remediations, material incidents, and risk register changes",
            "Management Accountability": "CISO owns the security programme and is accountable to the CEO; CEO is accountable to the board",
            "External Auditors": "Independence verified annually; engagement letter approved by Audit Committee; findings shared with full board",
            "Responsibilities": "Board Chair → agenda; Audit Committee → oversight; CISO → reporting; Legal → regulatory interface",
            "Enforcement": "Non-compliance with board directives escalated to full board within 5 business days",
            "Review Cycle": "Annual; triggered by board composition change, material incident, or SOC 2 audit finding",
        },
    },
    "CC1.3": {
        "title": "Organizational Structure and Reporting Lines Policy",
        "description": "Management hierarchy, reporting relationships, and accountability structure",
        "audience": "All employees, HR, Management",
        "sections": {
            "Purpose": "Document authority hierarchy and security accountability per SOC 2 CC1.3",
            "Scope": "All employees and contractors; HR and Management as owners",
            "Organisational Structure": "CISO reports to CEO; Security Engineering under CISO; Product Engineering is a separate line of business with dotted-line security accountability to CISO",
            "Security Roles": [
                "CISO: owns security programme, approves exceptions, escalates to board",
                "Security Engineer: operates technical controls, monitors Okta / AWS / GitHub alerts",
                "Compliance Lead: maintains evidence tracker, coordinates audits",
                "Engineering Lead: enforces secure-coding standards, approves PRs with security impact",
            ],
            "Incident Reporting Path": "Employee → Direct Manager → CISO → CEO → Board (each link ≤ 2 hours for P1)",
            "Access Follows Function": "Okta group membership mirrors job function; HR triggers access review within 24 h of role change",
            "Delegation of Authority": "Decisions requiring CISO sign-off: exception requests, Tier-1 vendor approvals, public security disclosures",
            "Responsibilities": "HR maintains and publishes org chart; CISO approves any security-role changes; all managers keep their team's Okta groups current",
            "Enforcement": "Unauthorised changes to reporting lines or role assignments treated as a policy violation",
            "Review Cycle": "Annual; immediate update after any reorganisation or CISO-level leadership change",
        },
    },
    "CC1.4": {
        "title": "Security Awareness Training Policy",
        "description": "Commitment to attract, develop and retain competent individuals",
        "audience": "HR, All employees",
        "sections": {
            "Purpose": "Ensure all personnel have the competence required for their security responsibilities per SOC 2 CC1.4",
            "Scope": "All full-time employees, part-time staff, and contractors; HR and CISO as owners",
            "Mandatory Training Programme": [
                "Annual security-awareness training (60 min minimum): data handling, phishing, incident reporting, acceptable use",
                "Role-based supplements: Engineering → OWASP Top 10 and secure-coding; Finance → fraud-awareness; HR → privacy and data retention",
                "New-hire onboarding: training must be completed within 30 days; Okta full access activated only after completion",
            ],
            "Phishing Simulation": "Quarterly simulated phishing campaigns; click rate tracked; employees who click receive immediate remedial micro-training",
            "Completion Tracking": "LMS records completion with timestamp; non-completion after 30-day grace period flags Okta account for access review",
            "Training Content Review": "CISO reviews and updates curriculum annually; immediate update required after confirmed phishing incident or major threat landscape change",
            "Responsibilities": "HR schedules and tracks completion; CISO defines curriculum and approves content; managers enforce for their direct reports",
            "Enforcement": "Repeated non-completion triggers Okta access suspension; failure to remediate phishing simulation counted in performance review",
            "Review Cycle": "Annual curriculum review; phishing simulation results reviewed quarterly by CISO",
        },
    },
    "CC1.5": {
        "title": "Accountability and Disciplinary Action Policy",
        "description": "Mechanisms to hold individuals accountable for internal control responsibilities",
        "audience": "HR, Management, Legal",
        "sections": {
            "Purpose": "Define mechanisms to hold individuals accountable for internal-control responsibilities per SOC 2 CC1.5",
            "Scope": "All employees, contractors; HR, Management, Legal as enforcers",
            "Accountability Framework": "Each SOC 2 control has a named owner in the compliance dashboard; owners are notified within 24 h when their control status changes to FAIL",
            "Violation Categories": [
                "Minor: procedural lapses (e.g. late evidence submission, missed training deadline)",
                "Moderate: negligent access misuse, failure to report a known vulnerability",
                "Severe: intentional circumvention of controls, data theft, fraud, suppression of audit evidence",
            ],
            "Disciplinary Process": "Investigation by HR + CISO → documented findings → proportional response reviewed by Legal for Severe cases",
            "Progressive Discipline": "Minor: verbal warning → written warning; Moderate: written warning → suspension; Severe: immediate termination + legal referral",
            "Control-Failure Response": "Control owner contacts CISO within 24 h; remediation ticket created in Jira; target SLA defined by risk tier",
            "Evidence Preservation": "All disciplinary records retained per legal requirements; stored outside reach of the implicated individual",
            "Responsibilities": "Manager initiates process; HR executes discipline; CISO advises on technical findings; Legal reviews Severe cases",
            "Enforcement": "Retaliation against whistleblowers is itself classified as a Severe violation",
            "Review Cycle": "Annual; triggered by material disciplinary incident or audit finding related to accountability gaps",
        },
    },
    "CC2.2": {
        "title": "Internal Communication Policy",
        "description": "Internal communication of security objectives and responsibilities",
        "audience": "All employees",
        "sections": {
            "Purpose": "Ensure security objectives and control responsibilities are communicated effectively throughout the organisation per SOC 2 CC2.2",
            "Scope": "All employees and contractors; Slack as primary async channel",
            "Communication Channels": [
                "#compliance-alerts (Slack): critical security events, P1/P2 incidents, control failures — monitored 24/7",
                "#security (Slack): general security updates, policy changes, threat intelligence",
                "Email: formal policy notices requiring acknowledgement",
                "GitHub repository: all policies and runbooks published and version-controlled",
            ],
            "Security Objective Communication": "CISO sends company-wide quarterly security update covering: threat landscape, control status summary, upcoming audit milestones",
            "Policy Distribution": "All policies published to the GitHub repository; employees acknowledge via e-signature; acknowledgement tracked in LMS",
            "Incident Communication": "P1/P2 incidents posted to #compliance-alerts within 1 hour of declaration; status updates every 2 hours until resolution",
            "Control Status Transparency": "Compliance dashboard accessible to all employees; weekly digest of control status changes sent to #compliance-alerts",
            "Responsibilities": "CISO owns security-communications calendar; HR distributes policy updates and tracks acknowledgements; all staff read and acknowledge within 14 days of publication",
            "Enforcement": "Failure to acknowledge policy updates within 14 days triggers Okta access review by HR",
            "Review Cycle": "Annual; immediate review triggered by communication gap identified in incident post-mortem",
        },
    },
    "CC2.3": {
        "title": "External Communication and Privacy Policy",
        "description": "External communication on data handling, privacy practices and security commitments",
        "audience": "Customers, public, regulators",
        "sections": {
            "Purpose": "Define standards for external communications regarding data handling, privacy practices, and security commitments per SOC 2 CC2.3",
            "Scope": "Customers, regulators, public; Customer Success, Legal, and CISO as owners of external communications",
            "Privacy Commitments": [
                "Data minimisation: collect only what is required for the stated purpose",
                "Purpose limitation: data not used beyond the scope disclosed at collection",
                "Retention limits: data deleted per the published retention schedule",
                "Data subject rights: access and deletion requests fulfilled within 30 days",
            ],
            "Security Disclosure Standards": "All public security statements (blog posts, press releases, breach notifications) require CISO and Legal approval before publication",
            "Vulnerability Disclosure": "Responsible-disclosure programme published; researchers directed to security@marineso.com; response SLA 5 business days",
            "Customer Breach Notification": "Confirmed data breach: customer notification within 72 hours; content and channel approved by Legal; regulator notification per applicable law",
            "SOC 2 Report Sharing": "SOC 2 Type II report shared with customers under NDA on request; CISO approves each disclosure",
            "Regulatory Inquiries": "All regulatory inquiries routed to Legal within 24 h; CISO provides technical input; no direct external response without Legal approval",
            "Responsibilities": "CISO approves all security disclosures; Legal approves regulatory responses and breach notifications; Customer Success handles customer requests within agreed SLA",
            "Enforcement": "Unauthorised external security disclosure by any employee = immediate escalation to CISO and Legal; potential termination",
            "Review Cycle": "Annual; triggered by data breach, new regulatory requirement, or material change to data-processing activities",
        },
    },
    "CC3.1": {
        "title": "Risk Assessment Objectives and Risk Appetite Policy",
        "description": "Specification of business objectives, risk tolerance and risk appetite statements",
        "audience": "Management, Board, Security team",
        "sections": {
            "Purpose": "Specify business objectives, risk tolerance, and risk-appetite statements per SOC 2 CC3.1",
            "Scope": "Management, Board of Directors, and Security team; all business functions",
            "Business Objectives": [
                "Service availability: 99.9% uptime SLA for the compliance dashboard and evidence APIs",
                "Data integrity: zero tolerance for unauthorised modification of audit evidence",
                "Customer trust: maintain SOC 2 Type II certification; disclose incidents transparently",
                "Regulatory compliance: meet all applicable data-protection and security regulations",
            ],
            "Risk Appetite Statement": [
                "LOW appetite: data breaches, integrity failures in audit evidence, prolonged service outages",
                "MEDIUM appetite: temporary performance degradation, minor process deviations with documented compensating controls",
                "HIGH appetite: new technology adoption, product experimentation in non-production environments",
            ],
            "Risk Scoring Methodology": "Likelihood (1–5) × Impact (1–5) = Risk Score; LOW < 8; MEDIUM 8–14; HIGH 15–19; CRITICAL ≥ 20",
            "Risk Acceptance Thresholds": "HIGH risks: require CISO written sign-off and documented mitigation plan; CRITICAL: require Board notification and approval",
            "Risk Categories": "Cyber / technical; operational; compliance / legal; third-party / vendor",
            "Responsibilities": "CISO owns and maintains the risk register; Management approves appetite statement annually; Board reviews risk posture quarterly",
            "Enforcement": "Risks accepted without documented CISO sign-off constitute an audit finding and must be remediated within 30 days",
            "Review Cycle": "Annual formal review; triggered by material business change, new product line, or CRITICAL risk event",
        },
    },
    "CC3.2": {
        "title": "Risk Identification and Analysis Policy",
        "description": "Risk identification, analysis and response procedures",
        "audience": "Management, Security team",
        "sections": {
            "Purpose": "Establish a systematic process for identifying, analysing, and responding to risks per SOC 2 CC3.2",
            "Scope": "Management, Security team, and all system owners; covers all production systems",
            "Risk Identification Methods": [
                "Continuous automated scanning: AWS Config rules, Okta anomaly detection, GitHub secret scanning",
                "Annual formal risk assessment: structured interviews with system owners and threat-modelling sessions",
                "Vendor intelligence: security bulletins from Okta, AWS, and GitHub incorporated within 48 h",
                "New-system onboarding: mandatory threat model required before production deployment",
            ],
            "Risk Register": "Maintained in the compliance dashboard; each entry includes: description, likelihood, impact, score, owner, response, and due date",
            "Analysis Methodology": "Qualitative risk matrix (Likelihood × Impact per CC3.1 scoring); supported by threat modelling (STRIDE) for new features and integrations",
            "Risk Response Options": [
                "Mitigate: implement control to reduce likelihood or impact; document in Jira as remediation ticket",
                "Accept: CISO sign-off required; re-evaluated annually",
                "Transfer: cyber-insurance or contractual liability shift; Legal must approve",
                "Avoid: discontinue the activity or system that creates the risk",
            ],
            "Responsibilities": "Security team executes assessments and maintains the risk register; system owners provide accurate input; CISO approves all risk-response decisions",
            "Enforcement": "Systems deployed to production without a completed risk assessment are immediately suspended pending review",
            "Review Cycle": "Annual formal assessment; continuous via automated monitoring; ad-hoc review triggered by any CRITICAL or HIGH risk event",
        },
    },
    "CC3.3": {
        "title": "Fraud Risk Assessment Policy",
        "description": "Assessment of fraud risk scenarios including misappropriation, corruption, and reporting fraud",
        "audience": "Management, Finance, Legal, Internal Audit",
        "sections": {
            "Purpose": "Establish a formal fraud-risk assessment framework per SOC 2 CC3.3; zero-tolerance stance on intentional deception or asset misappropriation",
            "Scope": "All employees, contractors, and vendors; all systems including Okta, AWS (us-east-1), GitHub, and the compliance dashboard",
            "Fraud Risk Categories": [
                "Identity and access abuse: Okta privilege escalation, credential stuffing, MFA bypass",
                "Infrastructure misuse: unauthorised AWS resource provisioning, cryptomining, data exfiltration via S3",
                "Source-code manipulation: GitHub backdoors, logic bombs, unauthorised commits to main, dependency tampering",
                "Compliance misrepresentation: falsification of evidence in the Evidence Tracker, manipulation of control-status metrics",
                "Financial fraud: misappropriation of company funds, falsified vendor invoices",
            ],
            "Risk Analysis Methodology": "Annual fraud-risk assessment using Likelihood × Impact matrix (1–5 scale) per CC3.1; risks tiered HIGH / MEDIUM / LOW; assessment led by CISO and Internal Audit",
            "Monitoring and Detection": "Okta audit logs reviewed weekly; AWS CloudTrail anomaly alerts; GitHub audit log monitored for force-pushes and admin actions; compliance dashboard tracks evidence integrity via SHA-256 hashes",
            "Whistleblower Protection": "Zero-retaliation policy; suspected fraud reported to #compliance-alerts or directly to Legal; identity of reporter protected; HR investigation process initiated within 24 h",
            "Incident Escalation": "Suspected fraud → #compliance-alerts → CISO + Legal within 24 h → Board notification if confirmed",
            "Responsibilities": "CISO leads fraud-risk programme; Finance owns financial-fraud detection; Engineering Lead owns code-integrity controls; all staff obligated to report via #compliance-alerts",
            "Enforcement": "Confirmed fraud results in immediate termination, revocation of all access (Okta + GitHub + AWS), and referral to legal authorities; vulnerabilities that enabled the fraud are remediated within 48 h",
            "Review Cycle": "Annual minimum; ad-hoc review triggered by: addition of a new core system, confirmed fraud incident, or material architecture change",
        },
    },
    "CC4.1": {
        "title": "Monitoring Activities and Control Evaluation Policy",
        "description": "Ongoing and separate evaluations of internal controls effectiveness",
        "audience": "Management, Compliance team, Internal Audit",
        "sections": {
            "Purpose": "Establish continuous and point-in-time evaluation of internal-control effectiveness per SOC 2 CC4.1",
            "Scope": "All 33 SOC 2 controls; Management, Compliance team, and Internal Audit as evaluators",
            "Continuous Monitoring": [
                "Automated compliance dashboard refreshes control status daily from Okta, AWS, and GitHub evidence agents",
                "Evidence stored with SHA-256 hash to detect tampering",
                "Slack #compliance-alerts receives real-time notifications on any control status change to FAIL",
            ],
            "Control Evaluation Types": [
                "Automated: technical controls validated by agents (access reviews, MFA coverage, encryption status)",
                "Manual: governance and policy controls evaluated quarterly via structured review checklist",
                "Hybrid: controls with both a technical and a procedural component evaluated using both methods",
            ],
            "Deficiency Reporting": "FAIL status triggers: (1) Jira remediation ticket within 24 h, (2) CISO notification same day, (3) escalation to Management if unremediated beyond SLA",
            "Separate Evaluations": "Annual internal audit by Compliance Lead; biennial independent SOC 2 Type II audit by external auditor",
            "Evidence Collection": "Automated agents collect evidence from Okta, AWS, and GitHub; each evidence record includes source, timestamp, SHA-256 hash, and auditor verdict",
            "Responsibilities": "Compliance Lead monitors dashboard daily; CISO reviews aggregated status weekly; Internal Audit conducts annual point-in-time assessment",
            "Enforcement": "Controls with unremediated FAILs beyond agreed SLA are escalated to Management and included as findings in the next board report",
            "Review Cycle": "Continuous automated monitoring; annual formal evaluation; policy reviewed annually or after a control-failure spike",
        },
    },
    "CC5.1": {
        "title": "Control Activities Selection Policy",
        "description": "Selection and development of control activities to mitigate risks",
        "audience": "Management, Compliance team",
        "sections": {
            "Purpose": "Define how control activities are selected, developed, and implemented to mitigate risks per SOC 2 CC5.1",
            "Scope": "Management, Compliance team, and Engineering; all production systems and processes",
            "Control Selection Criteria": [
                "Risk-based: controls address risks identified in the CC3.2 risk register",
                "Mapped to AICPA Trust Services Criteria: each control traces to at least one TSC requirement",
                "Feasibility assessed: implementation cost weighed against risk reduction before adoption",
            ],
            "Control Types": [
                "Preventive: Okta MFA enforcement, GitHub branch-protection rules, AWS IAM least-privilege",
                "Detective: AWS CloudTrail, Okta audit logs, GitHub audit log, compliance-dashboard anomaly alerts",
                "Corrective: incident-response runbooks, automated rollback in GitHub Actions, Jira remediation tickets",
            ],
            "Automation-First Principle": "Controls implemented as code wherever feasible (AWS Config rules, GitHub Actions checks, Okta policies); manual controls documented with step-by-step procedures",
            "Control Documentation": "Each control recorded in the compliance dashboard with: owner, type, frequency, evidence collection method, and test procedure",
            "Control Testing": "Automated controls: tested in CI on every deployment; high-risk controls: quarterly manual test; all controls: annual formal test",
            "Change Control for Controls": "New controls require CISO approval; changes to existing controls follow the Change Management Policy (CC5.3); removals require Board notification if they affect a TSC requirement",
            "Responsibilities": "CISO selects and approves controls; Compliance team documents and schedules tests; Engineering implements technical controls and maintains automation",
            "Enforcement": "Unapproved control removals constitute an audit finding; undocumented controls excluded from the SOC 2 evidence package",
            "Review Cycle": "Annual; triggered by new risk-assessment findings, failed control tests, or material changes to the production environment",
        },
    },
    "CC5.3": {
        "title": "Change Management Policy",
        "description": "Deployment of changes through policies and procedures",
        "audience": "Engineering, DevOps",
        "sections": {
            "Purpose": "Control the deployment of changes to production systems to minimise risk and maintain compliance per SOC 2 CC5.3",
            "Scope": "All production systems: AWS (us-east-1), GitHub (stivr4469/compliance-sandbox), Okta, and the compliance dashboard",
            "Change Categories": [
                "Standard: low-risk, pre-approved template changes (e.g. dependency patch, config flag); no additional approval required",
                "Normal: new features, architectural changes; requires PR review by at least one approver and automated-test passage",
                "Emergency: critical fixes for active incidents; requires CISO or Engineering Lead verbal approval; formal documentation in Jira within 24 h",
            ],
            "Pre-Deployment Requirements": [
                "Pull request with description and test evidence in GitHub",
                "Minimum one peer-review approval (two for security-impacting changes)",
                "All automated tests and security scans pass in GitHub Actions CI pipeline",
            ],
            "Production Deployment Process": "Deployments executed only from the main branch via GitHub Actions pipeline; direct manual changes to AWS are prohibited except during declared emergencies",
            "Rollback Procedures": "Every deployment must include a documented rollback step; automated rollback triggered by health-check failure within 5 minutes of deployment",
            "Change Freeze Periods": "No Normal or Emergency changes during the SOC 2 audit window unless approved by CISO; board-declared freeze periods published in #compliance-alerts at least 48 h in advance",
            "Responsibilities": "Engineering Lead approves Normal changes; CISO approves security-impacting or infrastructure changes; all engineers follow the pipeline and do not bypass it",
            "Enforcement": "Unauthorised production changes trigger an immediate incident investigation; confirmed bypass = Severe disciplinary action per CC1.5",
            "Review Cycle": "Annual; triggered by change-related incident or external audit finding",
        },
    },
    "CC7.4": {
        "title": "Incident Response Policy",
        "description": "Incident response program including detection, response and recovery",
        "audience": "Security team, Engineering, Management",
        "sections": {
            "Purpose": "Define the incident-detection, response, and recovery programme per SOC 2 CC7.4",
            "Scope": "All production systems; Security team, Engineering, and Management as participants",
            "Incident Classification": [
                "P1 Critical: confirmed data breach, ransomware, or full service outage — Response SLA 1 hour",
                "P2 High: account compromise, significant performance degradation, partial data exposure — Response SLA 4 hours",
                "P3 Medium: suspicious activity without confirmed breach, failed control requiring investigation — Response SLA 24 hours",
                "P4 Low: minor anomaly, informational alert, no confirmed impact — Response SLA 72 hours",
            ],
            "Detection Sources": [
                "Okta anomaly-detection alerts forwarded to #compliance-alerts",
                "AWS CloudWatch alarms and CloudTrail event rules",
                "GitHub secret-scanning and push-protection alerts",
                "Employee reports via #compliance-alerts or security@marineso.com",
            ],
            "SIRT Composition": "Incident Commander: CISO; Security Engineer: technical response lead; Engineering Lead: system recovery; Legal: activated for P1 with potential data breach",
            "Response Phases": [
                "Detection: identify and validate the event; assign severity",
                "Containment: limit blast radius — revoke Okta session, isolate AWS resource via security group, lock affected GitHub branch",
                "Eradication: remove root cause — patch, credential rotation, malicious code removal",
                "Recovery: restore service from known-good state; validate integrity before re-opening traffic",
                "Post-Mortem: 5 business days after resolution; root cause, timeline, preventive actions documented in GitHub",
            ],
            "External Communication": "Customer notification within 72 hours for confirmed data breach (CC2.3); regulatory notification per applicable law; all external statements approved by Legal",
            "Responsibilities": "CISO acts as Incident Commander; all employees must report suspected incidents within 1 hour of detection; Legal handles all external regulatory notifications",
            "Enforcement": "Failure to report a known incident = Severe violation per CC1.5; mandatory participation in SIRT when paged",
            "Review Cycle": "Annual tabletop exercise; post-mortem required after every P1 and P2; policy reviewed annually or after a material incident",
        },
    },
    "CC9.1": {
        "title": "Business Continuity Policy",
        "description": "Risk mitigation for business disruptions and recovery procedures",
        "audience": "Management, All employees",
        "sections": {
            "Purpose": "Ensure critical operations continue during and recover rapidly after disruptions per SOC 2 CC9.1",
            "Scope": "All critical systems: AWS (us-east-1), Okta, GitHub, compliance dashboard; Management and Engineering as owners",
            "Recovery Objectives": [
                "Compliance dashboard: RTO 4 h / RPO 1 h",
                "Okta (SaaS): covered by Okta's 99.99% SLA; internal RTO 1 h for alternative authentication",
                "AWS infrastructure: RTO 2 h / RPO 30 min via automated snapshot restore",
                "GitHub: mirrored backup; RTO 4 h if GitHub.com is unavailable",
            ],
            "Critical Business Functions": [
                "Evidence collection and audit-trail preservation",
                "Compliance dashboard availability for internal and auditor access",
                "Okta authentication for employee access to all systems",
            ],
            "Backup Procedures": [
                "AWS: automated daily EBS snapshots; RDS continuous WAL-based backup; retained 30 days",
                "GitHub: daily mirror to S3 bucket in a secondary AWS region",
                "Evidence database: continuous WAL archiving; point-in-time recovery up to 1 h before failure",
            ],
            "Recovery Procedures": "Documented runbooks per service stored in the GitHub repository; each runbook includes: trigger criteria, step-by-step recovery, verification checklist, and escalation contact",
            "Crisis Communication": "All-hands status updates via Slack #compliance-alerts; customer communication per CC2.3; regulatory notification per applicable law",
            "Business Impact Analysis": "Annual BIA conducted by CISO + Engineering Lead; critical systems identified, dependencies mapped, RTO/RPO validated",
            "Responsibilities": "CISO owns the BCP programme; Engineering Lead owns runbooks and executes recovery; Management declares a continuity event",
            "Testing": "Annual tabletop exercise; semi-annual backup-restoration test with results documented and reviewed by CISO",
            "Enforcement": "Untested recovery procedures constitute an audit finding; failed restoration test triggers immediate runbook update within 30 days",
            "Review Cycle": "Annual; triggered by BCP activation, failed test, or addition of a new critical system",
        },
    },
    "CC9.2": {
        "title": "Vendor Management Policy",
        "description": "Vendor and business partner risk assessment and management",
        "audience": "Procurement, Management, Legal",
        "sections": {
            "Purpose": "Assess and manage risk from third-party vendors and business partners per SOC 2 CC9.2",
            "Scope": "All vendors with data access or system integration; Procurement, Management, and Legal as owners",
            "Vendor Tiering": [
                "Tier 1 (data processors with access to customer or employee PII): annual security assessment, mandatory SOC 2 / ISO 27001 report, DPA required",
                "Tier 2 (SaaS tools with internal data access, e.g. Okta, GitHub, Slack, AWS): biennial assessment, SOC 2 report review at renewal",
                "Tier 3 (utilities and commodity services with no data access): as-needed assessment",
            ],
            "Current Critical Vendors": [
                "Okta (Identity Provider, Tier 1): SOC 2 Type II certified; reviewed annually",
                "AWS (Cloud Infrastructure, Tier 1): SOC 2 Type II certified; reviewed annually",
                "GitHub (Source Code Management, Tier 2): SOC 2 Type II certified; reviewed biennially",
                "OpenRouter (AI API, Tier 2): security questionnaire completed; no PII transmitted",
                "Slack (Internal Communications, Tier 2): SOC 2 Type II certified; reviewed biennially",
            ],
            "Onboarding Requirements": "Security questionnaire completed; SOC 2 or equivalent report reviewed; Data Processing Agreement signed; Okta access scoped to minimum required permissions; CISO approves Tier-1 onboarding",
            "Ongoing Monitoring": "Annual assessment for Tier 1; SOC 2 report refreshed at contract renewal; Slack #compliance-alerts receives alerts on vendor-reported security incidents",
            "Offboarding": "Okta SSO access revoked on the same day contract ends; data deletion confirmed in writing within 30 days; DPA termination clause invoked",
            "Sub-Processor Management": "Vendors must disclose all sub-processors at onboarding; notify Marineso of material sub-processor changes at least 30 days in advance",
            "Responsibilities": "Procurement initiates vendor intake and collects questionnaire; CISO approves Tier-1 onboarding and annual assessments; Legal reviews and signs all contracts and DPAs",
            "Enforcement": "Vendors with lapsed assessments have Okta access suspended pending renewal; contracts with missing DPAs are non-compliant and referred to Legal",
            "Review Cycle": "Annual programme review; immediate review triggered by vendor security incident, breach notification, or material change to sub-processors",
        },
    },
    # ── Vanta-style дополнительные политики ──────────────────────────────────
    "CC6.1": {
        "title": "Access Control Policy",
        "description": "Logical access security — who can access what, how access is granted and revoked",
        "audience": "All employees, IT, Security, HR",
        "sections": {
            "Purpose": "Define how access to systems and data is granted, reviewed, and revoked per SOC 2 CC6.1",
            "Scope": "All systems: AWS, Okta, GitHub, Slack, production databases; all employee and contractor accounts",
            "Access Provisioning": [
                "Access requests submitted via ticketing system with manager approval",
                "New hire access provisioned within 1 business day of Okta activation",
                "Least-privilege principle: minimum access required for job function",
                "Privileged access (admin, root) requires CISO written approval and dual sign-off",
            ],
            "Authentication Requirements": [
                "MFA mandatory for all accounts (Okta TOTP or hardware key)",
                "Password minimum: 12 characters, complexity enabled, no reuse of last 12",
                "AWS root account: MFA hardware key required; access keys permanently disabled",
                "Service accounts: rotate credentials every 90 days; no interactive login",
            ],
            "Access Reviews": "Quarterly access review by managers; annual privileged-access review by CISO; results documented in evidence tracker",
            "Access Revocation": "Terminated employees: Okta deactivated within 2 hours of HR notification; AWS keys revoked immediately; GitHub access removed same day",
            "Remote Access": "VPN required for non-SaaS internal resources; zero-trust principles applied; session timeout 8 hours",
            "Responsibilities": "HR triggers provisioning/deprovisioning; IT executes; CISO audits quarterly",
            "Enforcement": "Unauthorized access attempts logged and alerted via CloudTrail + SIEM; policy violations escalated per Disciplinary Policy",
            "Review Cycle": "Annual; triggered by security incident, personnel change, or audit finding",
        },
    },
    "CC6.5": {
        "title": "Asset Management Policy",
        "description": "Inventory, classification, and secure disposal of physical and digital assets",
        "audience": "All employees, IT, Facilities",
        "sections": {
            "Purpose": "Maintain accurate asset inventory and ensure secure handling throughout asset lifecycle per SOC 2 CC6.5",
            "Scope": "All company-owned and personal devices used for company work; all cloud resources (AWS, SaaS subscriptions); data assets",
            "Asset Inventory": [
                "All hardware registered in MDM (Jamf for macOS, Intune for Windows) within 24 hours of issue",
                "Cloud assets tagged with owner, environment (prod/staging/dev), and data classification",
                "SaaS subscriptions inventoried in vendor management system with owner and data-access level",
            ],
            "Asset Classification": [
                "Confidential: customer PII, audit evidence, credentials → encrypted at rest and in transit, access logged",
                "Internal: source code, internal docs → access restricted to employees; MFA required",
                "Public: marketing materials, open-source code → no restriction",
            ],
            "Endpoint Security": [
                "FileVault (macOS) / BitLocker (Windows) full-disk encryption mandatory",
                "EDR agent (CrowdStrike Falcon / Microsoft Defender) installed and reporting",
                "OS patched within 14 days of critical CVE; verified by MDM compliance report",
                "Screen lock: maximum 5 minutes inactivity timeout enforced by MDM policy",
            ],
            "Secure Disposal": "Hard drives wiped to NIST 800-88 standard before disposal; certificate retained 3 years; cloud resources deleted via Terraform destroy with audit log",
            "Lost or Stolen Devices": "Immediate report to IT; remote wipe initiated within 1 hour via MDM; incident documented per Incident Response Policy",
            "Responsibilities": "IT owns hardware lifecycle; Engineering owns cloud resources; CISO owns classification scheme",
            "Review Cycle": "Asset inventory reviewed quarterly; policy annually",
        },
    },
    "CC5.2": {
        "title": "Information Security Policy",
        "description": "Umbrella information security policy covering all controls and employee obligations",
        "audience": "All employees, contractors, board",
        "sections": {
            "Purpose": "Establish the overarching information security framework protecting Marineso assets and customer data per SOC 2 CC5.2",
            "Scope": "All employees, contractors, and third parties with access to Marineso systems or data; all environments (production, staging, development)",
            "Security Principles": [
                "Confidentiality: data accessed only by authorised personnel with legitimate need",
                "Integrity: data modified only through authorised, audited processes",
                "Availability: systems maintained to meet defined SLAs and RTO/RPO targets",
                "Least privilege and separation of duties enforced for all roles",
            ],
            "Mandatory Controls": [
                "MFA on all user accounts (enforced via Okta)",
                "Full-disk encryption on all endpoints (enforced via MDM)",
                "Secrets managed via environment variables or secrets manager — never hardcoded",
                "All production changes reviewed via pull request with at least 1 approver",
                "Annual security awareness training completed before system access granted",
            ],
            "Risk Management": "Annual risk assessment; risks rated by likelihood × impact; HIGH risks remediated within 30 days; risk register reviewed quarterly by CISO",
            "Acceptable Use": "Company systems used for business purposes; personal use incidental and permitted if it does not introduce security risk; no circumvention of controls",
            "Incident Reporting": "All suspected incidents reported to security@marineso.com within 1 hour of discovery; see Incident Response Policy for full procedure",
            "Compliance": "Policy reviewed annually and after material changes; all employees sign acknowledgement; violations subject to disciplinary action",
            "Responsibilities": "CISO owns the policy; all employees are responsible for compliance; managers ensure team adherence",
            "Review Cycle": "Annual; after significant incident, regulatory change, or business model change",
        },
    },
}

# 9 контролей, закрываемых только через governance-документы
GOVERNANCE_CONTROLS = {
    "CC1.1", "CC1.2", "CC1.3", "CC1.5",
    "CC2.2", "CC2.3",
    "CC3.1", "CC3.2", "CC3.3",
    "CC4.1",
    "CC5.1",
    "CC9.1",
}


def _build_sections_outline(sections: SectionMap) -> str:
    """Строит текстовый outline из словаря секций для промта."""
    lines: List[str] = []
    for section_name, content in sections.items():
        lines.append(f"### {section_name}")
        if isinstance(content, list):
            for item in content:
                lines.append(f"  - {item}")
        else:
            lines.append(f"  {content}")
        lines.append("")
    return "\n".join(lines).strip()


class PolicyAgent:
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, use_gemini_cli: bool = False):
        self.use_gemini_cli = use_gemini_cli
        if not use_gemini_cli:
            self.client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=api_key,
                default_headers={
                    "HTTP-Referer": "compliance-sandbox",
                    "X-Title": "Compliance Sandbox Auditor",
                }
            )
            self.model = model

    def fetch_recent_violations(self) -> List[str]:
        try:
            resp = requests.get(f"{EVIDENCE_TRACKER_URL}/api/v1/evidence/?limit=50", timeout=10)
            resp.raise_for_status()
            evidence = resp.json()
            return [f"{ev.get('title')} ({ev.get('source')})" for ev in evidence]
        except Exception as e:
            logger.warning(f"Could not fetch recent violations: {e}")
            return []

    def fetch_failed_controls(self) -> List[str]:
        try:
            resp = requests.get(f"{EVIDENCE_TRACKER_URL}/api/v1/controls/?limit=100", timeout=10)
            resp.raise_for_status()
            controls = resp.json()
            return [c['code'] for c in controls if c.get('status', '').upper() == "FAIL"]
        except Exception as e:
            logger.warning(f"Could not fetch failed controls: {e}")
            return []

    def collect_environment_context(self) -> dict:
        return {
            "company_name": os.getenv("COMPANY_NAME", "Acme Corp"),
            "github_repo": os.getenv("GITHUB_REPO", ""),
            "okta_domain": os.getenv("OKTA_DOMAIN", ""),
            "slack_channel": "#compliance-alerts",
            "aws_region": os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            "evidence_tracker_url": EVIDENCE_TRACKER_URL,
            "recent_violations": self.fetch_recent_violations(),
            "failed_controls": self.fetch_failed_controls(),
        }

    def generate_policy(self, control_code: str, control_info: dict, env_context: dict) -> str:
        sections: SectionMap = control_info.get("sections", {})
        sections_outline = _build_sections_outline(sections) if sections else (
            "Purpose | Scope | Policy Statement | Responsibilities | Procedures | Enforcement | Review Cycle"
        )

        prompt = f"""You are a senior compliance expert writing SOC 2 Type II policy documents for a real company.

Write a professional policy document for control {control_code}: {control_info['title']}.

COMPANY CONTEXT — reference these specific details throughout the document (do NOT use generic placeholders):
- Company: {env_context['company_name']}
- GitHub repository: {env_context['github_repo']}
- Identity provider: Okta ({env_context['okta_domain']})
- Incident escalation: Slack {env_context['slack_channel']}
- Cloud infrastructure: AWS ({env_context['aws_region']})
- Compliance dashboard: {env_context['evidence_tracker_url']}
- Audience: {control_info.get('audience', 'All employees')}

CURRENT COMPLIANCE STATE — incorporate relevant findings where appropriate:
- Controls currently FAILING: {env_context['failed_controls']}
- Recent violations: {env_context['recent_violations'][:3]}

REQUIRED DOCUMENT STRUCTURE — write EVERY section below, covering the listed topics in detail:

{sections_outline}

WRITING RULES:
- English only; formal but readable tone
- Name actual tools (Okta, AWS, GitHub, Slack) in every relevant section — never write "the identity provider" or "the source control system"
- Each section must be substantive (3–6 sentences minimum or a proper bullet list)
- Total length: 650–850 words
- Format: Markdown, ## for top-level sections, bullet lists where the outline shows list items
- End with the Review Cycle section
- Return ONLY the policy document — no preamble, no explanations, no closing remarks"""

        try:
            if self.use_gemini_cli:
                result = subprocess.run(
                    ["gemini", "-p", prompt, "-y"],
                    input=prompt,
                    capture_output=True, text=True, timeout=180
                )
                if result.returncode != 0:
                    raise Exception(f"Gemini CLI error: {result.stderr}")
                output = result.stdout
                # Обрезать Gemini-internal Task Status section
                for marker in ["---\n\n### Task Status", "---\n\n## Task", "\n### Task Status", "\n## Статус:"]:
                    if marker in output:
                        output = output[:output.index(marker)]
                # Убрать служебные строки CLI
                lines = output.splitlines()
                clean = [l for l in lines if not any(x in l for x in [
                    "Ripgrep", "MCP issues", "Error executing tool",
                    "Falling back", "YOLO mode"
                ])]
                return "\n".join(clean).strip()
            else:
                for attempt, wait in enumerate(_RATE_LIMIT_BACKOFF):
                    try:
                        response = self.client.chat.completions.create(
                            model=self.model,
                            messages=[{"role": "user", "content": prompt}],
                        )
                        return response.choices[0].message.content
                    except RateLimitError as e:
                        if attempt == len(_RATE_LIMIT_BACKOFF) - 1:
                            raise
                        logger.warning(
                            f"Rate limit hit for {control_code} (attempt {attempt + 1}), "
                            f"waiting {wait}s..."
                        )
                        time.sleep(wait)
        except Exception as e:
            logger.error(f"Error generating policy for {control_code}: {e}")
            raise


def main(controls_map: dict | None = None):
    parser = argparse.ArgumentParser(description="AI Policy Generator Agent")
    parser.add_argument("--control", type=str, help="Generate policy for a specific control code")
    parser.add_argument("--list", action="store_true", help="List all controls requiring policies")
    parser.add_argument("--company", type=str, help="Override company name for the policy")
    parser.add_argument("--gemini", action="store_true", help="Use Gemini CLI instead of OpenRouter")
    parser.add_argument("--governance", action="store_true", help="Generate only the 9 governance docs (CC1.2/1.3/1.5/2.3/3.1/3.2/3.3/4.1/5.1)")

    args = parser.parse_args()

    if args.list:
        print("Controls requiring policies:")
        for code, info in POLICY_CONTROLS.items():
            print(f"- {code}: {info['title']}")
        return

    use_gemini = args.gemini
    if not use_gemini and not OPENROUTER_API_KEY:
        logger.error("OPENROUTER_API_KEY not found. Use --gemini flag to use Gemini CLI instead.")
        return

    agent = PolicyAgent(
        api_key=OPENROUTER_API_KEY if not use_gemini else None,
        model=OPENROUTER_MODEL if not use_gemini else None,
        use_gemini_cli=use_gemini
    )
    evidence_client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="policy_agent")
    notifier = SlackNotifier(SLACK_WEBHOOK_URL) if SLACK_WEBHOOK_URL else None

    if controls_map is None:
        if not os.path.exists(CONTROLS_MAP_FILE):
            logger.error(f"{CONTROLS_MAP_FILE} not found. Run controls_seed.py first.")
            return
        with open(CONTROLS_MAP_FILE, "r") as f:
            controls_map = json.load(f)

    print("[AI] Collecting environment context...")
    env_context = agent.collect_environment_context()
    if args.company:
        env_context["company_name"] = args.company

    print(f"[AI] Context: company={env_context['company_name']}, "
          f"github={env_context['github_repo']}, "
          f"failed_controls={env_context['failed_controls']}")

    controls_to_process = POLICY_CONTROLS
    if args.governance:
        controls_to_process = {k: v for k, v in POLICY_CONTROLS.items() if k in GOVERNANCE_CONTROLS}
    elif args.control:
        if args.control in POLICY_CONTROLS:
            controls_to_process = {args.control: POLICY_CONTROLS[args.control]}
        else:
            logger.error(f"Control {args.control} is not in the policy controls list.")
            return

    for code, info in controls_to_process.items():
        if code not in controls_map:
            print(f"[SKIP] {code} not in controls_map.json")
            continue

        print(f"[AI] Generating policy for {code}: {info['title']}...")
        try:
            policy_text = agent.generate_policy(code, info, env_context)

            content = json.dumps({
                "policy_title": info["title"],
                "control": code,
                "generated_by": f"AI ({OPENROUTER_MODEL} via OpenRouter)",
                "environment": {
                    "github_repo": env_context["github_repo"],
                    "okta_domain": env_context["okta_domain"],
                    "company": env_context["company_name"]
                },
                "status": "DRAFT — requires human review and approval",
                "policy_text": policy_text
            })

            evidence_client.create_evidence(
                control_id=controls_map[code],
                title=f"[AI Draft] {info['title']}",
                content=content,
                source="AI_GENERATED"
            )
            evidence_client.update_control_status(controls_map[code], "PASS")
            print(f"[AI] Policy saved to Evidence Tracker: {code}")

            if notifier:
                notifier.send({
                    "text": (
                        f"📄 *Policy Draft Ready: {code}*\n"
                        f"*{info['title']}*\n"
                        f"_Generated for {env_context['company_name']} "
                        f"({env_context['github_repo']})_\n"
                        f"Review: `{EVIDENCE_TRACKER_URL}/docs`"
                    )
                })
                print(f"[SLACK] Notification sent for {code}")

        except Exception as e:
            logger.error(f"Failed to process {code}: {e}")
        finally:
            if not agent.use_gemini_cli:
                time.sleep(_INTER_REQUEST_DELAY)


if __name__ == "__main__":
    main()
