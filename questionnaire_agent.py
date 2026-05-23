import os
import json
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku")

SIG_LITE = [
    {"id": "A.1",  "category": "Risk Management",    "question": "Does your organization have a formal risk management program?"},
    {"id": "A.2",  "category": "Risk Management",    "question": "How frequently is your risk assessment performed?"},
    {"id": "B.1",  "category": "Security Policy",    "question": "Do you have a written information security policy?"},
    {"id": "B.2",  "category": "Security Policy",    "question": "When was your security policy last reviewed and updated?"},
    {"id": "C.1",  "category": "Access Control",     "question": "Do you enforce multi-factor authentication (MFA) for all users?"},
    {"id": "C.2",  "category": "Access Control",     "question": "How do you manage privileged access and admin accounts?"},
    {"id": "C.3",  "category": "Access Control",     "question": "Do you perform periodic access reviews?"},
    {"id": "D.1",  "category": "Data Protection",    "question": "Is data encrypted at rest and in transit?"},
    {"id": "D.2",  "category": "Data Protection",    "question": "What data classification policy do you follow?"},
    {"id": "D.3",  "category": "Data Protection",    "question": "How do you handle customer data deletion requests?"},
    {"id": "E.1",  "category": "Incident Response",  "question": "Do you have a documented incident response plan?"},
    {"id": "E.2",  "category": "Incident Response",  "question": "What is your SLA for notifying customers of a data breach?"},
    {"id": "F.1",  "category": "Vulnerability Mgmt", "question": "Do you perform regular vulnerability assessments or penetration tests?"},
    {"id": "F.2",  "category": "Vulnerability Mgmt", "question": "What is your patch management process for critical vulnerabilities?"},
    {"id": "G.1",  "category": "Business Continuity","question": "Do you have a Business Continuity Plan (BCP)?"},
    {"id": "G.2",  "category": "Business Continuity","question": "What is your Recovery Time Objective (RTO)?"},
    {"id": "H.1",  "category": "Vendor Management",  "question": "Do you perform security assessments of third-party vendors?"},
    {"id": "H.2",  "category": "Vendor Management",  "question": "Do your vendors sign Data Processing Agreements (DPA)?"},
    {"id": "I.1",  "category": "Compliance",         "question": "What compliance certifications does your organization hold?"},
    {"id": "I.2",  "category": "Compliance",         "question": "Are you SOC 2 Type II certified? Can you share the report?"},
]

CAIQ_LITE = [
    {"id": "AIS-01", "category": "Application Security",  "question": "Do you use application security testing (SAST/DAST) in your CI/CD pipeline?"},
    {"id": "BCR-01", "category": "Business Continuity",   "question": "Is your business continuity plan tested at least annually?"},
    {"id": "CCC-01", "category": "Change Control",        "question": "Do all changes go through a formal change management process?"},
    {"id": "DSP-01", "category": "Data Security",         "question": "Is all data classified according to a formal data classification policy?"},
    {"id": "GRC-01", "category": "Governance",            "question": "Does your organization have an information security committee or CISO?"},
    {"id": "HRS-01", "category": "HR Security",           "question": "Are background checks performed for employees with access to sensitive data?"},
    {"id": "IAM-01", "category": "Identity",              "question": "Do you use a centralized identity provider (IdP) such as Okta or Azure AD?"},
    {"id": "IAM-02", "category": "Identity",              "question": "Is role-based access control (RBAC) implemented?"},
    {"id": "IVS-01", "category": "Infrastructure",        "question": "Is your infrastructure hosted in a SOC 2 certified data center?"},
    {"id": "LOG-01", "category": "Logging",               "question": "Are all security events logged and retained for at least 12 months?"},
    {"id": "SEF-01", "category": "Security Incident",     "question": "Do you have a documented Security Event Management process?"},
    {"id": "TVM-01", "category": "Threat & Vulnerability","question": "Do you use automated vulnerability scanning tools?"},
    {"id": "TVM-02", "category": "Threat & Vulnerability","question": "What is your process for tracking and remediating CVEs?"},
    {"id": "UEM-01", "category": "Endpoint",              "question": "Do you use MDM to manage and enforce endpoint security policies?"},
    {"id": "UEM-02", "category": "Endpoint",              "question": "Is full disk encryption enforced on all company devices?"},
]

class QuestionnaireAgent:
    QUESTIONNAIRES = {
        "sig_lite": {"name": "SIG Lite", "questions": SIG_LITE},
        "caiq_lite": {"name": "CAIQ Lite", "questions": CAIQ_LITE},
    }
    
    RESPONSES_FILE = Path(__file__).parent / "questionnaire_responses.json"
    
    def __init__(self):
        if OPENROUTER_API_KEY:
            self.client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=OPENROUTER_API_KEY,
                default_headers={
                    "HTTP-Referer": "compliance-sandbox",
                    "X-Title": "Compliance Sandbox Questionnaire Automation",
                }
            )
        else:
            self.client = None
            
        self.model = OPENROUTER_MODEL
        self.policies_text = self._load_policies()

    def _load_policies(self) -> str:
        policies_dir = Path(__file__).parent / "policies"
        if not policies_dir.exists():
            return "No policies available."
        texts = []
        for f in policies_dir.glob("*.md"):
            try:
                texts.append(f"=== {f.stem} ===\n" + f.read_text(encoding="utf-8"))
            except:
                pass
        return "\n\n".join(texts)

    def answer_question(self, question_data: dict, policies_text: str) -> dict:
        if not self.client:
            return {
                "question_id": question_data["id"],
                "question": question_data["question"],
                "category": question_data["category"],
                "answer": "Marineso has documented policies covering this requirement. Please contact compliance@marineso.com for detailed documentation.",
                "confidence": "low",
                "policy_references": [],
                "needs_review": True
            }

        prompt = f"""You are a compliance officer at Marineso Inc. Answer the following security questionnaire 
question based on our actual policies and controls.

POLICIES AND CONTROLS:
{policies_text}

SOC 2 STATUS: 33 controls assessed, 16 PASS, 17 FAIL (sandbox environment).
CERTIFICATIONS: SOC 2 Type II (in progress), ISO 27001 (in progress).

Question ({question_data['category']}): {question_data['question']}

Provide a professional, honest answer in 2-4 sentences. 
If we have a policy covering this — cite it.
If we don't fully meet this requirement — be transparent.
Respond ONLY with the answer text, no JSON."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3
            )
            answer = response.choices[0].message.content.strip()
            
            # Simple heuristic for confidence
            confidence = "high"
            needs_review = False
            
            # If answer is too short or doesn't mention policies when they are available
            if len(answer) < 50:
                confidence = "medium"
                needs_review = True
            
            return {
                "question_id": question_data["id"],
                "question": question_data["question"],
                "category": question_data["category"],
                "answer": answer,
                "confidence": confidence,
                "policy_references": [p for p in ["Corporate Governance", "Access Control", "Data Protection", "Incident Response"] if p.lower() in answer.lower()],
                "needs_review": needs_review
            }
        except Exception as e:
            logger.error(f"Error answering question {question_data['id']}: {e}")
            return {
                "question_id": question_data["id"],
                "question": question_data["question"],
                "category": question_data["category"],
                "answer": f"Error generating answer: {str(e)}",
                "confidence": "low",
                "policy_references": [],
                "needs_review": True
            }

    def generate_response(self, questionnaire_id: str, requester: dict = None) -> dict:
        q_template = self.QUESTIONNAIRES.get(questionnaire_id)
        if not q_template:
            return {"error": "Questionnaire template not found"}
            
        answers = []
        high_conf_count = 0
        needs_review_count = 0
        
        for q in q_template["questions"]:
            ans = self.answer_question(q, self.policies_text)
            answers.append(ans)
            if ans["confidence"] == "high": high_conf_count += 1
            if ans["needs_review"]: needs_review_count += 1
            
        response_id = str(uuid.uuid4())
        full_response = {
            "id": response_id,
            "questionnaire": questionnaire_id,
            "questionnaire_name": q_template["name"],
            "requester": requester or {"company": "Unknown", "email": "unknown@example.com"},
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_questions": len(q_template["questions"]),
            "high_confidence": high_conf_count,
            "needs_review_count": needs_review_count,
            "answers": answers
        }
        
        self._save_response(full_response)
        return full_response

    def _save_response(self, response: dict):
        responses = []
        if self.RESPONSES_FILE.exists():
            try:
                responses = json.loads(self.RESPONSES_FILE.read_text(encoding="utf-8"))
            except:
                pass
        responses.append(response)
        self.RESPONSES_FILE.write_text(json.dumps(responses, indent=2, ensure_ascii=False), encoding="utf-8")

    def get_all_responses(self) -> List[Dict]:
        if not self.RESPONSES_FILE.exists():
            return []
        try:
            responses = json.loads(self.RESPONSES_FILE.read_text(encoding="utf-8"))
            # Remove full answers for brief list
            summary_list = []
            for r in responses:
                r_copy = dict(r)
                r_copy.pop("answers", None)
                summary_list.append(r_copy)
            return summary_list
        except:
            return []

    def get_response_by_id(self, response_id: str) -> Optional[Dict]:
        if not self.RESPONSES_FILE.exists():
            return None
        try:
            responses = json.loads(self.RESPONSES_FILE.read_text(encoding="utf-8"))
            for r in responses:
                if r["id"] == response_id:
                    return r
            return None
        except:
            return None

    def export_to_text(self, response_id: str) -> str:
        resp = self.get_response_by_id(response_id)
        if not resp:
            return "Response not found"
            
        lines = [
            f"SECURITY QUESTIONNAIRE: {resp['questionnaire_name']}",
            f"COMPANY: Marineso Inc.",
            f"REQUESTER: {resp['requester']['company']} ({resp['requester']['email']})",
            f"GENERATED AT: {resp['generated_at']}",
            "=" * 60,
            ""
        ]
        
        for a in resp["answers"]:
            lines.append(f"[{a['question_id']}] {a['question']}")
            lines.append(f"Response: {a['answer']}")
            if a["policy_references"]:
                lines.append(f"References: {', '.join(a['policy_references'])}")
            lines.append("-" * 40)
            
        return "\n".join(lines)
