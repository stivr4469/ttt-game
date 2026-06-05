import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List

from log_config import get_logger
from evidence_client import EvidenceClient
from slack_notifier import SlackNotifier

log = get_logger(__name__)


# ── Async helper ──────────────────────────────────────────────────────────────

def _run_async(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result(timeout=30)
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

TRAINING_COURSES = {
    "aup": {
        "id": "aup",
        "title": "Acceptable Use Policy",
        "description": "Understanding proper use of company IT resources",
        "required": True,
        "passing_score": 80,
        "questions": [
            {"id": 1, "text": "Can you use company devices for personal social media?",
             "options": ["Yes, always", "No, never", "Only during breaks on personal accounts", "Yes, for work-related social media only"],
             "correct": 2},
            {"id": 2, "text": "What should you do if you find a USB drive in the parking lot?",
             "options": ["Plug it in to see what's on it", "Hand it to IT security without plugging in", "Take it home", "Throw it away"],
             "correct": 1},
            {"id": 3, "text": "Is it acceptable to share your work account credentials with a colleague?",
             "options": ["Yes, if they need temporary access", "Yes, if your manager approves", "No, never", "Only for emergency situations"],
             "correct": 2},
            {"id": 4, "text": "How long can you leave your workstation unlocked when away?",
             "options": ["As long as needed", "Up to 30 minutes", "Never — always lock when leaving", "Up to 5 minutes"],
             "correct": 2},
            {"id": 5, "text": "Which of the following is a safe practice when working remotely?",
             "options": ["Using public WiFi without VPN", "Connecting via company VPN", "Sharing your screen in a public place", "Saving data to personal cloud storage"],
             "correct": 1},
        ]
    },
    "password_policy": {
        "id": "password_policy",
        "title": "Password & MFA Requirements",
        "description": "Secure authentication practices and multi-factor authentication",
        "required": True,
        "passing_score": 80,
        "questions": [
            {"id": 1, "text": "What is the minimum password length required by company policy?",
             "options": ["6 characters", "8 characters", "12 characters", "16 characters"],
             "correct": 2},
            {"id": 2, "text": "How often should you change your password?",
             "options": ["Every week", "Every 90 days or when compromised", "Every year", "Never, if it's strong enough"],
             "correct": 1},
            {"id": 3, "text": "What is MFA (Multi-Factor Authentication)?",
             "options": ["Using multiple passwords", "Verifying identity with 2+ factors (password + phone/token)", "Logging in from multiple devices", "Having multiple user accounts"],
             "correct": 1},
            {"id": 4, "text": "You receive an MFA prompt you didn't initiate. What do you do?",
             "options": ["Approve it — probably a system glitch", "Deny it and report to IT security immediately", "Ignore it", "Approve it if it's during work hours"],
             "correct": 1},
            {"id": 5, "text": "Which password is strongest?",
             "options": ["Password123!", "p@ssw0rd", "MyDog2020", "xK#9mL$vQ2@nR7"],
             "correct": 3},
        ]
    },
    "phishing": {
        "id": "phishing",
        "title": "Phishing Awareness",
        "description": "Recognizing and responding to phishing and social engineering attacks",
        "required": True,
        "passing_score": 80,
        "questions": [
            {"id": 1, "text": "An email from 'CEO@c0mpany.com' asks you to wire $10,000 urgently. What do you do?",
             "options": ["Wire the money — CEO requests are urgent", "Call the CEO directly to verify", "Reply asking for more details", "Forward to accounting"],
             "correct": 1},
            {"id": 2, "text": "Which is a red flag in a phishing email?",
             "options": ["Professional company logo", "Urgent language + generic greeting like 'Dear User'", "Company email domain", "Unsubscribe link at bottom"],
             "correct": 1},
            {"id": 3, "text": "You receive a link to 'verify your account'. What do you check first?",
             "options": ["Click it — it looks official", "Hover over the link to see the real URL", "The email sender's name", "Whether you're busy"],
             "correct": 1},
            {"id": 4, "text": "What is spear phishing?",
             "options": ["A phishing attack targeting fish industry", "Targeted phishing using personal information about the victim", "Phishing via USB drives", "Phishing via phone calls"],
             "correct": 1},
            {"id": 5, "text": "You accidentally clicked a suspicious link. What do you do?",
             "options": ["Nothing — one click can't hurt", "Disconnect from network and report to IT security immediately", "Run a quick Google search about the site", "Change your password and don't tell anyone"],
             "correct": 1},
        ]
    },
    "gdpr_basics": {
        "id": "gdpr_basics",
        "title": "GDPR & Data Privacy",
        "description": "Understanding data protection regulations and handling personal data",
        "required": True,
        "passing_score": 75,
        "questions": [
            {"id": 1, "text": "What does GDPR stand for?",
             "options": ["General Data Protection Regulation", "Global Data Privacy Rules", "Government Data Processing Requirements", "General Digital Privacy Rights"],
             "correct": 0},
            {"id": 2, "text": "Which of the following is personal data under GDPR?",
             "options": ["Company revenue figures", "A person's email address", "Public stock prices", "Office building address"],
             "correct": 1},
            {"id": 3, "text": "How quickly must a data breach be reported to authorities?",
             "options": ["Within 24 hours", "Within 72 hours", "Within 1 week", "Within 1 month"],
             "correct": 1},
            {"id": 4, "text": "What is 'data minimization' in GDPR?",
             "options": ["Deleting all data regularly", "Collecting only data necessary for the specific purpose", "Encrypting all personal data", "Storing data in smaller files"],
             "correct": 1},
            {"id": 5, "text": "A customer asks you to delete all their personal data. What is this called?",
             "options": ["Data freeze", "Right to erasure (right to be forgotten)", "Data minimization", "Privacy by design"],
             "correct": 1},
        ]
    },
    "incident_response": {
        "id": "incident_response",
        "title": "Incident Response Procedures",
        "description": "What to do when a security incident occurs",
        "required": True,
        "passing_score": 80,
        "questions": [
            {"id": 1, "text": "What is the FIRST step when you discover a security incident?",
             "options": ["Try to fix it yourself", "Tell your colleagues", "Report it to IT security immediately", "Document everything first"],
             "correct": 2},
            {"id": 2, "text": "You find ransomware encrypting your files. What do you do?",
             "options": ["Pay the ransom", "Disconnect from network + call IT security immediately", "Reboot your computer", "Wait to see if it stops"],
             "correct": 1},
            {"id": 3, "text": "What is an 'incident' in cybersecurity?",
             "options": ["Any system slowdown", "An event that threatens security, availability, or data integrity", "A failed login attempt", "A software update"],
             "correct": 1},
            {"id": 4, "text": "After an incident is resolved, what should happen?",
             "options": ["Move on and forget about it", "Post-incident review to learn and prevent recurrence", "Blame the person who caused it", "Nothing — it's resolved"],
             "correct": 1},
            {"id": 5, "text": "What is the incident response hotline / contact? (For sandbox: who do you call?)",
             "options": ["Your direct manager only", "IT Security team via #security-incidents Slack channel", "The CEO directly", "External police"],
             "correct": 1},
        ]
    }
}

HR_ROSTER_FILE = Path(__file__).parent / "hr_roster.json"


async def _load_employees_from_db() -> list:
    """SELECT active employees из hr_employee таблицы."""
    from database import AsyncSessionLocal
    from models import HREmployee
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(HREmployee).where(HREmployee.status == "active")
        )
        rows = result.scalars().all()
        return [
            {
                "email": r.email,
                "name": r.name,
                "status": r.status,
            }
            for r in rows
        ]


def _load_employees() -> list:
    """Загружает активных сотрудников из DB. Fallback на hr_roster.json если таблица пуста."""
    try:
        employees = _run_async(_load_employees_from_db())
        if employees:
            return employees
        log.info("hr_employee table empty, falling back to hr_roster.json")
    except Exception as e:
        log.warning(f"DB _load_employees failed: {e}")

    # Fallback на JSON
    if not HR_ROSTER_FILE.exists():
        return []
    try:
        roster = json.loads(HR_ROSTER_FILE.read_text(encoding="utf-8"))
        return [e for e in roster.get("employees", []) if e.get("status") == "active"]
    except Exception as e:
        log.error(f"Failed to load hr_roster.json: {e}")
        return []


class TrainingAgent:

    def __init__(self):
        self._evidence_client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="training_agent")
        self._notifier = SlackNotifier(SLACK_WEBHOOK_URL) if SLACK_WEBHOOK_URL else None

    # ── DB helpers ────────────────────────────────────────────────────────────

    async def _load_db(self, user_email: str) -> dict:
        """SELECT TrainingCompletionDetail WHERE employee_email = user_email → dict {course_id: {...}}."""
        from database import AsyncSessionLocal
        from models import TrainingCompletionDetail
        from sqlalchemy import select

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(TrainingCompletionDetail).where(
                    TrainingCompletionDetail.employee_email == user_email
                )
            )
            rows = result.scalars().all()

        user_data: dict = {}
        for row in rows:
            user_data[row.course_id] = {
                "course_id": row.course_id,
                "course_title": row.course_title,
                "status": row.status,
                "score": row.score or 0,
                "certificate_id": row.certificate_id,
                "completed_at": row.completed_at.isoformat() if row.completed_at else None,
                "attempts": row.attempts,
            }
        return user_data

    async def _save_db(self, user_email: str, course_id: str, completion_data: dict) -> None:
        """Upsert TrainingCompletionDetail (unique: employee_email + course_id)."""
        from database import AsyncSessionLocal
        from models import TrainingCompletionDetail
        from sqlalchemy import select

        completed_at = None
        if completion_data.get("completed_at"):
            try:
                completed_at = datetime.fromisoformat(completion_data["completed_at"])
            except (ValueError, TypeError):
                completed_at = None

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(TrainingCompletionDetail).where(
                    TrainingCompletionDetail.employee_email == user_email,
                    TrainingCompletionDetail.course_id == course_id,
                )
            )
            existing = result.scalars().first()
            if existing:
                existing.course_title = completion_data.get("course_title", existing.course_title)
                existing.status = completion_data.get("status", existing.status)
                existing.score = completion_data.get("score")
                existing.certificate_id = completion_data.get("certificate_id")
                existing.attempts = completion_data.get("attempts", existing.attempts)
                existing.completed_at = completed_at
            else:
                session.add(TrainingCompletionDetail(
                    id=str(uuid.uuid4()),
                    employee_email=user_email,
                    course_id=course_id,
                    course_title=completion_data.get("course_title", ""),
                    status=completion_data.get("status", "not_started"),
                    score=completion_data.get("score"),
                    certificate_id=completion_data.get("certificate_id"),
                    attempts=completion_data.get("attempts", 1),
                    completed_at=completed_at,
                ))
            await session.commit()

    async def _load_all_db(self) -> dict:
        """SELECT all TrainingCompletionDetail rows → dict {email: {course_id: {...}}}."""
        from database import AsyncSessionLocal
        from models import TrainingCompletionDetail
        from sqlalchemy import select

        async with AsyncSessionLocal() as session:
            result = await session.execute(select(TrainingCompletionDetail))
            rows = result.scalars().all()

        all_data: dict = {}
        for row in rows:
            if row.employee_email not in all_data:
                all_data[row.employee_email] = {}
            all_data[row.employee_email][row.course_id] = {
                "course_id": row.course_id,
                "course_title": row.course_title,
                "status": row.status,
                "score": row.score or 0,
                "certificate_id": row.certificate_id,
                "completed_at": row.completed_at.isoformat() if row.completed_at else None,
                "attempts": row.attempts,
            }
        return all_data

    def get_all_courses(self) -> list:
        """Список курсов без вопросов (только метаданные)."""
        courses = []
        for cid, c in TRAINING_COURSES.items():
            courses.append({
                "id": c["id"],
                "title": c["title"],
                "description": c["description"],
                "required": c["required"],
                "passing_score": c["passing_score"],
                "question_count": len(c["questions"])
            })
        return courses

    def get_course_with_questions(self, course_id: str) -> dict:
        """Курс с вопросами (без правильных ответов!)."""
        course = TRAINING_COURSES.get(course_id)
        if not course:
            return None

        # Clone to avoid modifying the original
        c = dict(course)
        c["questions"] = []
        for q in course["questions"]:
            q_copy = dict(q)
            q_copy.pop("correct", None)
            c["questions"].append(q_copy)

        return c

    def get_user_completions(self, user_email: str) -> list:
        """Прогресс конкретного пользователя по всем курсам."""
        user_data = _run_async(self._load_db(user_email))

        completions = []
        for cid, c in TRAINING_COURSES.items():
            comp = user_data.get(cid, {
                "course_id": cid,
                "course_title": c["title"],
                "status": "not_started",
                "score": 0,
                "certificate_id": None,
                "completed_at": None
            })
            completions.append(comp)
        return completions

    def submit_quiz(self, user_email: str, course_id: str, answers: dict) -> dict:
        """
        answers = {"1": 2, "2": 1, ...}  — вопрос_id → индекс ответа
        """
        course = TRAINING_COURSES.get(course_id)
        if not course:
            return {"error": "Course not found"}

        correct_count = 0
        total_questions = len(course["questions"])

        for q in course["questions"]:
            q_id = str(q["id"])
            if q_id in answers and int(answers[q_id]) == q["correct"]:
                correct_count += 1

        score = int((correct_count / total_questions) * 100)
        passed = score >= course["passing_score"]
        certificate_id = f"CERT-{str(uuid.uuid4())[:8].upper()}" if passed else None

        # Load current user data from DB to get attempt count
        user_data = _run_async(self._load_db(user_email))
        prev = user_data.get(course_id, {})

        completion_data = {
            "course_id": course_id,
            "course_title": course["title"],
            "status": "passed" if passed else "failed",
            "score": score,
            "certificate_id": certificate_id,
            "completed_at": datetime.now(timezone.utc).isoformat() if passed else None,
            "attempts": prev.get("attempts", 0) + 1
        }

        # Only overwrite if previously not passed or if score is higher
        if prev.get("status") != "passed" or passed:
            _run_async(self._save_db(user_email, course_id, completion_data))

        return {
            "passed": passed,
            "score": score,
            "certificate_id": certificate_id,
            "correct_count": correct_count,
            "total": total_questions
        }

    def get_compliance_report(self) -> dict:
        """Читает список сотрудников из DB (fallback: hr_roster.json)."""
        employees = _load_employees()
        if not employees:
            return {"error": "HR roster not found"}

        completions = _run_async(self._load_all_db())

        report_employees = []
        fully_compliant_count = 0

        required_courses = [cid for cid, c in TRAINING_COURSES.items() if c["required"]]

        for emp in employees:
            email = emp["email"]
            user_comp = completions.get(email, {})

            emp_report = {
                "email": email,
                "name": emp["name"],
                "courses": {},
                "all_required_done": True
            }

            for cid in required_courses:
                status = user_comp.get(cid, {}).get("status", "not_started")
                emp_report["courses"][cid] = status
                if status != "passed":
                    emp_report["all_required_done"] = False

            if emp_report["all_required_done"]:
                fully_compliant_count += 1

            report_employees.append(emp_report)

        total_active = len(report_employees)
        compliance_pct = (fully_compliant_count / total_active * 100) if total_active > 0 else 0

        return {
            "report_date": datetime.now(timezone.utc).isoformat(),
            "total_employees": total_active,
            "fully_compliant": fully_compliant_count,
            "compliance_pct": round(compliance_pct, 1),
            "employees": report_employees
        }

    def send_reminders(self) -> int:
        """Найти сотрудников с незавершёнными обязательными курсами."""
        report = self.get_compliance_report()
        if "error" in report:
            return 0

        reminder_count = 0
        for emp in report["employees"]:
            if not emp["all_required_done"]:
                missing = [TRAINING_COURSES[cid]["title"] for cid, status in emp["courses"].items() if status != "passed"]

                if self._notifier:
                    msg = {
                        "text": f"🔔 *Security Training Reminder*\n"
                                f"Hi {emp['name']}, you have incomplete security training courses:\n"
                                f"• " + "\n• ".join(missing) + "\n"
                                f"Please complete them at: {EVIDENCE_TRACKER_URL.replace(':8000', ':8080')}/training"
                    }
                    self._notifier.send(msg)
                    reminder_count += 1

        return reminder_count

    def collect_evidence(self, controls_map: dict = None) -> dict:
        """Evidence для CC1.4."""
        report = self.get_compliance_report()
        if "error" in report:
            return {}

        evidence_data = {
            "control_code": "CC1.4",
            "pct_trained": report["compliance_pct"],
            "total": report["total_employees"],
            "compliant": report["fully_compliant"],
            "timestamp": report["report_date"]
        }

        if controls_map and "CC1.4" in controls_map:
            control_id = controls_map["CC1.4"]
            self._evidence_client.create_evidence(
                control_id=control_id,
                title="Employee Security Awareness Training Report",
                content=json.dumps(report, indent=2),
                source="HR_AUDIT"
            )

            status = "PASS" if report["compliance_pct"] >= 80 else "FAIL"
            self._evidence_client.submit_test_result(control_id, status, test_key="hr.user.training_completed", producer="training")

        return evidence_data
