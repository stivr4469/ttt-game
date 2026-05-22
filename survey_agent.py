#!/usr/bin/env python3
"""
survey_agent.py — SOC 2 Personnel Awareness Survey
Проводит опрос сотрудников по ключевым контролям, оценивает ответы через AI,
сохраняет результаты в Evidence Tracker как source=SURVEY.
"""

import os
import json
import logging
import argparse
from datetime import datetime
from openai import OpenAI
from dotenv import load_dotenv
from evidence_client import EvidenceClient
from slack_notifier import SlackNotifier
from constants import CONTROLS_MAP_FILE

load_dotenv()

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku")
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
COMPANY_NAME = os.getenv("COMPANY_NAME", "Marineso")

# Вопросы опроса, привязанные к CC-контролям
SURVEY_QUESTIONS = {
    "CC1.1": {
        "title": "Information Security & Ethics Policy",
        "question": (
            "Опишите кодекс этики и политику информационной безопасности компании. "
            "Что происходит при нарушении?"
        ),
    },
    "CC1.4": {
        "title": "Security Awareness Training",
        "question": (
            "Когда вы последний раз проходили обучение по информационной безопасности? "
            "Назовите минимум 2 темы, которые изучали."
        ),
    },
    "CC2.2": {
        "title": "Internal Communication Policy",
        "question": (
            "Куда вы сообщаете об инцидентах безопасности? "
            "Назовите конкретный канал в Slack и ответственного сотрудника."
        ),
    },
    "CC7.4": {
        "title": "Incident Response",
        "question": (
            "Что вы делаете при обнаружении подозрительной активности или утечки данных? "
            "Опишите конкретные шаги."
        ),
    },
    "CC9.1": {
        "title": "Business Continuity",
        "question": (
            "Что такое BCP (Business Continuity Plan)? "
            "Знаете ли вы действия при длительном сбое производственных систем?"
        ),
    },
}

# Демо-сотрудники: реалистичный микс хороших и плохих ответов
DEMO_RESPONDENTS = [
    {
        "email": "alex.dev@marineso.com",
        "name": "Alex Developer",
        "role": "Engineering Lead",
        "answers": {
            "CC1.1": (
                "Кодекс этики — документ о честном поведении, защите данных клиентов "
                "и конфиденциальности. При нарушении — дисциплинарные меры вплоть до увольнения."
            ),
            "CC1.4": (
                "Проходил обучение 3 месяца назад. Темы: защита от фишинга, "
                "правила работы с паролями и MFA, безопасная работа с данными."
            ),
            "CC2.2": (
                "Инциденты сообщаю в Slack канал #compliance-alerts "
                "и дублирую письмом security-team@marineso.com."
            ),
            "CC7.4": (
                "При подозрительной активности: немедленно сообщаю в #compliance-alerts, "
                "не трогаю заражённую систему, документирую что видел, жду инструкций."
            ),
            "CC9.1": (
                "BCP — план непрерывности бизнеса на случай сбоев. "
                "Знаю что есть резервные копии данных и план восстановления систем."
            ),
        },
    },
    {
        "email": "maria.hr@marineso.com",
        "name": "Maria HR",
        "role": "HR Manager",
        "answers": {
            "CC1.1": "Есть политика безопасности, но подробностей не помню.",
            "CC1.4": "Проходила обучение, но давно. Точно не помню темы.",
            "CC2.2": "Наверное нужно написать руководителю?",
            "CC7.4": "Сказала бы своему руководителю.",
            "CC9.1": "Не знаю что такое BCP.",
        },
    },
    {
        "email": "ivan.devops@marineso.com",
        "name": "Ivan DevOps",
        "role": "DevOps Engineer",
        "answers": {
            "CC1.1": (
                "Кодекс этики описывает правила защиты данных клиентов, "
                "конфиденциальность информации, запрет на личное использование ресурсов компании. "
                "Нарушение — выговор или увольнение по статье."
            ),
            "CC1.4": (
                "Последнее обучение — месяц назад. "
                "Темы: фишинг, управление доступом, работа с секретами в CI/CD, инциденты безопасности."
            ),
            "CC2.2": (
                "Инциденты — сразу в #compliance-alerts в Slack. "
                "Также через Evidence Tracker. Есть дежурный security-инженер."
            ),
            "CC7.4": (
                "1. Изолировать систему от сети. "
                "2. Сообщить в #compliance-alerts. "
                "3. Не удалять логи. "
                "4. Задокументировать инцидент. "
                "5. Ждать инструкций от security team."
            ),
            "CC9.1": (
                "BCP — план непрерывности бизнеса. "
                "При сбое: переключаемся на резервные системы AWS в другом регионе, "
                "восстанавливаем из backup S3, уведомляем команду через Slack."
            ),
        },
    },
]


class SurveyAgent:
    def __init__(self):
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=OPENROUTER_API_KEY,
            default_headers={
                "HTTP-Referer": "compliance-sandbox",
                "X-Title": "Compliance Sandbox Auditor",
            },
        )
        self.evidence_client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="survey_agent")
        self.notifier = SlackNotifier(SLACK_WEBHOOK_URL) if SLACK_WEBHOOK_URL else None

    def score_response(self, control_code: str, question: str, answer: str, respondent: dict) -> dict:
        """Оценивает ответ сотрудника через AI. Возвращает verdict и reasoning."""
        prompt = f"""You are a SOC 2 compliance auditor evaluating an employee's awareness of security policies.

Company: {COMPANY_NAME}
Control: {control_code} — {SURVEY_QUESTIONS[control_code]['title']}
Employee: {respondent['name']} ({respondent['role']})

Question asked:
{question}

Employee's answer:
{answer}

Evaluate whether this answer demonstrates ADEQUATE knowledge for SOC 2 compliance.
A PASS requires the employee to show basic understanding of the relevant policy/procedure.
A FAIL means the employee lacks knowledge that creates compliance risk.

Respond with JSON only:
{{
  "verdict": "PASS" or "FAIL",
  "score": 1-5,
  "gaps": ["list of specific knowledge gaps if any"],
  "reasoning": "one sentence explanation"
}}"""

        try:
            response = self.client.chat.completions.create(
                model=OPENROUTER_MODEL,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.choices[0].message.content.strip()
            # Вырезать JSON из ответа если обёрнут в ```
            if "```" in raw:
                raw = raw.split("```")[1].replace("json", "").strip()
            return json.loads(raw)
        except Exception as e:
            logger.error(f"AI scoring failed for {control_code}: {e}")
            return {
                "verdict": "PENDING",
                "score": 0,
                "gaps": ["AI scoring unavailable"],
                "reasoning": str(e),
            }

    def run(self, respondents: list, controls_map: dict) -> dict:
        """Проводит полный опрос и сохраняет evidence."""
        survey_date = datetime.now().strftime("%Y-%m-%d %H:%M")
        overall = {"pass": 0, "fail": 0, "pending": 0, "respondents": len(respondents)}
        per_control = {code: {"pass": 0, "fail": 0} for code in SURVEY_QUESTIONS}

        print(f"\n{'='*60}")
        print(f" SOC 2 PERSONNEL AWARENESS SURVEY — {COMPANY_NAME}")
        print(f" {survey_date} | {len(respondents)} respondents | {len(SURVEY_QUESTIONS)} controls")
        print(f"{'='*60}\n")

        for respondent in respondents:
            name = respondent["name"]
            role = respondent["role"]
            email = respondent["email"]
            print(f"── {name} ({role}) ──")

            for control_code, q_info in SURVEY_QUESTIONS.items():
                control_id = controls_map.get(control_code)
                if not control_id:
                    print(f"  [SKIP] {control_code} не найден в controls_map.json")
                    continue

                question = q_info["question"]
                answer = respondent["answers"].get(control_code, "")

                # Оценить через AI
                scoring = self.score_response(control_code, question, answer, respondent)
                verdict = scoring.get("verdict", "PENDING")
                score = scoring.get("score", 0)
                reasoning = scoring.get("reasoning", "")
                gaps = scoring.get("gaps", [])

                # Счётчики
                if verdict == "PASS":
                    overall["pass"] += 1
                    per_control[control_code]["pass"] += 1
                elif verdict == "FAIL":
                    overall["fail"] += 1
                    per_control[control_code]["fail"] += 1
                else:
                    overall["pending"] += 1

                icon = "✅" if verdict == "PASS" else ("❌" if verdict == "FAIL" else "⏳")
                print(f"  {icon} {control_code}: {verdict} (score={score}/5) — {reasoning}")
                if gaps and verdict == "FAIL":
                    print(f"     Пробелы: {', '.join(gaps)}")

                # Сохранить в Evidence Tracker
                content = json.dumps({
                    "survey_date": survey_date,
                    "respondent": {
                        "email": email,
                        "name": name,
                        "role": role,
                    },
                    "control": control_code,
                    "question": question,
                    "answer": answer,
                    "ai_verdict": verdict,
                    "ai_score": score,
                    "ai_reasoning": reasoning,
                    "knowledge_gaps": gaps,
                    "source": "SURVEY",
                })

                self.evidence_client.create_evidence(
                    control_id=control_id,
                    title=f"[Survey] {control_code} — {name}: {verdict}",
                    content=content,
                    source="SURVEY",
                )

                # Обновить статус контроля при первом FAIL
                if verdict == "FAIL":
                    self.evidence_client.update_control_status(control_id, "FAIL")

            print()

        return {"overall": overall, "per_control": per_control}

    def notify_slack(self, summary: dict):
        if not self.notifier:
            return
        overall = summary["overall"]
        total = overall["pass"] + overall["fail"] + overall["pending"]
        fail_pct = round(overall["fail"] / total * 100) if total else 0

        fail_controls = [
            code for code, s in summary["per_control"].items() if s["fail"] > 0
        ]

        text = (
            f"📋 *SOC 2 Personnel Awareness Survey Complete*\n"
            f"*{COMPANY_NAME}* | {overall['respondents']} respondents\n"
            f"✅ PASS: {overall['pass']} | ❌ FAIL: {overall['fail']} ({fail_pct}%)\n"
        )
        if fail_controls:
            text += f"⚠️ Controls with gaps: {', '.join(fail_controls)}\n"
        text += f"Evidence saved to: `{EVIDENCE_TRACKER_URL}/docs`"

        self.notifier.send({"text": text})


def main(controls_map: dict | None = None):
    parser = argparse.ArgumentParser(description="SOC 2 Personnel Awareness Survey Agent")
    parser.add_argument("--demo", action="store_true", default=True,
                        help="Использовать демо-данные (по умолчанию)")
    parser.add_argument("--list", action="store_true",
                        help="Показать список вопросов")
    args = parser.parse_args()

    if args.list:
        print("SOC 2 Survey Questions:")
        for code, info in SURVEY_QUESTIONS.items():
            print(f"\n{code} — {info['title']}")
            print(f"  Q: {info['question']}")
        return

    if not OPENROUTER_API_KEY:
        print("[ERROR] OPENROUTER_API_KEY не задан в .env")
        return

    # Load controls_map.json if not provided
    if controls_map is None:
        if not os.path.exists(CONTROLS_MAP_FILE):
            print(f"Error: {CONTROLS_MAP_FILE} not found. Run controls_seed.py first.")
            return
        with open(CONTROLS_MAP_FILE) as f:
            controls_map = json.load(f)

    agent = SurveyAgent()
    summary = agent.run(DEMO_RESPONDENTS, controls_map)

    # Итоговый отчёт
    overall = summary["overall"]
    print(f"{'='*60}")
    print(f" ИТОГ ОПРОСА")
    print(f"{'='*60}")
    total_answers = overall["pass"] + overall["fail"] + overall["pending"]
    print(f" Сотрудников опрошено: {overall['respondents']}")
    print(f" Всего ответов:        {total_answers}")
    print(f" PASS:                 {overall['pass']}")
    print(f" FAIL:                 {overall['fail']}")
    print(f"\n Результаты по контролям:")
    for code, s in summary["per_control"].items():
        total = s["pass"] + s["fail"]
        status = "✅ OK" if s["fail"] == 0 else f"❌ {s['fail']}/{total} не знают"
        print(f"   {code}: {status}")
    print(f"\n Evidence → {EVIDENCE_TRACKER_URL}/docs (source=SURVEY)")
    print(f"{'='*60}")

    agent.notify_slack(summary)


if __name__ == "__main__":
    main()
