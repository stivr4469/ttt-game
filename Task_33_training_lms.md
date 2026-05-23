# Task 33 — Employee Security Training LMS

## Цель
Реализовать полноценный LMS (Learning Management System) для security awareness training сотрудников. Закрыть контроль CC1.4 (Training) — сейчас FAIL.

---

## Контекст кодовой базы

- `hr_agent.py` — читает `hr_roster.json` (список сотрудников Okta), посмотреть структуру
- `survey_agent.py` — пример агента с опросом, посмотреть паттерн
- `slack_notifier.py` — отправка в Slack, посмотреть функцию send
- `evidence_client.py` — `EvidenceClient.submit_evidence(control_code, description, evidence_data)`
- `auditor_routes.py` — паттерн роутера
- `ui/index.html` — стиль фронтенда (dark theme, `#0f1117` фон, `#00d4aa` акцент)
- `ui_server.py` строки 100-103 — паттерн подключения роутеров

---

## Файлы для создания

### 1. `training_agent.py`

**Константа `TRAINING_COURSES`** (встроить в код):

```python
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
             "correct": 2},  # индекс правильного ответа (0-based)
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
```

**Класс `TrainingAgent`:**

```python
class TrainingAgent:
    COMPLETIONS_FILE = Path(__file__).parent / "training_completions.json"
    
    def _load(self) -> dict:
        """Читать training_completions.json."""
    
    def _save(self, data: dict):
        """Записать training_completions.json."""
    
    def get_all_courses(self) -> list:
        """Список курсов без вопросов (только метаданные)."""
    
    def get_course_with_questions(self, course_id: str) -> dict:
        """Курс с вопросами (без правильных ответов!)."""
        # ВАЖНО: не отдавать поле "correct" клиенту
    
    def get_user_completions(self, user_email: str) -> list:
        """Прогресс конкретного пользователя по всем курсам."""
    
    def submit_quiz(self, user_email: str, course_id: str, answers: dict) -> dict:
        """
        answers = {"1": 2, "2": 1, ...}  — вопрос_id → индекс ответа
        Подсчитать score, проверить passing_score.
        Если passed: сгенерировать certificate_id = "CERT-<uuid8>"
        Сохранить в completions.
        Вернуть: {"passed": bool, "score": int, "certificate_id": str|None, "passed_count": int, "total": int}
        """
    
    def get_compliance_report(self) -> dict:
        """
        Читать hr_roster.json для списка сотрудников.
        Для каждого: статус по каждому обязательному курсу.
        Вернуть: {
          "report_date": "...",
          "total_employees": N,
          "fully_compliant": N,
          "compliance_pct": float,
          "employees": [{"email": ..., "name": ..., "courses": {...}, "all_required_done": bool}]
        }
        """
    
    def send_reminders(self) -> int:
        """
        Найти сотрудников с незавершёнными обязательными курсами.
        Отправить напоминание через slack_notifier (если доступен).
        Вернуть количество отправленных напоминаний.
        """
    
    def collect_evidence(self, controls_map: dict = None) -> dict:
        """
        Evidence для CC1.4.
        Вернуть: {"control_code": "CC1.4", "pct_trained": float, "total": N, "compliant": N}
        Отправить через EvidenceClient если controls_map предоставлен.
        """
```

**`hr_roster.json` структура** (посмотри реальный файл, но ожидаемая схема):
```json
[{"email": "...", "name": "...", "department": "...", "status": "active"}]
```

---

### 2. `training_routes.py`

```python
router = APIRouter(prefix="/api/training", tags=["training"])
_agent = TrainingAgent()
```

**Эндпоинты:**

`GET /api/training/courses` — список всех курсов (без вопросов). Requires: любой auth.

`GET /api/training/course/{course_id}` — курс с вопросами (БЕЗ правильных ответов). Requires: любой auth.

`GET /api/training/my-progress` — прогресс текущего пользователя (email из JWT token). Requires: любой auth.

`POST /api/training/course/{course_id}/submit` — сдать тест.
Body: `{"answers": {"1": 2, "2": 1, ...}}`
Requires: любой auth.
Email берётся из JWT.

`GET /api/training/compliance-report` — полный отчёт по всем сотрудникам. Requires: Admin или Auditor.

`POST /api/training/send-reminders` — отправить Slack напоминания. Requires: Admin.

---

### 3. `ui/training.html`

Dark theme (как `ui/index.html`). Структура:

```
[Шапка] 🎓 Security Awareness Training
         "Stay secure, stay compliant"

[Мой прогресс — 5 карточек курсов]
 ┌──────────────────────────────────┐
 │ ✅ Acceptable Use Policy         │
 │ Score: 90% | Certified           │
 │ [Certificate: CERT-abc12345]     │
 └──────────────────────────────────┘
 ┌──────────────────────────────────┐
 │ 🔄 Phishing Awareness            │
 │ Not started                      │
 │ [Start Course] кнопка           │
 └──────────────────────────────────┘

[Форма курса — показывается когда нажата Start Course]
 Заголовок курса
 Прогресс: "Question 3 of 5"
 Текст вопроса
 [○ Вариант А]
 [○ Вариант Б] (radio buttons)
 [Next] / [Submit]
 
[Результат]
 "Congratulations! You passed with 80%"
 "Certificate ID: CERT-abc12345"  (если passed)
 "Score: 60%. Required: 80%. Please retry."  (если failed)

[Admin: Compliance Report — только для Admin/Auditor]
 Таблица: Сотрудник | AUP | Phishing | Password | GDPR | IR | Статус
 Итого: "X/N employees fully compliant (Y%)"
 [Send Reminders] кнопка
```

JavaScript:
- При загрузке: `fetch('/api/training/my-progress')` → отрендерить карточки
- При нажатии Start Course: `fetch('/api/training/course/{id}')` → показать форму с вопросами
- Submit: `fetch('/api/training/course/{id}/submit', {method:'POST', body: answers})` → показать результат
- Если роль Admin/Auditor: дополнительно `fetch('/api/training/compliance-report')` → таблица

Токен авторизации — взять из localStorage/cookie (посмотреть как это сделано в `ui/index.html`).

---

### 4. Добавить в `audit_runner.py`

Найти в `audit_runner.py` список фаз и добавить сбор evidence от TrainingAgent в фазу EVIDENCE COLLECTION:

```python
# Фаза training evidence
from training_agent import TrainingAgent
training_agent = TrainingAgent()
training_result = training_agent.collect_evidence(controls_map)
# Записать в лог аналогично другим агентам
```

---

### 5. Изменения в `ui_server.py`

После строки `from auditor_routes import router as auditor_router` добавить:
```python
from training_routes import router as training_router
app.include_router(training_router)
```

И добавить роут для HTML:
```python
@app.get("/training", response_class=HTMLResponse)
async def training_page():
    return FileResponse(ROOT / "ui" / "training.html")
```

---

## Как проверить

```bash
# Список курсов
curl http://localhost:8001/api/training/courses \
  -H "Authorization: Bearer <token>"

# Сдать тест (пример)
curl -X POST http://localhost:8001/api/training/course/aup/submit \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"answers": {"1": 2, "2": 1, "3": 2, "4": 2, "5": 1}}'

# Compliance report (Admin)
curl http://localhost:8001/api/training/compliance-report \
  -H "Authorization: Bearer <admin_token>"

# Открыть страницу
http://localhost:8001/training
```

---

## Ожидаемый эффект на SOC2

После реализации: CC1.4 (Training) должен перейти из FAIL в PASS при следующем запуске `audit_runner.py`, если ≥ 80% сотрудников завершили обязательные курсы.

---

## Статус после выполнения

Обновить `Task_status.md` с результатами.
