# Task 36 — Security Questionnaire Automation (SIG / CAIQ)

## Цель
Автоматически отвечать на security questionnaires от клиентов/партнёров используя уже существующие политики. Аналог Vanta Questionnaire Automation. Ключевая B2B-функция: партнёр присылает 200-вопросный SIG → система генерирует черновик ответов за секунды.

---

## Контекст кодовой базы

- `policy_agent.py` — LLM клиент (OpenRouter, посмотреть как вызывается `client.chat.completions.create`)
- `policies/` — директория с готовыми политиками в Markdown (источник ответов)
- `controls_map.json` — маппинг контролей на описания
- `evidence_client.py` — EvidenceClient
- `auditor_routes.py` — паттерн роутера
- `auth.py` — decode_token, ROLES
- `ui_server.py` строки 100-103 — паттерн подключения роутеров

---

## Встроенные вопросники (хардкодить в `questionnaire_agent.py`)

### SIG Lite (Standardized Information Gathering) — 20 вопросов:
```python
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
```

### CAIQ Lite (Cloud Security Alliance) — 15 вопросов:
```python
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
```

---

## Файлы для создания

### 1. `questionnaire_agent.py`

```python
class QuestionnaireAgent:
    
    QUESTIONNAIRES = {
        "sig_lite": {"name": "SIG Lite", "questions": SIG_LITE},
        "caiq_lite": {"name": "CAIQ Lite", "questions": CAIQ_LITE},
    }
    
    RESPONSES_FILE = Path(__file__).parent / "questionnaire_responses.json"
    
    def __init__(self):
        # LLM клиент — точно такой же как в policy_agent.py (OpenRouter)
        # Загрузить все политики из папки policies/ в память (self.policies_text)
    
    def _load_policies(self) -> str:
        """Читать все .md файлы из policies/, объединить в одну строку."""
        policies_dir = Path(__file__).parent / "policies"
        texts = []
        for f in policies_dir.glob("*.md"):
            texts.append(f"=== {f.stem} ===\n" + f.read_text())
        return "\n\n".join(texts)
    
    def answer_question(self, question: dict, policies_text: str) -> dict:
        """
        Один вопрос → LLM генерирует ответ используя политики как контекст.
        
        Промт:
        You are a compliance officer at Marineso Inc. Answer the following security questionnaire 
        question based on our actual policies and controls.
        
        POLICIES AND CONTROLS:
        {policies_text}
        
        SOC 2 STATUS: 33 controls assessed, 16 PASS, 17 FAIL (sandbox environment).
        CERTIFICATIONS: SOC 2 Type II (in progress), ISO 27001 (in progress).
        
        Question ({category}): {question}
        
        Provide a professional, honest answer in 2-4 sentences. 
        If we have a policy covering this — cite it.
        If we don't fully meet this requirement — be transparent.
        Respond ONLY with the answer text, no JSON.
        
        Возвращать:
        {
          "question_id": "A.1",
          "question": "...",
          "category": "...",
          "answer": "...",
          "confidence": "high|medium|low",
          "policy_references": ["policy_name_1", ...],
          "needs_review": bool  # True если ответ неуверенный
        }
        """
    
    def generate_response(self, questionnaire_id: str, requester: dict = None) -> dict:
        """
        Ответить на все вопросы анкеты.
        requester = {"company": "Acme", "email": "security@acme.com"}
        
        1. Загрузить политики (один раз)
        2. Для каждого вопроса вызвать answer_question()
        3. Сохранить результат в questionnaire_responses.json
        4. Вернуть полный response dict
        
        Если OPENROUTER_API_KEY не задан → mock ответы:
        answer = "Marineso has documented policies covering this requirement. 
                  Please contact compliance@marineso.com for detailed documentation."
        confidence = "low", needs_review = True
        
        Response dict:
        {
          "id": "<uuid>",
          "questionnaire": "sig_lite",
          "questionnaire_name": "SIG Lite",
          "requester": {"company": "...", "email": "..."},
          "generated_at": "...",
          "total_questions": N,
          "high_confidence": N,
          "needs_review_count": N,
          "answers": [...]
        }
        """
    
    def get_all_responses(self) -> list[dict]:
        """Все сохранённые ответы (метаданные без answers для быстрой загрузки)."""
    
    def get_response_by_id(self, response_id: str) -> dict | None:
        """Полный response с answers."""
    
    def export_to_text(self, response_id: str) -> str:
        """Экспорт ответов в читаемый текстовый формат для отправки партнёру."""
```

---

### 2. `questionnaire_routes.py`

```python
router = APIRouter(prefix="/api/questionnaires", tags=["questionnaires"])
_agent = QuestionnaireAgent()
```

**Эндпоинты:**

`GET /api/questionnaires/templates` — список доступных шаблонов вопросников. Публичный (без auth).
```json
[
  {"id": "sig_lite", "name": "SIG Lite", "questions_count": 20, "description": "..."},
  {"id": "caiq_lite", "name": "CAIQ Lite", "questions_count": 15, "description": "..."}
]
```

`GET /api/questionnaires/templates/{id}` — вопросы конкретного шаблона. Публичный.

`POST /api/questionnaires/generate` — сгенерировать ответы. Requires: Admin, Auditor.
Body: `{"questionnaire_id": "sig_lite", "requester": {"company": "Acme", "email": "..."}}`
Время выполнения: 1-3 мин (LLM вызовы на каждый вопрос).

`GET /api/questionnaires/responses` — список всех сгенерированных ответов. Requires: Admin, Auditor.

`GET /api/questionnaires/responses/{id}` — полный response. Requires: Admin, Auditor.

`GET /api/questionnaires/responses/{id}/export` — текстовый экспорт. Requires: Admin, Auditor.
Content-Type: text/plain, Content-Disposition: attachment.

---

### 3. `ui/questionnaires.html`

Dark theme. Структура:

```
[Шапка] 📋 Security Questionnaire Automation
         "Auto-generate responses for partner security reviews"

[Доступные шаблоны]
 ┌──────────────────────────────────┐  ┌──────────────────────────────────┐
 │ 📋 SIG Lite                      │  │ ☁️ CAIQ Lite                     │
 │ 20 questions | Risk & Access     │  │ 15 questions | Cloud Security    │
 │ [Generate Response] кнопка       │  │ [Generate Response] кнопка       │
 └──────────────────────────────────┘  └──────────────────────────────────┘

[Форма генерации — модальное окно]
  Questionnaire: SIG Lite (уже выбран)
  Requester Company: [text input]
  Requester Email: [email input]
  [Generate] кнопка (с предупреждением что займёт 1-3 мин)

[Прогресс генерации]
  Анимированный spinner + "Generating answers... (question 7/20)"

[История ответов — таблица]
  Колонки: Date | Questionnaire | Requester | Questions | Confidence | Actions
  Actions: [View] [Export TXT]

[Детальный view — модальное окно]
  Для каждого вопроса:
    Категория (badge)
    Вопрос (текст)
    Ответ (текст, редактируемый textarea)
    Confidence badge: 🟢 High / 🟡 Medium / 🔴 Low
    "Needs Review" предупреждение если needs_review=true
```

---

### 4. Изменения в `ui_server.py`

```python
from questionnaire_routes import router as questionnaire_router
app.include_router(questionnaire_router)

@app.get("/questionnaires", response_class=HTMLResponse)
async def questionnaires_page():
    return FileResponse(ROOT / "ui" / "questionnaires.html")
```

---

## Как проверить

```bash
# Список шаблонов (публичный)
curl http://localhost:8001/api/questionnaires/templates

# Сгенерировать ответы (Admin токен, занимает 1-3 мин с API)
curl -X POST http://localhost:8001/api/questionnaires/generate \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"questionnaire_id": "sig_lite", "requester": {"company": "Acme Corp", "email": "security@acme.com"}}'

# История
curl http://localhost:8001/api/questionnaires/responses \
  -H "Authorization: Bearer <admin_token>"

# Открыть UI
http://localhost:8001/questionnaires
```

---

## Статус после выполнения

Обновить `Task_status.md` с результатами.
