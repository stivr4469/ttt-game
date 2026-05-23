# Task 31 — AI Gap Analysis (персональный action plan для FAIL-контролей)

## Цель
Реализовать AI-powered Gap Analysis: для каждого FAIL-контроля LLM генерирует конкретный список действий что нужно сделать чтобы перейти в PASS. Аналог Vanta AI recommendations.

---

## Паттерны из кодовой базы (обязательно использовать)

**LLM клиент** (из `policy_agent.py`, строки 540-551):
```python
from openai import OpenAI
import os

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku")

client = OpenAI(
    api_key=OPENROUTER_API_KEY,
    base_url="https://openrouter.ai/api/v1",
    default_headers={"HTTP-Referer": "https://compliance-sandbox.local"}
)
```

**Evidence клиент** (из `auditor_routes.py`):
```python
from evidence_client import EvidenceClient
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
_ec = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="gap_analysis")
```

**Роутер** (из `auditor_routes.py`):
```python
from fastapi import APIRouter, Depends, HTTPException
from auth import decode_token, ROLES
router = APIRouter(prefix="/api/gap-analysis", tags=["gap-analysis"])
```

---

## Файлы для создания

### 1. `gap_analysis_agent.py`

```python
class GapAnalysisAgent:
    def __init__(self):
        # OpenRouter клиент (как в policy_agent.py)
        # EvidenceClient для получения данных
        # controls_map — читать из controls_map.json
    
    def analyze_control(self, control_id: str, control_info: dict, evidences: list) -> dict:
        """Синхронный вызов LLM для одного контроля."""
        # Промт: дать контексту название контроля + описание требования + список evidence
        # Попросить JSON: gap_description, actions, priority, estimated_days
        # Вернуть структуру ниже
    
    def run_full_analysis(self) -> dict:
        """Анализировать все FAIL-контроли, вернуть полный report."""
        # 1. Получить список контролей через _ec.get_controls()
        # 2. Отфильтровать FAIL
        # 3. Для каждого вызвать analyze_control()
        # 4. Вернуть dict ниже
```

**Структура возврата `analyze_control`:**
```json
{
  "control_id": "CC6.1",
  "control_name": "Logical Access Controls",
  "status": "FAIL",
  "priority": "critical",
  "gap_description": "MFA не включён для всех пользователей Okta",
  "actions": [
    "Включить MFA enforcement в Okta Admin Console → Security → Authenticators",
    "Установить политику: MFA required для всех приложений",
    "Пройти пересканирование: python3 scanner.py"
  ],
  "estimated_days": 1,
  "analyzed_at": "<ISO datetime>"
}
```

**Промт для LLM (вставить в код):**
```
You are a SOC 2 compliance expert. A control has FAILED. Analyze the evidence and provide a concrete remediation plan.

Control: {control_id} — {control_name}
Requirement: {requirement_description}
Evidence collected: {evidence_summary}

Respond ONLY with valid JSON (no markdown):
{
  "gap_description": "one sentence explaining why it failed",
  "actions": ["specific action 1", "specific action 2", "specific action 3"],
  "priority": "critical|high|medium",
  "estimated_days": <integer 1-30>
}
```

**`run_full_analysis` возвращает:**
```json
{
  "generated_at": "<ISO datetime>",
  "total_fail": 17,
  "controls": [ /* список analyze_control результатов */ ],
  "top_priority": [ /* только critical + high, отсортировано по estimated_days */ ]
}
```

**Если `OPENROUTER_API_KEY` не задан** — вернуть mock данные (не падать):
```python
MOCK_ANALYSIS = {
    "gap_description": "Control requires manual configuration — API key not configured for AI analysis",
    "actions": ["Configure OPENROUTER_API_KEY in .env", "Re-run gap analysis"],
    "priority": "medium",
    "estimated_days": 1
}
```

---

### 2. `gap_analysis_routes.py`

```python
router = APIRouter(prefix="/api/gap-analysis", tags=["gap-analysis"])
CACHE_FILE = Path(__file__).parent / "gap_analysis_cache.json"
```

**Эндпоинты:**

`GET /api/gap-analysis` — вернуть кешированный результат из `gap_analysis_cache.json`.
Если кеш отсутствует — вернуть `{"cached": false, "message": "Run POST /api/gap-analysis/refresh first"}`.
Требует auth: роли Admin или Auditor.

`GET /api/gap-analysis/{control_id}` — вернуть анализ одного контроля из кеша.
Если контроль не в кеше — `404`.

`POST /api/gap-analysis/refresh` — запустить `GapAnalysisAgent().run_full_analysis()`, сохранить в кеш, вернуть результат.
**Требует Admin.** Предупреждение: занимает 30-120 сек (LLM вызовы).

Сохранение кеша:
```python
def _save_cache(data: dict):
    with open(CACHE_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def _load_cache() -> dict | None:
    if CACHE_FILE.exists():
        return json.loads(CACHE_FILE.read_text())
    return None
```

---

### 3. UI секция в `ui/index.html`

Найти в `ui/index.html` подходящее место (например, после секции с контролями) и добавить:

```html
<!-- Gap Analysis секция -->
<section id="gap-analysis" style="margin-top:2rem">
  <div style="display:flex;justify-content:space-between;align-items:center">
    <h2>🎯 AI Gap Analysis</h2>
    <button onclick="refreshGapAnalysis()" id="gap-btn" 
            style="background:#00d4aa;color:#0f1117;border:none;padding:0.5rem 1rem;border-radius:6px;cursor:pointer">
      Run Analysis
    </button>
  </div>
  <div id="gap-results">Loading...</div>
</section>
```

JavaScript (добавить в `<script>`):
```javascript
async function loadGapAnalysis() {
  const r = await fetch('/api/gap-analysis', {headers: authHeaders()});
  const data = await r.json();
  // Отрендерить список контролей с action items
  // Priority badge: 🔴 critical / 🟠 high / 🟡 medium
  // Каждый action item — чекбокс (визуальный, не сохраняется)
  // "Est. fix: X days"
}

async function refreshGapAnalysis() {
  document.getElementById('gap-btn').textContent = 'Analyzing... (may take 1-2 min)';
  const r = await fetch('/api/gap-analysis/refresh', {method:'POST', headers: authHeaders()});
  const data = await r.json();
  renderGapResults(data);
}
```

Функция `authHeaders()` — взять из существующего JS в `ui/index.html` (там уже есть работа с JWT токеном).

---

### 4. Изменения в `ui_server.py`

После строки `from auditor_routes import router as auditor_router` добавить:
```python
from gap_analysis_routes import router as gap_analysis_router
app.include_router(gap_analysis_router)
```

---

## Как проверить

```bash
# Запустить refresh (Admin токен нужен)
curl -X POST http://localhost:8001/api/gap-analysis/refresh \
  -H "Authorization: Bearer <admin_token>"

# Посмотреть кеш
curl http://localhost:8001/api/gap-analysis \
  -H "Authorization: Bearer <admin_token>"

# Один контроль
curl http://localhost:8001/api/gap-analysis/CC6.1 \
  -H "Authorization: Bearer <admin_token>"
```

---

## Статус после выполнения

Обновить `Task_status.md` с результатами.
