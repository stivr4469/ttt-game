# Task 34 — Risk Register (реестр рисков)

## Цель
Создать отдельный модуль Risk Register: явный учёт рисков с оценкой likelihood/impact, owner, treatment plan, timeline. Автоматически генерировать риски из FAIL-контролей. Аналог Vanta Risk Management.

---

## Контекст кодовой базы

- `auditor_routes.py` — паттерн роутера (APIRouter, EvidenceClient, Depends(decode_token))
- `evidence_client.py` — `EvidenceClient.get_controls()` возвращает список контролей со статусом
- `controls_map.json` — маппинг контролей: `{"CC6.1": {"name": "...", "description": "..."}}`
- `jira_client.py` — Jira клиент (посмотреть как создаются тикеты — риски линкуются с тикетами)
- `auth.py` — `decode_token`, `ROLES`
- `ui/index.html` — стиль dark theme
- `ui_server.py` строки 100-103 — паттерн подключения роутеров

---

## Файлы для создания

### 1. `risk_register.py` (модуль данных)

Хранилище — `risk_register.json`. Структура одного риска:
```json
{
  "id": "RISK-001",
  "title": "MFA not enforced for all users",
  "description": "Okta MFA policy is not applied to all applications",
  "source": "control",
  "control_id": "CC6.1",
  "likelihood": 4,
  "impact": 5,
  "risk_score": 20,
  "category": "access_control",
  "owner": "ciso@marineso.com",
  "treatment": "mitigate",
  "treatment_plan": "Enable MFA enforcement in Okta Admin Console",
  "status": "open",
  "jira_ticket": null,
  "created_at": "2026-05-22T...",
  "updated_at": "2026-05-22T...",
  "target_date": "2026-06-15"
}
```

**Поля:**
- `likelihood`: 1-5 (1=Rare, 2=Unlikely, 3=Possible, 4=Likely, 5=Almost Certain)
- `impact`: 1-5 (1=Negligible, 2=Minor, 3=Moderate, 4=Major, 5=Critical)
- `risk_score`: likelihood × impact (1-25)
- `category`: `access_control | data_protection | change_management | vendor | operational | compliance`
- `treatment`: `accept | mitigate | transfer | avoid`
- `status`: `open | in_progress | resolved | accepted`
- `source`: `control` (авто из FAIL) | `manual` (создан вручную)

**Класс `RiskRegister`:**

```python
class RiskRegister:
    RISK_FILE = Path(__file__).parent / "risk_register.json"
    
    # Маппинг контролей на категории рисков
    CONTROL_CATEGORY_MAP = {
        "CC6.1": "access_control", "CC6.2": "access_control",
        "CC6.3": "access_control", "CC6.7": "data_protection",
        "CC6.8": "operational",    "CC7.1": "operational",
        "CC7.2": "operational",    "CC7.3": "operational",
        "CC7.4": "operational",    "CC8.1": "change_management",
        "CC5.3": "change_management", "CC9.2": "vendor",
        "CC1.4": "compliance",     "CC3.4": "change_management",
    }
    
    def _load(self) -> list[dict]: ...
    def _save(self, risks: list[dict]): ...
    
    def get_all(self, status: str = None, category: str = None) -> list[dict]:
        """Фильтрация по статусу и категории."""
    
    def get_by_id(self, risk_id: str) -> dict | None: ...
    
    def create(self, data: dict) -> dict:
        """Создать риск. ID генерировать: RISK-001, RISK-002..."""
    
    def update(self, risk_id: str, data: dict) -> dict:
        """Обновить поля риска, пересчитать risk_score."""
    
    def delete(self, risk_id: str) -> bool: ...
    
    def sync_from_controls(self, controls: list[dict]) -> dict:
        """
        Главная функция: взять список FAIL-контролей,
        создать/обновить риски автоматически.
        Для каждого FAIL-контроля без существующего риска — создать новый.
        Уже существующие риски (source=control, control_id=X) — не дублировать.
        
        Дефолтные значения при автосоздании:
          likelihood = 3, impact = 4 (можно поменять вручную потом)
          treatment = "mitigate"
          status = "open"
          owner = "ciso@marineso.com"
          target_date = сегодня + 30 дней
        
        Вернуть: {"created": N, "updated": N, "skipped": N}
        """
    
    def get_summary(self) -> dict:
        """
        Статистика для дашборда:
        {
          "total": N,
          "by_status": {"open": N, "in_progress": N, "resolved": N, "accepted": N},
          "by_category": {...},
          "critical_count": N,  # risk_score >= 20
          "high_count": N,       # risk_score 15-19
          "medium_count": N,     # risk_score 8-14
          "low_count": N,        # risk_score <= 7
          "average_score": float
        }
        """
    
    def get_risk_matrix(self) -> list[dict]:
        """Данные для матрицы 5x5 (likelihood vs impact)."""
        # Вернуть риски с координатами для отрисовки матрицы
```

---

### 2. `risk_routes.py`

```python
router = APIRouter(prefix="/api/risks", tags=["risk-register"])
_register = RiskRegister()
```

**Эндпоинты:**

`GET /api/risks` — все риски. Query params: `?status=open&category=access_control`. Requires: Admin, Auditor, Viewer.

`GET /api/risks/summary` — статистика. Requires: любой auth.

`GET /api/risks/matrix` — данные для risk matrix. Requires: любой auth.

`GET /api/risks/{risk_id}` — один риск. Requires: любой auth.

`POST /api/risks` — создать риск вручную. Requires: Admin, Auditor.
Body: title, description, likelihood, impact, category, owner, treatment, treatment_plan, target_date.

`PATCH /api/risks/{risk_id}` — обновить поля. Requires: Admin, Auditor.

`DELETE /api/risks/{risk_id}` — удалить. Requires: Admin only.

`POST /api/risks/sync` — синхронизировать из FAIL-контролей через EvidenceClient. Requires: Admin.
Вызывает `_register.sync_from_controls(controls)`.

---

### 3. `ui/risk-register.html`

Dark theme. Структура:

```
[Шапка] ⚠️ Risk Register
[Кнопки] [Sync from Controls] [+ Add Risk] [Export PDF]

[Summary карточки — 4 в ряд]
  🔴 Critical (score≥20): N
  🟠 High (15-19): N
  🟡 Medium (8-14): N
  🟢 Low (≤7): N

[Risk Matrix — сетка 5x5]
  Ось X: Impact (1-5)
  Ось Y: Likelihood (1-5)
  Ячейки раскрашены: зелёный→красный
  В ячейках: точки/числа рисков
  (Рендерить через CSS grid или canvas)

[Таблица рисков]
  Колонки: ID | Title | Category | Score | Owner | Status | Treatment | Target Date | Actions
  Строки кликабельны → модальное окно редактирования
  Фильтры: Status dropdown, Category dropdown
  Цвет строки зависит от risk_score

[Модальное окно Add/Edit риска]
  Поля: Title, Description, Likelihood (select 1-5), Impact (select 1-5),
        Category (select), Owner (email), Treatment (select), Treatment Plan, Target Date
  Risk Score = Likelihood × Impact (вычисляется в реальном времени)
  [Save] [Cancel]
```

JS: CRUD через fetch к `/api/risks/*`. Risk score вычислять на фронте при изменении слайдеров.

---

### 4. Изменения в `ui_server.py`

```python
from risk_routes import router as risk_router
app.include_router(risk_router)

@app.get("/risk-register", response_class=HTMLResponse)
async def risk_register_page():
    return FileResponse(ROOT / "ui" / "risk-register.html")
```

### 5. Изменения в `audit_runner.py`

После сбора evidence добавить:
```python
from risk_register import RiskRegister
rr = RiskRegister()
sync_result = rr.sync_from_controls(fail_controls)
print(f"Risk Register: {sync_result['created']} created, {sync_result['updated']} updated")
```

---

## Как проверить

```bash
# Синхронизация из FAIL-контролей
curl -X POST http://localhost:8001/api/risks/sync \
  -H "Authorization: Bearer <admin_token>"

# Получить все риски
curl http://localhost:8001/api/risks \
  -H "Authorization: Bearer <token>"

# Summary
curl http://localhost:8001/api/risks/summary \
  -H "Authorization: Bearer <token>"

# Открыть UI
http://localhost:8001/risk-register
```

---

## Статус после выполнения

Обновить `Task_status.md` с результатами.
