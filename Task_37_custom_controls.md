# Task 37 — Customizable Controls (кастомные контроли)

## Цель
Разрешить добавлять собственные compliance контроли помимо стандартных 33 AICPA SOC2. Нужно для regulated industries (GDPR Article 13, HIPAA §164.308, кастомные корпоративные требования). Аналог Vanta Custom Controls.

---

## Контекст кодовой базы

- `controls_map.json` — текущие 33 контроля (read-only, не изменять)
- `evidence_client.py` — `EvidenceClient`: `get_controls()`, `submit_evidence()`, `create_control()` (проверить есть ли такой метод; если нет — добавить через прямой HTTP к Evidence Tracker)
- `scanner.py` — посмотреть как создаются evidence записи (паттерн)
- `auditor_routes.py` — паттерн роутера
- `auth.py` — decode_token, ROLES
- `ui_server.py` строки 100-103 — паттерн подключения роутеров
- `ui/index.html` — стиль dark theme

---

## Архитектура

Кастомные контроли хранятся **отдельно** от стандартных:
- `custom_controls.json` — локальное хранилище кастомных контролей
- Не затрагивает `controls_map.json` и Evidence Tracker DB

---

## Файлы для создания

### 1. `custom_controls.py` (модуль данных)

Структура одного кастомного контроля:
```json
{
  "id": "CUSTOM-001",
  "code": "GDPR-13",
  "name": "GDPR Article 13 — Privacy Notice",
  "description": "Data subjects must be informed about data processing at collection time",
  "framework": "GDPR",
  "category": "data_protection",
  "owner": "dpo@marineso.com",
  "status": "manual",
  "evidence_description": "Privacy notice displayed on all data collection forms",
  "evidence_links": ["https://marineso.com/privacy", "policies/privacy_policy.md"],
  "pass_criteria": "Privacy notice must be visible at all data collection points",
  "current_status": "PASS",
  "last_checked": "2026-05-22T...",
  "notes": "Reviewed by DPO on 2026-05-20",
  "created_at": "2026-05-22T...",
  "created_by": "admin@marineso.com",
  "tags": ["gdpr", "privacy", "eu"]
}
```

**Поля:**
- `framework`: `GDPR | HIPAA | PCI_DSS | ISO_27001 | CUSTOM | SOC2`
- `category`: `access_control | data_protection | change_management | vendor | operational | compliance | privacy`
- `status`: `manual` (оценка вручную) | `automated` (планируется автоматическая проверка)
- `current_status`: `PASS | FAIL | NOT_ASSESSED | IN_PROGRESS`

**Класс `CustomControlsManager`:**

```python
class CustomControlsManager:
    CONTROLS_FILE = Path(__file__).parent / "custom_controls.json"
    
    # Предустановленные шаблоны для быстрого старта
    TEMPLATES = {
        "gdpr_13": {
            "code": "GDPR-13", "name": "GDPR Article 13 — Privacy Notice",
            "framework": "GDPR", "category": "data_protection",
            "pass_criteria": "Privacy notice displayed at all data collection points"
        },
        "gdpr_17": {
            "code": "GDPR-17", "name": "GDPR Article 17 — Right to Erasure",
            "framework": "GDPR", "category": "data_protection",
            "pass_criteria": "Data deletion requests processed within 30 days"
        },
        "hipaa_safeguards": {
            "code": "HIPAA-164.308", "name": "HIPAA Administrative Safeguards",
            "framework": "HIPAA", "category": "access_control",
            "pass_criteria": "Designated security officer assigned and documented"
        },
        "pci_encryption": {
            "code": "PCI-3.4", "name": "PCI DSS — Cardholder Data Encryption",
            "framework": "PCI_DSS", "category": "data_protection",
            "pass_criteria": "All stored cardholder data encrypted with AES-256"
        },
    }
    
    def _load(self) -> list[dict]: ...
    def _save(self, controls: list[dict]): ...
    
    def get_all(self, framework: str = None, status: str = None) -> list[dict]:
        """Фильтрация по framework и current_status."""
    
    def get_by_id(self, control_id: str) -> dict | None: ...
    
    def get_templates(self) -> list[dict]:
        """Список доступных шаблонов."""
    
    def create_from_template(self, template_id: str, created_by: str) -> dict:
        """Создать контроль из шаблона."""
    
    def create(self, data: dict, created_by: str) -> dict:
        """
        Создать кастомный контроль.
        ID генерировать: CUSTOM-001, CUSTOM-002...
        Проверить уникальность code.
        """
    
    def update(self, control_id: str, data: dict) -> dict:
        """Обновить контроль (все поля кроме id, created_at, created_by)."""
    
    def update_status(self, control_id: str, status: str, notes: str, updated_by: str) -> dict:
        """Обновить current_status + last_checked + notes."""
    
    def delete(self, control_id: str) -> bool: ...
    
    def get_summary(self) -> dict:
        """
        {
          "total": N,
          "by_framework": {"GDPR": N, "HIPAA": N, ...},
          "by_status": {"PASS": N, "FAIL": N, "NOT_ASSESSED": N, "IN_PROGRESS": N},
          "pass_rate": float
        }
        """
    
    def get_all_controls_combined(self, standard_controls: list[dict]) -> list[dict]:
        """
        Объединить стандартные (из EvidenceClient) + кастомные контроли.
        Добавить поле "is_custom": True/False.
        """
```

---

### 2. `custom_controls_routes.py`

```python
router = APIRouter(prefix="/api/custom-controls", tags=["custom-controls"])
_manager = CustomControlsManager()
```

**Эндпоинты:**

`GET /api/custom-controls` — все кастомные контроли. Query: `?framework=GDPR&status=FAIL`. Requires: любой auth.

`GET /api/custom-controls/summary` — статистика. Requires: любой auth.

`GET /api/custom-controls/templates` — список шаблонов. Requires: любой auth.

`GET /api/custom-controls/{control_id}` — один контроль.

`POST /api/custom-controls` — создать новый. Requires: Admin, Auditor.
Body: все поля кроме id, created_at, created_by.

`POST /api/custom-controls/from-template/{template_id}` — создать из шаблона. Requires: Admin, Auditor.

`PATCH /api/custom-controls/{control_id}` — обновить поля. Requires: Admin, Auditor.

`POST /api/custom-controls/{control_id}/status` — обновить статус. Requires: Admin, Auditor.
Body: `{"status": "PASS", "notes": "Verified by DPO on 2026-05-22"}`

`DELETE /api/custom-controls/{control_id}` — удалить. Requires: Admin.

`GET /api/controls/all` — **объединённый список** стандартных + кастомных контролей. Requires: любой auth.
*(Это новый эндпоинт поверх существующего `/api/controls`)*

---

### 3. UI секция — добавить вкладку в `ui/index.html`

В существующем дашборде найти секцию с контролями и добавить переключатель:

```html
<div style="display:flex;gap:1rem;margin-bottom:1rem">
  <button onclick="showControls('standard')" class="tab-btn active">
    Standard (33)
  </button>
  <button onclick="showControls('custom')" class="tab-btn">
    Custom (0)
  </button>
  <button onclick="showControls('all')" class="tab-btn">
    All Controls
  </button>
  <!-- Только для Admin/Auditor -->
  <button onclick="openAddCustomControl()" 
          style="margin-left:auto;background:#00d4aa;color:#0f1117;border:none;padding:0.4rem 1rem;border-radius:6px;cursor:pointer">
    + Add Custom Control
  </button>
</div>
```

**Модальное окно "Add Custom Control":**
```
[Быстрый старт — шаблоны]
  [GDPR-13] [GDPR-17] [HIPAA-164.308] [PCI-3.4] [Custom...]

[Форма]
  Code:        [text] e.g. GDPR-13
  Framework:   [select: GDPR/HIPAA/PCI_DSS/ISO_27001/CUSTOM]
  Name:        [text]
  Description: [textarea]
  Category:    [select]
  Owner:       [email]
  Pass Criteria: [textarea]
  Current Status: [select: NOT_ASSESSED/PASS/FAIL/IN_PROGRESS]
  [Save] [Cancel]
```

**Отображение кастомных контролей в таблице:**
- Те же колонки что у стандартных: Code | Name | Status | Framework | Owner | Actions
- Status: PASS=зелёный, FAIL=красный, NOT_ASSESSED=серый, IN_PROGRESS=жёлтый
- Actions: [Edit Status] [Edit] [Delete]

---

### 4. Изменения в `ui_server.py`

```python
from custom_controls_routes import router as custom_controls_router
app.include_router(custom_controls_router)
```

*(HTML страницы нет — встраивается в index.html)*

---

## Как проверить

```bash
# Список шаблонов
curl http://localhost:8001/api/custom-controls/templates \
  -H "Authorization: Bearer <token>"

# Создать из шаблона GDPR-13
curl -X POST http://localhost:8001/api/custom-controls/from-template/gdpr_13 \
  -H "Authorization: Bearer <admin_token>"

# Создать кастомный контроль вручную
curl -X POST http://localhost:8001/api/custom-controls \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "CORP-001",
    "name": "Data Retention Policy",
    "framework": "CUSTOM",
    "category": "data_protection",
    "owner": "ciso@marineso.com",
    "pass_criteria": "All data retention periods documented and enforced",
    "current_status": "NOT_ASSESSED"
  }'

# Обновить статус
curl -X POST http://localhost:8001/api/custom-controls/CUSTOM-001/status \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"status": "PASS", "notes": "Reviewed and confirmed 2026-05-22"}'

# Объединённый список всех контролей
curl http://localhost:8001/api/controls/all \
  -H "Authorization: Bearer <token>"
```

---

## Статус после выполнения

Обновить `Task_status.md` с результатами.
