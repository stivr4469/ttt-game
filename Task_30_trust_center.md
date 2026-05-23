# Task 30 — Trust Center (публичная страница compliance)

## Цель
Создать публичную страницу `/trust` — аналог Vanta Trust Center. Доступна без авторизации, показывает статус compliance организации потенциальным клиентам/партнёрам.

---

## Файлы для создания

### 1. `trust_routes.py`

```python
# Роутер подключается в ui_server.py аналогично access_review_routes.py
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pathlib import Path
import json, uuid, datetime

router = APIRouter(tags=["trust"])
TOKENS_FILE = Path(__file__).parent / "trust_access_tokens.json"
```

**Эндпоинты (все БЕЗ auth — публичные):**

`GET /trust` → вернуть `FileResponse("ui/trust.html")`

`GET /api/trust/snapshot` → вернуть JSON:
```json
{
  "org_name": "Marineso Inc.",
  "frameworks": [
    {"name": "SOC 2 Type II", "status": "certified", "last_audit": "2026-05-22", "auditor": "Deloitte"},
    {"name": "ISO 27001", "status": "in_progress", "last_audit": null, "auditor": null}
  ],
  "controls_summary": {"total": 33, "pass": 16, "fail": 17, "note": "FAILs are sandbox findings"},
  "uptime_30d": 99.9,
  "security_metrics": {
    "pen_tests_per_year": 2,
    "vuln_sla_critical_hours": 24,
    "employees_security_trained_pct": 80,
    "mfa_enforced": true,
    "encryption_at_rest": true,
    "soc2_audit_cycle": "annual"
  },
  "last_updated": "<ISO datetime now>"
}
```
Статус controls_summary брать из реального файла `controls_map.json` если доступен, иначе хардкод выше.

`POST /api/trust/request-access` → принять body `{"email": "...", "company": "...", "reason": "..."}`, сгенерировать UUID токен, сохранить в `trust_access_tokens.json` с timestamp и email, вернуть `{"token": "...", "expires_in_hours": 72}`.

`GET /api/trust/details?token=xxx` → проверить токен в `trust_access_tokens.json` (срок 72ч), вернуть расширенный JSON с перечнем всех 33 контролей и их статусами (читать из controls_map.json).

---

### 2. `ui/trust.html`

Dark theme (цвета как в `ui/index.html`: `#0f1117` фон, `#1a1d27` карточки, `#00d4aa` акцент).

**Структура страницы:**

```
[Шапка] 🛡️ Marineso Security & Trust Center
         "We believe security should be transparent"

[Фреймворки — карточки в ряд]
 ┌─────────────────┐  ┌─────────────────┐
 │ 🛡️ SOC 2 Type II│  │ 📋 ISO 27001    │
 │  ✅ Certified   │  │  🔄 In Progress │
 │  Last: May 2026 │  │  Est: Q4 2026   │
 └─────────────────┘  └─────────────────┘

[Live счётчики — 3 числа]
  33 Controls    16 Passing    99.9% Uptime

[Security Practices — 2 колонки иконок]
 ✅ MFA Enforced          ✅ Encryption at Rest
 ✅ Annual Pen Test        ✅ 24h Critical Patch SLA
 ✅ Security Training      ✅ SOC 2 Annual Audit

[CTA секция]
 "Need the full audit report?"
 [Request Detailed Report] кнопка → модальное окно с формой

[Модальное окно запроса]
  Поля: Email, Company, Reason (select: due diligence / vendor review / partnership)
  Кнопка Submit → POST /api/trust/request-access → показать "Check your email for the access link"

[Футер] "Last updated: <date>" | "Powered by Compliance Sandbox"
```

Данные загружать через `fetch('/api/trust/snapshot')` при загрузке страницы.
Анимированные счётчики (CSS counter animation) для чисел.

---

### 3. Изменения в `ui_server.py`

Добавить 3 строки после строки `from auditor_routes import router as auditor_router` (строка ~101):

```python
from trust_routes import router as trust_router
app.include_router(trust_router)
```

И добавить роут для HTML страницы (если `trust_routes.py` не возвращает HTML сам):
```python
@app.get("/trust", response_class=HTMLResponse)
async def trust_center():
    return FileResponse(ROOT / "ui" / "trust.html")
```
*(Если FileResponse для /trust уже есть в trust_routes.py — не дублировать.)*

---

## Важные детали

- `trust_access_tokens.json` — создавать если не существует (`{}` по умолчанию)
- Токены хранить: `{"<uuid>": {"email": "...", "company": "...", "created_at": "...", "expires_at": "..."}}`
- Проверка срока: `datetime.fromisoformat(token["expires_at"]) > datetime.now()`
- `/trust` и все `/api/trust/*` — **без** `Depends(decode_token)`, полностью публичные
- Комментарии в коде на русском

---

## Как проверить

```bash
# Запустить ui_server (если уже запущен — перезапустить)
python3 ui_server.py

# Проверить snapshot
curl http://localhost:8001/api/trust/snapshot

# Проверить запрос доступа
curl -X POST http://localhost:8001/api/trust/request-access \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","company":"Acme","reason":"due diligence"}'

# Открыть в браузере
http://localhost:8001/trust
```

---

## Статус после выполнения

Обновить `Task_status.md` с результатами.
