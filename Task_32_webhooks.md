# Task 32 — Webhook Real-time Triggers

## Цель
Добавить webhook endpoint-ы: GitHub/Okta/Slack шлют события → система мгновенно пересчитывает затронутые контроли через Celery, не дожидаясь ежедневного сканера.

---

## Контекст кодовой базы

- `celery_app.py` — уже настроен Celery + Redis
- `tasks.py` — существующие Celery задачи (посмотреть паттерн)
- `orchestrator.py` — запускает агентов (посмотреть как запускать агентов программно)
- `scanner.py` — имеет `main(controls_map)` функцию
- `github_agent.py` — имеет `main(controls_map)` функцию
- `hr_agent.py` — имеет `main(controls_map)` функцию
- `ui_server.py` строки 100-103 — паттерн подключения роутеров

---

## Файлы для создания

### 1. Добавить задачи в `tasks.py`

Дописать в конец существующего `tasks.py`:

```python
import json, os
from pathlib import Path

CONTROLS_MAP_FILE = Path(__file__).parent / "controls_map.json"

def _load_controls_map():
    if CONTROLS_MAP_FILE.exists():
        return json.loads(CONTROLS_MAP_FILE.read_text())
    return {}

# Маппинг: контроль → какой агент его пересчитывает
CONTROL_AGENT_MAP = {
    "CC8.1": "github",   # Change Authorization
    "CC5.3": "github",   # Change Management
    "CC3.4": "scanner",  # Change Assessment
    "CC6.1": "scanner",  # Logical Access
    "CC6.2": "hr",       # User Registration
    "CC6.3": "scanner",  # Least Privilege
    "CC6.8": "github",   # Anti-Malware / Dependabot
    "CC7.3": "github",   # Security Events / Advisories
}

@celery_app.task(name="tasks.rescan_control")
def rescan_control(control_id: str, trigger: str):
    """Пересканировать конкретный контроль по webhook-триггеру."""
    agent = CONTROL_AGENT_MAP.get(control_id)
    controls_map = _load_controls_map()
    if agent == "github":
        from github_agent import main as run_github
        run_github(controls_map)
    elif agent == "scanner":
        from scanner import main as run_scanner
        run_scanner(controls_map)
    elif agent == "hr":
        from hr_agent import main as run_hr
        run_hr(controls_map)
    # Записать в лог
    _append_webhook_log({"control_id": control_id, "trigger": trigger, "agent": agent, "ts": datetime.utcnow().isoformat()})

def _append_webhook_log(entry: dict):
    """Добавить запись в webhook_events.json, хранить последние 100."""
    log_file = Path(__file__).parent / "webhook_events.json"
    events = []
    if log_file.exists():
        try:
            events = json.loads(log_file.read_text())
        except:
            events = []
    events.append(entry)
    events = events[-100:]  # ротация — последние 100
    log_file.write_text(json.dumps(events, indent=2, ensure_ascii=False))
```

*(Добавить `from datetime import datetime` если нет в tasks.py)*

---

### 2. `webhook_routes.py`

```python
import hmac, hashlib, json, os, datetime
from pathlib import Path
from fastapi import APIRouter, Request, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from log_config import get_logger
from auth import decode_token, ROLES

router = APIRouter(prefix="/webhooks", tags=["webhooks"])
log = get_logger(__name__)

GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
OKTA_WEBHOOK_TOKEN    = os.getenv("OKTA_WEBHOOK_TOKEN", "")
EVENTS_FILE = Path(__file__).parent / "webhook_events.json"
```

**Маппинг GitHub событий → контроли:**
```python
GITHUB_EVENT_CONTROL_MAP = {
    "push":                     ["CC8.1", "CC5.3"],
    "pull_request":             ["CC5.3", "CC3.4"],
    "repository_vulnerability_alert": ["CC6.8", "CC7.3"],
    "security_advisory":        ["CC7.3"],
    "create":                   ["CC8.1"],
    "delete":                   ["CC8.1"],
}

OKTA_EVENT_CONTROL_MAP = {
    "user.lifecycle.deactivate":  ["CC6.2"],
    "user.lifecycle.create":      ["CC6.2"],
    "user.account.lock":          ["CC6.1"],
    "user.mfa.factor.deactivate": ["CC6.1"],
    "user.session.start":         ["CC6.1"],
}
```

**`POST /webhooks/github`:**
1. Прочитать header `X-Hub-Signature-256`
2. Верифицировать подпись HMAC-SHA256 (если `GITHUB_WEBHOOK_SECRET` задан; если не задан — пропустить верификацию)
3. Прочитать `X-GitHub-Event` header
4. Найти контроли в `GITHUB_EVENT_CONTROL_MAP`
5. Для каждого контроля: `rescan_control.delay(control_id, f"github_{event}")` (Celery async)
6. Записать в `webhook_events.json`: `{"source": "github", "event": event, "controls": [...], "ts": "..."}`
7. Вернуть `{"received": true, "controls_triggered": [...]}`

Верификация подписи:
```python
def _verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not secret:
        return True  # верификация отключена
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

**`POST /webhooks/okta`:**
1. Проверить header `Authorization: SSWS <token>` совпадает с `OKTA_WEBHOOK_TOKEN` (если задан)
2. Okta шлёт JSON с `data.events[].eventType`
3. Для каждого события найти контроли в `OKTA_EVENT_CONTROL_MAP`
4. Celery задачи + лог аналогично GitHub
5. Вернуть `{"received": true}`

**`POST /webhooks/slack`** (упрощённо):
1. Принять любой payload
2. Записать в лог с source="slack"
3. Вернуть `{"received": true}` (Slack требует немедленного 200)

**`GET /api/webhooks/log`** (требует Admin):
```python
@router.get("/api/webhooks/log")
async def get_webhook_log(token=Depends(decode_token)):
    if token["role"] not in ["Admin"]:
        raise HTTPException(403)
    events = []
    if EVENTS_FILE.exists():
        events = json.loads(EVENTS_FILE.read_text())
    return {"events": events[-50:], "total": len(events)}
```
*(Префикс роутера `/webhooks`, но этот эндпоинт нужен на `/api/webhooks/log` — используй отдельный router или `prefix=""` для этого роута)*

---

### 3. UI секция в `ui/index.html`

Добавить небольшую секцию "Recent Webhook Events" (после секции агентов или в sidebar):

```html
<div id="webhook-events" style="margin-top:1rem">
  <h3>⚡ Recent Webhook Events</h3>
  <div id="webhook-list" style="font-size:0.85rem;color:#8892a4">Loading...</div>
</div>
```

JS (добавить в script):
```javascript
async function loadWebhookEvents() {
  try {
    const r = await fetch('/api/webhooks/log', {headers: authHeaders()});
    if (!r.ok) return;
    const data = await r.json();
    const el = document.getElementById('webhook-list');
    if (!data.events.length) { el.textContent = 'No events yet'; return; }
    el.innerHTML = data.events.slice(-10).reverse().map(e =>
      `<div>⚡ ${e.source}/${e.event || 'event'} → ${(e.controls||[]).join(', ')||'—'} <span style="color:#4a5568">${e.ts?.slice(0,19)||''}</span></div>`
    ).join('');
  } catch(e) {}
}
// Вызвать при загрузке и каждые 30 сек
loadWebhookEvents();
setInterval(loadWebhookEvents, 30000);
```

---

### 4. Изменения в `ui_server.py`

После строки `from auditor_routes import router as auditor_router` добавить:
```python
from webhook_routes import router as webhook_router
app.include_router(webhook_router)
```

---

### 5. Добавить в `.env` (если нет)

```env
GITHUB_WEBHOOK_SECRET=
OKTA_WEBHOOK_TOKEN=
```
*(Пустые значения — верификация подписи отключена для sandbox)*

---

## Как проверить

```bash
# Тест GitHub webhook (без верификации подписи)
curl -X POST http://localhost:8001/webhooks/github \
  -H "X-GitHub-Event: push" \
  -H "Content-Type: application/json" \
  -d '{"repository":{"name":"compliance-sandbox"},"pusher":{"name":"test"}}'

# Лог событий (нужен Admin токен)
curl http://localhost:8001/api/webhooks/log \
  -H "Authorization: Bearer <admin_token>"

# Проверить что событие попало в файл
cat webhook_events.json
```

---

## Статус после выполнения

Обновить `Task_status.md` с результатами.
