# Task 35 — Vulnerability Management (CVE tracking)

## Цель
Добавить модуль управления уязвимостями: парсинг GitHub Dependabot alerts + Security Advisories, CVE severity scoring по CVSS, SLA tracking (Critical→24h, High→7d, Medium→30d). Закрыть контроли CC6.8 и CC7.3 (сейчас оба FAIL).

---

## Контекст кодовой базы

- `github_client.py` — уже есть GitHub клиент, посмотреть методы
- `github_agent.py` — посмотреть как использует github_client, паттерн
- `base_http_client.py` — базовый HTTP клиент с retry/backoff (использовать для GitHub API)
- `evidence_client.py` — `EvidenceClient.submit_evidence(control_code, description, data)`
- `constants.py` — GITHUB_TOKEN и другие константы
- `auditor_routes.py` — паттерн роутера
- `ui_server.py` строки 100-103 — паттерн подключения роутеров

---

## Файлы для создания

### 1. `vuln_agent.py`

**Класс `VulnAgent`:**

```python
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO  = os.getenv("GITHUB_REPO", "stivr4469/compliance-sandbox")
GITHUB_ORG   = os.getenv("GITHUB_ORG", "")

# SLA по severity (часы)
SLA_HOURS = {
    "critical": 24,
    "high":     168,   # 7 дней
    "medium":   720,   # 30 дней
    "low":      2160,  # 90 дней
}

class VulnAgent:
    def __init__(self):
        self.token = GITHUB_TOKEN
        self.repo  = GITHUB_REPO
        self.vulns_file = Path(__file__).parent / "vulnerabilities.json"
    
    def _gh_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
    
    def fetch_dependabot_alerts(self) -> list[dict]:
        """
        GET https://api.github.com/repos/{repo}/dependabot/alerts
        Параметры: state=open, per_page=100
        
        Если GITHUB_TOKEN не задан или запрос падает → вернуть mock данные:
        [
          {"number": 1, "state": "open", "severity": "high",
           "package": "requests", "version": "2.25.0", "cve_id": "CVE-2023-32681",
           "summary": "Unintended leak of Proxy-Authorization header",
           "created_at": "2026-05-01T...", "fixed_in": "2.31.0"},
          {"number": 2, "state": "open", "severity": "critical",
           "package": "pillow", "version": "9.0.0", "cve_id": "CVE-2023-44271",
           "summary": "Uncontrolled resource consumption in ImageFont",
           "created_at": "2026-05-10T...", "fixed_in": "10.0.1"},
          {"number": 3, "state": "open", "severity": "medium",
           "package": "cryptography", "version": "38.0.0", "cve_id": "CVE-2023-49083",
           "summary": "NULL pointer dereference in PKCS12 parsing",
           "created_at": "2026-04-20T...", "fixed_in": "41.0.6"}
        ]
        """
    
    def fetch_security_advisories(self) -> list[dict]:
        """
        GET https://api.github.com/repos/{repo}/security-advisories
        Если не доступно → вернуть [] (не критично)
        """
    
    def calculate_sla_status(self, vuln: dict) -> dict:
        """
        По created_at и severity вычислить:
        - deadline = created_at + SLA_HOURS[severity]
        - hours_remaining = (deadline - now).total_seconds() / 3600
        - sla_status = "on_track" | "at_risk" | "breached"
          at_risk: осталось < 20% времени SLA
          breached: deadline прошёл
        """
    
    def run(self, controls_map: dict = None) -> dict:
        """
        1. Fetch dependabot alerts
        2. Fetch security advisories
        3. Для каждой уязвимости добавить SLA статус
        4. Сохранить в vulnerabilities.json
        5. Подсчитать статистику
        6. Отправить evidence:
           - CC6.8 (Anti-Malware): evidence = статистика + список CVE
           - CC7.3 (Security Events): evidence = critical/high alerts
        7. Вернуть результат
        
        Результат:
        {
          "total": N,
          "by_severity": {"critical": N, "high": N, "medium": N, "low": N},
          "sla_breached": N,
          "sla_at_risk": N,
          "vulnerabilities": [...],
          "collected_at": "..."
        }
        """
```

**`vulnerabilities.json` — структура одной записи:**
```json
{
  "id": "VULN-001",
  "source": "dependabot",
  "number": 1,
  "cve_id": "CVE-2023-32681",
  "severity": "high",
  "package": "requests",
  "affected_version": "2.25.0",
  "fixed_in": "2.31.0",
  "summary": "Unintended leak of Proxy-Authorization header",
  "state": "open",
  "created_at": "2026-05-01T...",
  "sla_deadline": "2026-05-08T...",
  "sla_status": "breached",
  "hours_remaining": -336.5,
  "remediation": "pip install requests>=2.31.0",
  "jira_ticket": null
}
```

---

### 2. `vuln_routes.py`

```python
router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])
VULNS_FILE = Path(__file__).parent / "vulnerabilities.json"
```

**Эндпоинты:**

`GET /api/vulnerabilities` — список всех уязвимостей из файла.
Query params: `?severity=high&sla_status=breached&state=open`.
Requires: любой auth.

`GET /api/vulnerabilities/summary` — статистика. Requires: любой auth.

`GET /api/vulnerabilities/{vuln_id}` — одна уязвимость.

`POST /api/vulnerabilities/scan` — запустить `VulnAgent().run(controls_map)`. Requires: Admin.
Занимает несколько секунд.

`PATCH /api/vulnerabilities/{vuln_id}` — обновить статус (state: open→resolved, добавить jira_ticket). Requires: Admin, Auditor.

---

### 3. UI секция в `ui/index.html` или отдельный `ui/vulnerabilities.html`

Создать отдельную страницу `ui/vulnerabilities.html` (dark theme):

```
[Шапка] 🔒 Vulnerability Management
[Кнопки] [Run Scan] [Filter: All Severity ▼]

[SLA Dashboard — карточки]
  🔴 Breached SLA: N vulns    🟠 At Risk: N    🟢 On Track: N

[Таблица уязвимостей]
  Колонки: CVE | Package | Severity | Version | Fix | SLA Status | Deadline | Actions
  Цвет строки: critical=красный, high=оранжевый, medium=жёлтый
  SLA Breached строки — мигающая рамка (CSS animation)
  [Mark Resolved] кнопка в Actions

[Детальная панель (при клике на строку)]
  CVE description, affected component, remediation steps
  "Fix: pip install {package}>={fixed_in}"
```

JS:
- `fetch('/api/vulnerabilities')` при загрузке
- Фильтр по severity: клиентская фильтрация по уже загруженным данным
- [Run Scan] → `POST /api/vulnerabilities/scan` → обновить таблицу

---

### 4. Добавить агента в `audit_runner.py`

В фазу EVIDENCE COLLECTION добавить:
```python
print("  Vulnerabilities", end="", flush=True)
t = time.time()
from vuln_agent import VulnAgent
vuln_result = VulnAgent().run(controls_map)
print(f"  ✓  {vuln_result['total']} vulns    {time.time()-t:.1f}s")
```

*(Посмотреть точный паттерн print в audit_runner.py и скопировать форматирование)*

---

### 5. Изменения в `ui_server.py`

```python
from vuln_routes import router as vuln_router
app.include_router(vuln_router)

@app.get("/vulnerabilities", response_class=HTMLResponse)
async def vuln_page():
    return FileResponse(ROOT / "ui" / "vulnerabilities.html")
```

---

## Как проверить

```bash
# Запустить скан (Admin токен)
curl -X POST http://localhost:8001/api/vulnerabilities/scan \
  -H "Authorization: Bearer <admin_token>"

# Посмотреть список
curl http://localhost:8001/api/vulnerabilities \
  -H "Authorization: Bearer <token>"

# Только critical
curl "http://localhost:8001/api/vulnerabilities?severity=critical" \
  -H "Authorization: Bearer <token>"

# Проверить что CC6.8 и CC7.3 получили evidence
curl http://localhost:8001/api/evidence?control_code=CC6.8 \
  -H "Authorization: Bearer <token>"

# Открыть UI
http://localhost:8001/vulnerabilities
```

## Ожидаемый эффект
После запуска `audit_runner.py` контроли CC6.8 (Anti-Malware) и CC7.3 (Security Events) должны получить более богатые evidence. Возможен переход в PASS если mock-данные соответствуют требованиям сканера.

---

## Статус после выполнения

Обновить `Task_status.md` с результатами.
