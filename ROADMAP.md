# Sandbox Auditor — ROADMAP

SOC 2 Type II полигон: автоматический сбор доказательств, оценка контролей, AI-генерация политик, remediation, e-signature и аудит одной кнопкой.

---

## Фаза 1 — Базовая инфраструктура ✅ DONE

| Задача | Файл | Статус |
|---|---|---|
| LocalStack + Evidence Tracker | `docker-compose.yml` | ✅ |
| Seed уязвимой инфраструктуры | `seed_infrastructure.py` | ✅ |
| 33 SOC 2 контрола (AICPA) | `controls_seed.py` | ✅ |
| AWS + Okta + GitHub сканер | `scanner.py` | ✅ |
| Evidence Tracker клиент | `evidence_client.py` | ✅ |
| Slack нотификации | `slack_notifier.py` | ✅ |

---

## Фаза 2 — Специализированные агенты ✅ DONE

| Задача | Файл | Статус |
|---|---|---|
| GitHub compliance agent (8 проверок) | `github_agent.py` | ✅ |
| HR audit agent (5 проверок, Okta sync) | `hr_agent.py` | ✅ |
| MDM agent (device inventory, FileVault, EDR) | `mdm_agent.py` | ✅ |
| AI Policy Generator (16 контролей) | `policy_agent.py` | ✅ |
| BaseHTTPClient с retry/backoff | `base_http_client.py` | ✅ |

---

## Фаза 3 — Внешние интеграции ✅ DONE

| Задача | Файл | Статус |
|---|---|---|
| Jira remediation agent (idempotent tickets) | `remediation_agent.py` | ✅ |
| DocuSign e-signature agent | `esignature_agent.py` | ✅ |
| Jira client (ADF format) | `jira_client.py` | ✅ |
| DocuSign client (Bearer auth, base64 docs) | `docusign_client.py` | ✅ |
| UI endpoints для новых агентов | `ui_server.py` | ✅ |

---

## Фаза 4 — MDM-интеграции + DRY + тесты ✅ DONE

| Задача | Файл | Статус |
|---|---|---|
| Jamf Pro client (Classic API v1) | `jamf_client.py` | ✅ |
| Microsoft Intune client (Graph API, OAuth2) | `intune_client.py` | ✅ |
| Тесты Jamf (25 тестов) | `tests/test_jamf_client.py` | ✅ |
| Тесты Intune (19 тестов) | `tests/test_intune_client.py` | ✅ |
| Тесты DocuSign (22 теста) | `tests/test_docusign_client.py` | ✅ |
| Тесты RemediationAgent (15 тестов) | `tests/test_remediation_agent.py` | ✅ |
| conftest.py (sys.path для pytest) | `tests/conftest.py` | ✅ |

> ⚠️ DRY (SlackNotifier/GitHubClient → BaseHTTPClient) отложен: тесты используют `patch("requests.post")`, которое не перехватывает `Session.request`. Требует обновления моков в 14 тестах.

---

## Фаза 5 — Структурированные промты + Audit Runner ✅ DONE

| Задача | Файл | Статус |
|---|---|---|
| `sections` для всех 16 контролей в POLICY_CONTROLS | `policy_agent.py` | ✅ |
| `_build_sections_outline()` — динамический промт | `policy_agent.py` | ✅ |
| Аудит одной кнопкой (6 фаз) | `audit_runner.py` | ✅ |
| Фикс scanner.py (os.getenv переменные) | `scanner.py` | ✅ |
| Фикс github_agent.py (X-API-Key в create_fail_issues) | `github_agent.py` | ✅ |

### audit_runner.py — результаты последнего прогона (2026-05-22)

```
EVIDENCE COLLECTION
  AWS+Okta       ✓  1101 items    11.6s
  GitHub         ✓  1111 items     5.6s
  MDM            ✓     8 items     0.2s
  HR             ✓  1116 items     1.9s

CONTROL STATUS (33 total)
  PASS    ███████████░░░░░░░░░░░    16  (48.5%)
  FAIL    ███████████░░░░░░░░░░░    17  (51.5%)

POLICIES GENERATED    8 / 9 governance controls
REMEDIATION TICKETS   17 created
E-SIGNATURE           envelope sent to ciso@marineso.com

OVERALL READINESS     ████████░░░░░░░░  48%
AUDIT VERDICT         ⚠  NOT READY — 17 controls require remediation

Duration: 391.8s
```

---

## Покрытие контролей AICPA vs Vanta

| Категория | Контролей | Автоматизировано | % |
|---|---|---|---|
| CC1 (Control Environment) | 5 | 3 | 60% |
| CC2 (Communication) | 3 | 2 | 67% |
| CC3 (Risk Assessment) | 4 | 3 | 75% |
| CC4 (Monitoring) | 2 | 2 | 100% |
| CC5 (Control Activities) | 3 | 2 | 67% |
| CC6 (Logical Access) | 8 | 8 | 100% |
| CC7 (System Operations) | 5 | 5 | 100% |
| CC8 (Change Management) | 1 | 1 | 100% |
| CC9 (Risk Mitigation) | 2 | 2 | 100% |
| **Итого** | **33** | **28** | **~85%** |

---

## Тесты

```bash
cd /home/zastone/study/Poligon/sandbox-auditor
python3 -m pytest tests/ -v
# 81 тест, все зелёные
```

---

## Следующие шаги (бэклог)

| Приоритет | Задача |
|---|---|
| HIGH | Поднять PASS с 48% → 80%: включить branch protection, CI/CD, secret scanning |
| HIGH | DRY: SlackNotifier + GitHubClient → BaseHTTPClient (обновить моки в тестах) |
| MEDIUM | `--parallel` режим в audit_runner (threading для Phase 1) |
| MEDIUM | HTML-отчёт из audit_runner (Jinja2 template) |
| LOW | Webhook-триггер: аудит по push в main |
| LOW | Тесты для audit_runner (mock всех агентов) |
