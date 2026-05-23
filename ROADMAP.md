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
| DRY: SlackNotifier + GitHubClient → BaseHTTPClient | `slack_notifier.py`, `github_client.py` | ✅ |

---

## Фаза 5 — Audit Runner + Policy + Trust Center ✅ DONE

| Задача | Файл | Статус |
|---|---|---|
| `sections` для всех 16 контролей в POLICY_CONTROLS | `policy_agent.py` | ✅ |
| Аудит одной кнопкой (6 фаз) | `audit_runner.py` | ✅ |
| `--parallel` режим (4 потока, 330s вместо 391s) | `audit_runner.py` | ✅ |
| HTML-отчёт (Jinja2 standalone) | `html_report.py` | ✅ |
| Публичный Trust Center с NDA-gate | `trust_routes.py` | ✅ |
| AI Gap Analysis (action plan для каждого FAIL) | `gap_analysis_agent.py` | ✅ |
| Webhook Real-time (GitHub/Okta → Celery) | `webhook_routes.py` | ✅ |

---

## Фаза 6 — People & Devices ✅ DONE

| Задача | Файл | Контроль | Статус |
|---|---|---|---|
| Security Training LMS (5 курсов, сертификаты) | `training_agent.py` | CC1.4 | ✅ |
| Background Checks (Checkr mock, compliance %) | `background_check_agent.py` | CC6.2 | ✅ |
| Vulnerability Management (CVE, SLA 24h/7d/30d) | `vuln_agent.py` | CC6.8, CC7.3 | ✅ |

---

## Фаза 8 — Production Hardening + Observability ✅ DONE

| Задача | Файл | Статус |
|---|---|---|
| Pydantic BaseSettings (централизованный конфиг) | `config.py` | ✅ |
| Dockerfile с build deps (gcc/libffi/libssl) | `Dockerfile` | ✅ |
| docker-compose: restart, Redis persistence, ui_server | `docker-compose.yml` | ✅ |
| CORS env-based (CORS_ORIGINS), security headers | `ui_server.py` | ✅ |
| Rate limiting 10/min на /api/auth/login (slowapi) | `ui_server.py` | ✅ |
| Auth на /api/scheduler/trigger + /api/tasks/run | `ui_server.py` | ✅ |
| Prometheus /metrics endpoint (prometheus-client) | `ui_server.py` | ✅ |
| Grafana auto-provisioned дашборд (9 панелей) | `grafana/` | ✅ |
| SecurityHeadersMiddleware (HSTS, X-Frame, CSP) | `ui_server.py` | ✅ |
| log_config.py: корректный захват extra-полей | `log_config.py` | ✅ |

---

## Фаза 7 — Enterprise Compliance Features ✅ DONE

| Задача | Файл | Статус |
|---|---|---|
| Risk Register (likelihood×impact, авто из FAIL) | `risk_register.py` | ✅ |
| Questionnaire Automation (SIG Lite + CAIQ Lite) | `questionnaire_agent.py` | ✅ |
| Custom Controls (GDPR/HIPAA/PCI поверх SOC2) | `custom_controls.py` | ✅ |
| Pentest Management (отчёты, findings, SLA) | `pentest_agent.py` | ✅ |
| Audit Timeline Wizard (milestone tracking) | `audit_timeline.py` | ✅ |
| Reports API (HTML download, список) | `report_routes.py` | ✅ |
| Единая навигация (sidebar, 6 секций) | `ui/index.html` | ✅ |
| `require_auth` / `require_admin` в auth.py | `auth.py` | ✅ |

---

## Последний прогон audit_runner.py (2026-05-22, --parallel)

```
EVIDENCE COLLECTION  [parallel (4 threads)]
  AWS+Okta       ✓  1568 items     5.0s
  GitHub         ✓  1568 items     4.8s
  MDM            ✓     8 items     0.2s
  HR             ✓  1568 items     1.9s
  Training       ✓                 — (source зафиксирован)
  Vulnerabilities ✓                — (source зафиксирован)

CONTROL STATUS (33 total)
  PASS    ██████████████████░░░░    27  (81.8%)
  FAIL    ████░░░░░░░░░░░░░░░░░░     6  (18.2%)

TOP FAILURES
  CC6.1   Root MFA disabled, слабая парольная политика  CRITICAL
  CC6.3   Пользователь с ролью SUPER_ADMIN              HIGH
  CC6.2   Уволенный пользователь остался активным       HIGH
  CC8.1   Нет branch protection на main                 HIGH
  CC3.4   Прямые коммиты в main без PR                  MEDIUM
  CC1.4   Просрочен training у 2 сотрудников            MEDIUM

POLICIES GENERATED    11 / 12 governance controls
REMEDIATION TICKETS   6 created
E-SIGNATURE           envelope sent to ciso@marineso.com

OVERALL READINESS     █████████████░░░  82%
AUDIT VERDICT         ⚠  NOT READY — 6 controls require remediation

Mode: parallel (4 threads)
Duration: 330.7s
HTML Report: reports/audit_report_2026-05-22_235514.html
```

---

## Покрытие контролей AICPA

| Категория | Контролей | Автоматизировано | % |
|---|---|---|---|
| CC1 (Control Environment) | 5 | 4 | 80% |
| CC2 (Communication) | 3 | 3 | 100% |
| CC3 (Risk Assessment) | 4 | 4 | 100% |
| CC4 (Monitoring) | 2 | 2 | 100% |
| CC5 (Control Activities) | 3 | 3 | 100% |
| CC6 (Logical Access) | 8 | 8 | 100% |
| CC7 (System Operations) | 5 | 5 | 100% |
| CC8 (Change Management) | 1 | 1 | 100% |
| CC9 (Risk Mitigation) | 2 | 2 | 100% |
| **Итого** | **33** | **32** | **~97%** |

---

## Покрытие Vanta feature set

| Метрика | Фазы 1-5 | Фазы 6-7 | Фаза 8 | Фазы 9-10 | Целевое |
|---|---|---|---|---|---|
| SOC 2 controls с evidence | 33/33 (100%) | 33/33 (100%) | 33/33 (100%) | 33/33 (100%) | 33/33 |
| Автоматизация сбора | ~75% | ~85% | ~85% | **~90%** | ~90% |
| Покрытие Vanta feature set | ~85% | ~92% | ~94% | **~98%** | ~95% |
| Production-readiness | ~85% | ~90% | ~96% | **~97%** | ~95% |
| Тест-покрытие (pytest) | 292 теста ✅ | 291/292 ✅ | 271/271 ✅ | **423/423 ✅** | — |
| Audit readiness (PASS%) | 48% | 82% | 82% | **82%** | 90%+ |

### Что закрыто в Фазах 9-10 (было gap vs Vanta)

| Фича | До | После |
|---|---|---|
| Vendor Risk Management (vendor reviews, DPA, subprocessors) | ❌ gap | ✅ |
| Multi-framework mapping (SOC2↔ISO27001↔NIST↔CIS) | ❌ gap | ✅ |
| Continuous compliance SLA-метрики | ❌ gap | ✅ |
| SOAR: интерактивное управление из Slack (revoke IAM, auto-fix) | ❌ частично | ✅ |

### Beyond Vanta — фичи которых нет у конкурентов

| Фича | Описание |
|---|---|
| **Time-Machine Audit** | Реконструкция compliance-состояния на любую дату в прошлом |
| **Compliance-as-Code** | YAML-декларации контролей с auto-remediation и approval workflow |
| **Chaos Compliance Runner** | Намеренные инъекции нарушений + замер SLA авто-реакции |
| **Control Cross-Mapping** | Единый граф: один контроль покрывает SOC2 + ISO + NIST + CIS |
| **Slack Interactive SOAR** | Отзыв прав в AWS/IAM прямо из Slack-кнопки |

### Оставшийся gap (~2%)

| Задача | Gap |
|---|---|
| Multi-cloud: GCP + Azure сканеры | ~1.5% |
| Multi-tenant (несколько организаций) | ~0.5% |

## Docker стек (2026-05-23)

```
docker compose up -d   →   6 сервисов

  ui_server    :8080   ✅ healthy   SOC 2 Dashboard
  grafana      :3000   ✅ healthy   Observability (admin/soc2admin)
  prometheus   :9090   ✅ healthy   Metrics scrape каждые 15s
  redis        :6379   ✅ healthy   Celery broker + persistence
  celery       —       ✅ healthy   Async task queue
  localstack   :4566   ✅ healthy   AWS mock
```

## Grafana дашборд — SOC 2 Compliance Dashboard

| Панель | Метрика | SOC 2 контроль |
|---|---|---|
| Request Rate | req/s | — |
| Error Rate (5xx) | % ошибок | CC7.1 мониторинг |
| P95 Latency | мс | CC7.1 производительность |
| HTTP by Status | 2xx/4xx/5xx timeline | CC7.2 |
| Latency p50/p90/p99 | гистограмма | CC7.1 |
| Top Endpoints | таблица запросов | — |
| Auth Failures 401/403 | таблица | CC6.1 доступ |
| Scan Trigger Activity | bar chart | CC7.2 security events |

---

## Тесты

```bash
cd /home/zastone/study/Poligon/sandbox-auditor
python3 -m pytest tests/ -v
# 423/423 тестов зелёные ✅
```

---

## Страницы UI (доступные маршруты)

| Маршрут | Страница | Auth |
|---|---|---|
| `/` | Dashboard | ✅ |
| `/trust` | Trust Center | 🌐 публичный |
| `/training` | Security Training LMS | ✅ |
| `/background-checks` | Background Checks | ✅ Admin |
| `/vulnerabilities` | Vulnerability Management | ✅ |
| `/pentests` | Pentest Reports | ✅ Admin |
| `/risk-register` | Risk Register | ✅ |
| `/audit-timeline` | Audit Timeline Wizard | ✅ Admin |
| `/questionnaires` | Questionnaire Automation | ✅ |
| `/access-review` | Access Review | ✅ |
| `/auditor-portal` | Auditor Portal | ✅ Auditor |

---

## Фаза 9 — Intelligence & Beyond Vanta ✅ DONE

> Цель: превзойти Vanta по техническим возможностям. Эти фичи недоступны в Vanta/Drata из коробки.

| Задача | Файл | Контроль | Статус |
|---|---|---|---|
| Control Mapping Engine (SOC2↔ISO27001↔NIST↔CIS) | `control_mapping.py` | All | ✅ |
| Time-Machine Audit (point-in-time compliance state) | `time_machine.py` | CC4.1, CC7.2 | ✅ |
| Compliance-as-Code (YAML-defined controls + auto-remediation) | `compliance_as_code.py` | All | ✅ |
| Vendor Risk Management (vendor reviews, DPA, subprocessors) | `vendor_risk_agent.py` | CC9.2 | ✅ |
| Segregation of Duties (AI draft → Human approve only) | `policy_lifecycle.py` | CC1.2, CC6.3 | ✅ |
| Explainability Layer (AI Decision Trace, audit trail) | `ai_decision_log.py` | CC4.1 | ✅ |
| Evidence Confidence Scoring (freshness + integrity + source) | `evidence_confidence.py` | CC4.1, CC7.2 | ✅ |

### Детали фичей

**Control Mapping Engine** — единый граф: один контроль покрывает сразу несколько фреймворков.
Пример: `CC6.1 ↔ ISO 27001 A.5.15 ↔ NIST AC-2 ↔ CIS 6.1`. Мультифреймворковый аудит одним сканером.

**Time-Machine Audit** — аудитор выбирает дату, система реконструирует полное compliance-состояние.
Пример: `Show compliance state on Jan 14`. Использует SHA-цепочку evidence (уже есть).

**Compliance-as-Code** — YAML-декларации контролей с автоисправлением:
```yaml
control: CC6.1
check: aws.iam.mfa == true
remediation: terraform.apply(mfa_policy)
```

**Vendor Risk Management** — полный pipeline: загрузка SOC2-отчёта вендора → AI-анализ exceptions →
Risk Assessment в Markdown → тикеты в Jira. Покрывает CC9.2 и требования по subprocessors.

---

## Фаза 10 — Chaos Engineering & SOAR ✅ DONE

| Задача | Файл | Статус |
|---|---|---|
| Chaos Compliance Runner (4 сценария, SLA-метрики) | `chaos_runner.py`, `chaos_routes.py` | ✅ |
| Slack Interactive SOAR (Block Kit, revoke IAM, auto-remediate) | `slack_actions_handler.py` | ✅ |
| Slack Actions API (history, stats) | `webhook_routes.py` | ✅ |
| 51 тест для Slack Actions | `tests/test_slack_actions.py` | ✅ |

---

## Бэклог (оставшийся ~8% gap до Vanta)

| Приоритет | Задача | Gap % |
|---|---|---|
| HIGH | Multi-cloud: GCP scanner (Cloud Asset API) | ~2% |
| HIGH | Multi-cloud: Azure scanner (Security Center API) | ~2% |
| MEDIUM | Multi-tenant: несколько организаций в одном инстансе | ~2% |
| MEDIUM | Kubernetes CIS benchmarks (EKS/k8s сканер) | ~1% |
| LOW | Реальный Checkr API (вместо mock) | ~0.5% |
| LOW | SOC2 Type II observation period tracker (6/12 мес.) | ~0.5% |
| LOW | Тесты для audit_runner (mock всех агентов) | — |
| LOW | Webhook-триггер: пересканирование по push в main | — |
