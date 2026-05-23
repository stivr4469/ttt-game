# Task Status

## Статус: DONE (Task 30 — Trust Center)

## Что сделано
- Реализован публичный Trust Center по пути `/trust`.
- Создан роутер `trust_routes.py` с эндпоинтами:
    - `GET /trust` — отдача HTML-страницы.
    - `GET /api/trust/snapshot` — публичный JSON со сводкой (SOC 2, ISO 27001, статистика контролей, uptime 99.9%, метрики безопасности).
    - `POST /api/trust/request-access` — NDA-gate для запроса расширенного доступа (генерация UUID токена на 72 часа).
    - `GET /api/trust/details` — расширенный вид со списком всех 33 контролей и их статусами (требует валидный токен).
- Создана фронтенд-страница `ui/trust.html`:
    - Dark theme (фон `#0f1117`, карточки `#1a1d27`, акцент `#00d4aa`).
    - Анимированные счетчики для Controls, Passing и Uptime.
    - Секция Security Practices с чек-листом (MFA, Encryption, Pen Test и т.д.).
    - Модальное окно для запроса доступа к полному отчету.
- Обновлен `ui_server.py`:
    - Подключен `trust_router`.
    - Все эндпоинты Trust Center доступны без авторизации.

## Как проверить
1. Запустить сервер: `python3 ui_server.py`
2. Открыть в браузере: `http://localhost:8080/trust`
3. Проверить API Snapshot: `curl http://localhost:8080/api/trust/snapshot`
4. Проверить запрос доступа:
   ```bash
   curl -X POST http://localhost:8080/api/trust/request-access \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com","company":"Acme","reason":"vendor review"}'
   ```

## Файлы
- `trust_routes.py`
- `ui/trust.html`
- `trust_access_tokens.json` (создается автоматически)
- `ui_server.py` (изменен)

## Task 31 — AI Gap Analysis
## Статус: DONE

## Что сделано
- Реализован `GapAnalysisAgent` для автоматического анализа FAIL-контролей с использованием LLM (OpenRouter/Claude).
- Создан роутер `gap_analysis_routes.py` с эндпоинтами для получения кешированного анализа и принудительного обновления.
- Добавлена визуализация в `ui/index.html`:
    - Список критических несоответствий (gaps) на главной странице Dashboard.
    - Конкретные action items с чекбоксами для исправления каждого контроля.
    - Приоритеты (critical/high/medium) и оценка времени на исправление.
- Реализован механизм кеширования в `gap_analysis_cache.json` для мгновенной загрузки.
- Добавлена поддержка Mock-данных при отсутствии API ключа.

## Как проверить
1. Зайти под Admin в Dashboard.
2. Нажать "Run Analysis" в секции AI Gap Analysis.
3. Дождаться завершения и увидеть список рекомендаций.

## Task 32 — Webhook Real-time Triggers
## Статус: DONE

## Что сделано
- Реализованы webhook эндпоинты для GitHub, Okta и Slack в `webhook_routes.py`.
- Настроена асинхронная обработка событий через Celery:
    - События GitHub (push, PR, security alerts) триггерят пересканирование соответствующих контролей (CC8.1, CC5.3 и т.д.).
    - События Okta (lifecycle, auth, mfa) триггерят пересканирование контролей доступа (CC6.1, CC6.2).
- Реализована верификация подписей GitHub HMAC-SHA256.
- Добавлено логирование событий в `webhook_events.json` с ротацией (последние 100).
- В UI добавлена панель "⚡ Webhook Activity" в sidebar для real-time мониторинга входящих событий.
- Эндпоинты интегрированы в `ui_server.py`.

## Как проверить
1. Симулировать GitHub webhook:
   ```bash
   curl -X POST http://localhost:8080/webhooks/github \
     -H "X-GitHub-Event: push" \
     -H "Content-Type: application/json" \
     -d '{"repository":{"name":"compliance-sandbox"},"pusher":{"name":"test"}}'
   ```
2. Проверить появление события в UI (sidebar слева).
3. Проверить Celery лог — там должен запуститься соответствующий агент.

## Task 33 — Employee Security Training LMS
## Статус: DONE

## Что сделано
- Реализована полноценная система обучения (LMS) для сотрудников в `training_agent.py`.
- Встроено 5 курсов с вопросами: Acceptable Use Policy, Password & MFA, Phishing Awareness, GDPR, Incident Response.
- Создан роутер `training_routes.py` с эндпоинтами для прохождения тестов, получения сертификатов и отчетов.
- Разработан фронтенд `ui/training.html`:
    - Карточки курсов со статусами.
    - Интерактивный интерфейс прохождения тестов.
    - Генерация ID сертификатов при успешной сдаче.
    - Compliance Report для администраторов (прогресс всей команды).
- Интегрирован сбор доказательств в `audit_runner.py` для контроля CC1.4 (Training).
- Добавлена функция отправки Slack-напоминаний сотрудникам о незавершенных курсах.
- Добавлена ссылка на обучение в основной Dashboard.

## Как проверить
1. Открыть `http://localhost:8080/training`.
2. Пройти любой курс (например, AUP) — нужно набрать >= 80% (4 из 5 вопросов).
3. Проверить появление сертификата.
4. Зайти под Admin и увидеть общий отчет по команде внизу страницы.
5. Запустить `python3 audit_runner.py` и убедиться, что CC1.4 оценивается на основе реальных данных LMS.

## Task 34 — Risk Register
## Статус: DONE

## Что сделано
- Реализован модуль `RiskRegister` для управления рисками организации.
- Добавлена автоматическая генерация рисков из FAIL-контролей (с маппингом на категории: access_control, operational, data_protection и т.д.).
- Создан роутер `risk_routes.py` с CRUD операциями и эндпоинтом для синхронизации.
- Разработан фронтенд `ui/risk-register.html`:
    - Summary карточки (Critical, High, Medium, Low).
    - Интерактивная тепловая матрица рисков 5x5 (Likelihood vs Impact).
    - Таблица рисков с цветовой индикацией и фильтрацией по статусу.
    - Модальное окно для создания, редактирования и удаления рисков.
- Интегрирована автоматическая синхронизация рисков в `audit_runner.py`.
- Добавлена ссылка на Risk Register в основной Dashboard.

## Как проверить
1. Открыть `http://localhost:8080/risk-register`.
2. Нажать "Sync from Controls" для автоматического наполнения реестра на основе текущих проваленных проверок.
3. Проверить отображение рисков на матрице (точки в ячейках).
4. Создать ручной риск через "+ Add Manual Risk" и убедиться, что Risk Score (Likelihood x Impact) рассчитывается корректно.

## Task 35 — Vulnerability Management
## Статус: DONE

## Что сделано
- Реализован `VulnAgent` для мониторинга уязвимостей через GitHub Dependabot API.
- Добавлен расчет SLA для каждой уязвимости на основе её критичности (Critical: 24h, High: 7d, Medium: 30d).
- Реализованы статусы SLA: `on_track`, `at_risk` (осталось < 20% времени) и `breached`.
- Создан роутер `vuln_routes.py` для управления списком уязвимостей и запуска сканирования.
- Разработан фронтенд `ui/vulnerabilities.html`:
    - SLA Dashboard с карточками (Breached, At Risk, On Track).
    - Таблица уязвимостей с цветовой кодировкой по severity.
    - Анимация (мигание) для просроченных (breached) уязвимостей.
    - Модальное окно с деталями и шагами по исправлению (remediation).
- Интегрирован сбор доказательств в `audit_runner.py` для контролей CC6.8 (Anti-Malware) и CC7.3 (Security Events).
- Добавлена поддержка Mock-данных при отсутствии GITHUB_TOKEN.
- Добавлена ссылка на Vulnerability Management в основной Dashboard.

## Как проверить
1. Открыть `http://localhost:8080/vulnerabilities`.
2. Нажать "Run Vulnerability Scan" для получения списка алертов из GitHub (или mock-данных).
3. Убедиться, что уязвимости распределены по статусам SLA.
4. Нажать "View" на любой уязвимости и проверить план исправления.

## Task 36 — Security Questionnaire Automation
## Статус: DONE

## Что сделано
- Реализован `QuestionnaireAgent` для автоматического заполнения анкет безопасности с помощью LLM (Claude-3).
- Встроены шаблоны анкет: SIG Lite (20 вопросов) и CAIQ Lite (15 вопросов).
- Реализована логика RAG (Retrieval-Augmented Generation): агент читает все политики в `policies/*.md` и использует их как контекст для ответов.
- Создан роутер `questionnaire_routes.py` для управления шаблонами и генерацией ответов.
- Разработан фронтенд `ui/questionnaires.html`:
    - Карточки доступных шаблонов.
    - Интерактивный процесс генерации с отображением прогресса.
    - История сгенерированных ответов с оценкой уверенности AI (Confidence Score).
    - Детальный просмотр ответов с подсветкой вопросов, требующих ручной проверки.
    - Функция экспорта заполненной анкеты в текстовый формат (.txt).
- Добавлена поддержка Mock-ответов при отсутствии API ключа.
- Добавлена ссылка на Questionnaires в основной Dashboard.

## Как проверить
1. Открыть `http://localhost:8080/questionnaires`.
2. Нажать "Generate Response" на карточке SIG Lite.
3. Ввести данные запрашивающей стороны (Company, Email) и запустить процесс.
4. Дождаться завершения (1-3 мин при наличии API ключа) и просмотреть результат.
5. Нажать "Download TXT" для получения готового файла для отправки клиенту.

## Task 37 — Customizable Controls
## Статус: DONE

## Что сделано
- Реализован `CustomControlsManager` для управления дополнительными комлпаенс-контролями (GDPR, HIPAA, PCI и др.).
- Добавлена поддержка шаблонов для быстрого создания стандартных кастомных контролей (например, GDPR Article 13, PCI 3.4).
- Создан роутер `custom_controls_routes.py` с поддержкой CRUD и обновлением статусов.
- Реализован эндпоинт `/api/custom-controls/all` для получения объединенного списка всех контролей (SOC 2 + Custom).
- Обновлен фронтенд `ui/index.html`:
    - Добавлены вкладки фильтрации по фреймворкам (SOC 2, GDPR, HIPAA, Custom).
    - Реализовано отображение кастомных контролей в общем списке с пометкой `[Custom]`.
    - Добавлена кнопка "+ Add Custom Control" для администраторов.
- Интегрирована поддержка ручного обновления статуса и добавления заметок для кастомных проверок.

## Как проверить
1. Открыть `http://localhost:8080/`.
2. Перейти в раздел "Controls".
3. Переключаться между фреймворками (например, нажать на "🇪🇺 GDPR").
4. Создать кастомный контроль из шаблона или вручную через API:
   ```bash
   curl -X POST http://localhost:8080/api/custom-controls/from-template/gdpr_13 \
     -H "Authorization: Bearer <admin_token>"
   ```
5. Убедиться, что новый контроль появился в списке и его статус можно менять.
