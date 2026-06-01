# Test Scheduler

Celery Beat планировщик для автоматического запуска тестов по расписанию на основе `TestDefinition.frequency_minutes`.

## Запуск Celery worker

```bash
celery -A celery_app worker --loglevel=info -Q compliance
```

## Запуск Celery Beat (планировщик)

```bash
celery -A beat_schedule beat --loglevel=info
```

Beat при старте читает все enabled `TestDefinition` из БД и строит расписание:
каждый тест запускается каждые `frequency_minutes` минут (минимум 1 минута).

## Переменные окружения

| Переменная             | По умолчанию                  | Описание                                         |
|------------------------|-------------------------------|--------------------------------------------------|
| `CELERY_BROKER_URL`    | `redis://localhost:6379/0`    | URL Redis для Celery broker                      |
| `CELERY_RESULT_BACKEND`| `redis://localhost:6379/0`    | URL Redis для хранения результатов задач         |
| `REDIS_URL`            | `redis://localhost:6379/0`    | Legacy alias (используется если CELERY_* не заданы) |
| `SCHEDULER_JWT_TOKEN`  | _(пусто)_                     | JWT-токен сервисного аккаунта (роль `scanner`)   |
| `API_BASE_URL`         | `http://localhost:8080`       | Базовый URL FastAPI приложения                   |

## Генерация SCHEDULER_JWT_TOKEN

```python
# Запустить один раз из корня проекта:
from auth import create_access_token
token = create_access_token({"sub": "scheduler@system", "role": "scanner"})
print(token)
```

Или через API:
```bash
curl -s -X POST http://localhost:8080/auth/token \
  -d "username=scanner@acme.com&password=scan123" | jq -r .access_token
```

## Ручной запуск теста через API

```
POST /api/v1/tests/{key}/run
Authorization: Cookie access_token=<JWT>
Roles: auditor, admin
```

Ответ (HTTP 202):
```json
{"task_id": "...", "test_key": "my-test", "status": "queued"}
```

## Мониторинг через Flower

```bash
celery -A celery_app flower --port=5555
```

Открыть: http://localhost:5555

## Зависимости

Уже включены в `requirements.txt`:
- `celery==5.3.6`
- `redis==5.0.1`
- `flower==2.0.1`
- `httpx==0.27.2`

## Как работает задача `run_test_definition`

1. Загружает `TestDefinition` из БД по `key`
2. Запускает `ASSERTERS[assertion_type](params, params)` — автономный asserter
3. Отправляет результат через `POST /api/v1/test-results/batch` с JWT-токеном
4. При ошибке сети — retry до 2 раз с задержкой 60 секунд

## Пример: добавить тест с расписанием 60 минут

```bash
curl -X POST http://localhost:8080/api/v1/tests \
  -H "Content-Type: application/json" \
  -b "access_token=$TOKEN" \
  -d '{
    "key": "always-pass-check",
    "title": "Smoke test",
    "producer": "scheduler",
    "assertion_type": "always_pass",
    "params": {},
    "severity": "LOW",
    "frequency_minutes": 60
  }'
```
