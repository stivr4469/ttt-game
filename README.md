# Sandbox Auditor

Этот проект эмулирует облачную инфраструктуру в LocalStack и сканирует её на соответствие SOC 2, отправляя результаты в Evidence Tracker.

## Порядок запуска

1. **Поднять LocalStack**
   ```bash
   cd sandbox-auditor
   docker compose up -d
   ```

2. **Поднять Evidence Tracker** (если ещё не запущен)
   ```bash
   cd ../evidence-tracker
   docker compose up -d
   cd ../sandbox-auditor
   ```

3. **Установить зависимости**
   ```bash
   pip install -r requirements.txt
   ```

4. **Создать SOC2 Framework и Controls в Evidence Tracker**
   ```bash
   python controls_seed.py
   ```

5. **Создать уязвимую инфраструктуру в LocalStack**
   ```bash
   python seed_infrastructure.py
   ```

6. **Запустить сканер**
   ```bash
   python scanner.py
   ```

## Проверка результатов

- **Evidence Tracker UI**: http://localhost:8000/docs
- **Список доказательств**: GET http://localhost:8000/api/v1/evidence/ (должно быть минимум 4 записи о нарушениях)
- **Статус контролей**: GET http://localhost:8000/api/v1/controls/ (статусы FAIL у CC6.1, CC6.3, CC7.2, CC8.1)
