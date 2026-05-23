#!/usr/bin/env python3
"""
audit_runner.py — "Одна кнопка" SOC 2 Audit Simulation
Запускает все агенты, оценивает контроли, генерирует политики,
создаёт remediation-тикеты, отправляет на подпись и выводит финальный отчёт.

Использование:
    python3 audit_runner.py [--skip-policy] [--skip-remediation] [--skip-esign] [--parallel]
"""

import argparse
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Optional

import requests
from dotenv import load_dotenv

# Загружаем .env в самом начале
load_dotenv()

# ── Константы ────────────────────────────────────────────────────────────────
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
EVIDENCE_API_KEY     = os.getenv("EVIDENCE_API_KEY", "soc2-dev-key")
CONTROLS_MAP_FILE    = "controls_map.json"

# Ширина блока отчёта
REPORT_WIDTH = 62


# ── Вспомогательные утилиты ──────────────────────────────────────────────────

def _bar(filled: int, total: int, width: int = 22) -> str:
    """Строит текстовый прогресс-бар из символов █ и ░."""
    if total == 0:
        filled_w = 0
    else:
        filled_w = round(filled / total * width)
    return "█" * filled_w + "░" * (width - filled_w)


def _pct(part: int, total: int) -> str:
    """Форматирует процент или возвращает «0.0%»."""
    if total == 0:
        return "0.0%"
    return f"{part / total * 100:.1f}%"


def _api_headers() -> dict:
    """Возвращает заголовки для Evidence Tracker API."""
    return {"X-API-Key": EVIDENCE_API_KEY}


def _load_controls_map() -> dict:
    """Загружает controls_map.json; возвращает пустой dict если файл не найден."""
    if not os.path.exists(CONTROLS_MAP_FILE):
        return {}
    with open(CONTROLS_MAP_FILE) as f:
        return json.load(f)


# ── Параллельный запуск агентов ──────────────────────────────────────────────

def _run_agent_task(name: str, func, *args) -> dict:
    """
    Обёртка для запуска одного агента в отдельном потоке.
    Замеряет время выполнения и ловит исключения.
    Возвращает dict с полями: name, elapsed, error (None если успех), _raw.
    """
    t0 = time.time()
    try:
        result = func(*args)
        elapsed = time.time() - t0
        return {"name": name, "elapsed": elapsed, "error": None, "_raw": result}
    except Exception as exc:
        elapsed = time.time() - t0
        return {"name": name, "elapsed": elapsed, "error": str(exc), "_raw": None}


def run_phase_parallel(tasks: list) -> dict:
    """
    Запускает агентов параллельно через ThreadPoolExecutor.

    tasks = [(имя_для_логов, callable, args_tuple), ...]

    Потокобезопасность: каждый агент пишет в отдельные таблицы evidence
    (scanner -> AWS/Okta-контроли, github_agent -> CC4.2/CC5.3/...,
    mdm_agent -> CC6.6/CC6.8, hr_agent -> CC6.2/CC9.2/CC1.4),
    поэтому конкурентных записей в одну строку БД не возникает.

    Если агент упал — остальные продолжают работу; ошибка фиксируется в results.

    Возвращает dict {имя_агента: task_result_dict}.
    """
    # Замок для безопасного вывода в stdout из разных потоков
    print_lock = threading.Lock()

    results_map: dict = {}

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(_run_agent_task, name, func, *args): name
            for name, func, args in tasks
        }

        for future in as_completed(futures):
            agent_name = futures[future]
            try:
                task_result = future.result(timeout=300)
            except Exception as exc:
                # Timeout или другая ошибка на уровне future
                task_result = {
                    "name": agent_name,
                    "elapsed": 0.0,
                    "error": f"Future error: {exc}",
                    "_raw": None,
                }

            with print_lock:
                if task_result["error"]:
                    print(f"  [{agent_name}] ERROR: {task_result['error']}")
                else:
                    print(f"  [{agent_name}] done [{task_result['elapsed']:.1f}s]")

            results_map[agent_name] = task_result

    return results_map


# ── Phase 1: Evidence Collection ─────────────────────────────────────────────

def collect_evidence(controls_map: dict, parallel: bool = False) -> list:
    """
    Запускает все агенты сбора доказательств.

    При parallel=True — агенты 1-4 (Scanner, GitHub, MDM, HR) запускаются
    одновременно через ThreadPoolExecutor(max_workers=4).
    Агенты 5-6 (Training, Vulnerabilities) запускаются последовательно после
    параллельного блока — они не имеют смысла параллелить с первыми четырьмя.

    При parallel=False — все 6 агентов запускаются последовательно
    (исходное поведение, не изменено).

    Каждый агент может упасть — ловим исключения и продолжаем.
    Возвращает список dict с полями: name, items, elapsed, error.
    """
    results = []

    if parallel:
        # ── Параллельный режим: агенты 1-4 ─────────────────────────────────
        print("  Режим: parallel (4 потока) — Scanner, GitHub, MDM, HR")

        # Импортируем callable в основном потоке до запуска пула,
        # чтобы избежать возможных race condition при первом импорте модуля.
        from scanner import main as _run_scanner
        from github_agent import main as _run_github
        from hr_agent import main as _run_hr

        # MDM использует класс — оборачиваем в функцию с той же сигнатурой
        def _run_mdm(cm: dict) -> dict:
            from mdm_agent import MDMAgent
            agent = MDMAgent(EVIDENCE_TRACKER_URL, cm)
            mdm_result = agent.run_checks()
            agent._save_evidence(mdm_result, cm)
            return mdm_result

        # tasks = [(имя_для_логов, callable, args_tuple)]
        parallel_tasks = [
            ("AWS+Okta", _run_scanner, (controls_map,)),
            ("GitHub",   _run_github,  (controls_map,)),
            ("MDM",      _run_mdm,     (controls_map,)),
            ("HR",       _run_hr,      (controls_map,)),
        ]

        parallel_results = run_phase_parallel(parallel_tasks)

        # Считаем суммарный items после завершения всего параллельного блока
        items_after_parallel = _count_all_evidence()

        # Формируем results в стандартном формате
        for name, _func, _args in parallel_tasks:
            r = parallel_results.get(name, {})
            if name == "MDM" and r.get("_raw") is not None:
                # MDM возвращает dict с total_devices
                items = r["_raw"].get("total_devices", 0)
            else:
                # Для остальных агентов — общий счётчик evidence после блока
                items = items_after_parallel
            results.append({
                "name":    name,
                "items":   items,
                "elapsed": r.get("elapsed", 0.0),
                "error":   r.get("error"),
            })

        # ── Агенты 5-6 — sequential после параллельного блока ───────────────

        # --- Training Agent ---
        print(f"[5/6] Training agent...", end=" ", flush=True)
        t0 = time.time()
        try:
            from training_agent import TrainingAgent
            training_agent = TrainingAgent()
            training_agent.collect_evidence(controls_map=controls_map)
            elapsed = time.time() - t0
            items = _count_all_evidence()
            results.append({"name": "Training", "items": items, "elapsed": elapsed, "error": None})
            print(f"done [{elapsed:.1f}s]")
        except Exception as exc:
            elapsed = time.time() - t0
            results.append({"name": "Training", "items": 0, "elapsed": elapsed, "error": str(exc)})
            print(f"ERROR: {exc}")

        # --- Vulnerability Agent ---
        print(f"[6/6] Vulnerability agent...", end=" ", flush=True)
        t0 = time.time()
        try:
            from vuln_agent import VulnAgent
            vuln_agent = VulnAgent()
            vuln_result = vuln_agent.run(controls_map=controls_map)
            elapsed = time.time() - t0
            items = vuln_result.get("total", 0)
            results.append({"name": "Vulnerabilities", "items": items, "elapsed": elapsed, "error": None})
            print(f"done ({items} vulns) [{elapsed:.1f}s]")
        except Exception as exc:
            elapsed = time.time() - t0
            results.append({"name": "Vulnerabilities", "items": 0, "elapsed": elapsed, "error": str(exc)})
            print(f"ERROR: {exc}")

        return results

    # ── Sequential режим (исходный код без изменений) ───────────────────────

    # scanner.py покрывает AWS + Okta (нет отдельных aws_agent.py / okta_agent.py)
    # github_agent.py — отдельный агент для GitHub
    # mdm_agent.py   — MDM устройства
    # hr_agent.py    — HR-аудит (дополнительно)

    # --- Scanner (AWS + Okta) ---
    print(f"[1/6] Scanner (AWS+Okta)...", end=" ", flush=True)
    t0 = time.time()
    try:
        from scanner import main as run_scanner
        run_scanner(controls_map=controls_map)
        elapsed = time.time() - t0
        # Количество items — считаем evidence из API после запуска
        items = _count_all_evidence()
        results.append({"name": "AWS+Okta", "items": items, "elapsed": elapsed, "error": None})
        print(f"done ({items} items) [{elapsed:.1f}s]")
    except Exception as exc:
        elapsed = time.time() - t0
        results.append({"name": "AWS+Okta", "items": 0, "elapsed": elapsed, "error": str(exc)})
        print(f"ERROR: {exc}")

    # --- GitHub Agent ---
    print(f"[2/6] GitHub agent...", end=" ", flush=True)
    t0 = time.time()
    try:
        from github_agent import main as run_github
        run_github(controls_map=controls_map)
        elapsed = time.time() - t0
        items = _count_all_evidence()
        results.append({"name": "GitHub", "items": items, "elapsed": elapsed, "error": None})
        print(f"done ({items} items) [{elapsed:.1f}s]")
    except Exception as exc:
        elapsed = time.time() - t0
        results.append({"name": "GitHub", "items": 0, "elapsed": elapsed, "error": str(exc)})
        print(f"ERROR: {exc}")

    # --- MDM Agent ---
    print(f"[3/6] MDM agent...", end=" ", flush=True)
    t0 = time.time()
    try:
        from mdm_agent import MDMAgent
        agent = MDMAgent(EVIDENCE_TRACKER_URL, controls_map)
        results_mdm = agent.run_checks()
        agent._save_evidence(results_mdm, controls_map)
        elapsed = time.time() - t0
        items = results_mdm.get("total_devices", 0)
        results.append({"name": "MDM", "items": items, "elapsed": elapsed, "error": None})
        print(f"done ({items} items) [{elapsed:.1f}s]")
    except Exception as exc:
        elapsed = time.time() - t0
        results.append({"name": "MDM", "items": 0, "elapsed": elapsed, "error": str(exc)})
        print(f"ERROR: {exc}")

    # --- HR Agent ---
    print(f"[4/6] HR agent...", end=" ", flush=True)
    t0 = time.time()
    try:
        from hr_agent import main as run_hr
        run_hr(controls_map=controls_map)
        elapsed = time.time() - t0
        items = _count_all_evidence()
        results.append({"name": "HR", "items": items, "elapsed": elapsed, "error": None})
        print(f"done ({items} items) [{elapsed:.1f}s]")
    except Exception as exc:
        elapsed = time.time() - t0
        results.append({"name": "HR", "items": 0, "elapsed": elapsed, "error": str(exc)})
        print(f"ERROR: {exc}")

    # --- Training Agent ---
    print(f"[5/6] Training agent...", end=" ", flush=True)
    t0 = time.time()
    try:
        from training_agent import TrainingAgent
        training_agent = TrainingAgent()
        training_agent.collect_evidence(controls_map=controls_map)
        elapsed = time.time() - t0
        items = _count_all_evidence()
        results.append({"name": "Training", "items": items, "elapsed": elapsed, "error": None})
        print(f"done [{elapsed:.1f}s]")
    except Exception as exc:
        elapsed = time.time() - t0
        results.append({"name": "Training", "items": 0, "elapsed": elapsed, "error": str(exc)})
        print(f"ERROR: {exc}")

    # --- Vulnerability Agent ---
    print(f"[6/6] Vulnerability agent...", end=" ", flush=True)
    t0 = time.time()
    try:
        from vuln_agent import VulnAgent
        vuln_agent = VulnAgent()
        vuln_result = vuln_agent.run(controls_map=controls_map)
        elapsed = time.time() - t0
        items = vuln_result.get("total", 0)
        results.append({"name": "Vulnerabilities", "items": items, "elapsed": elapsed, "error": None})
        print(f"done ({items} vulns) [{elapsed:.1f}s]")
    except Exception as exc:
        elapsed = time.time() - t0
        results.append({"name": "Vulnerabilities", "items": 0, "elapsed": elapsed, "error": str(exc)})
        print(f"ERROR: {exc}")

    return results


def _count_all_evidence() -> int:
    """Возвращает текущее общее количество evidence записей в трекере."""
    try:
        resp = requests.get(
            f"{EVIDENCE_TRACKER_URL}/api/v1/evidence/?limit=2000",
            headers=_api_headers(),
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                return data.get("total", len(data.get("items", [])))
        return 0
    except Exception:
        return 0


# ── Phase 2: Control Assessment ──────────────────────────────────────────────

def assess_controls() -> dict:
    """
    Получает список контролей из Evidence Tracker.
    Возвращает dict с полями: total, pass_count, fail_count, pending_count,
    controls (список dict), top_failures (список dict).
    """
    try:
        resp = requests.get(
            f"{EVIDENCE_TRACKER_URL}/api/v1/controls/?limit=100",
            headers=_api_headers(),
            timeout=10,
        )
        resp.raise_for_status()
        controls = resp.json()
    except Exception as exc:
        print(f"  [WARN] Не удалось получить контроли: {exc}")
        return {
            "total": 0,
            "pass_count": 0,
            "fail_count": 0,
            "pending_count": 0,
            "controls": [],
            "top_failures": [],
        }

    pass_count    = sum(1 for c in controls if str(c.get("status", "")).upper() == "PASS")
    fail_count    = sum(1 for c in controls if str(c.get("status", "")).upper() == "FAIL")
    pending_count = sum(1 for c in controls if str(c.get("status", "")).upper() not in ("PASS", "FAIL"))

    # Топ FAIL контролей — берём первые 5
    fail_controls = [c for c in controls if str(c.get("status", "")).upper() == "FAIL"]

    # Определяем severity для каждого FAIL-контроля по коду
    severity_map = {
        "CC6.1": "CRITICAL", "CC6.2": "HIGH", "CC6.3": "HIGH",
        "CC6.7": "HIGH",     "CC7.1": "HIGH", "CC7.2": "HIGH",
        "CC8.1": "HIGH",     "CC3.4": "MEDIUM",
    }
    for ctrl in fail_controls:
        ctrl["_severity"] = severity_map.get(ctrl.get("code", ""), "MEDIUM")

    # Сортируем: CRITICAL -> HIGH -> MEDIUM
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    top_failures = sorted(fail_controls, key=lambda c: order.get(c["_severity"], 9))[:5]

    return {
        "total":         len(controls),
        "pass_count":    pass_count,
        "fail_count":    fail_count,
        "pending_count": pending_count,
        "controls":      controls,
        "top_failures":  top_failures,
    }


# ── Phase 3: Policy Drafts ───────────────────────────────────────────────────

_OLLAMA_BASE_URL = os.getenv("OLLAMA_URL", "http://192.168.88.26:11434")


def generate_policies(controls_map: dict, use_ollama: bool = False, ollama_model: str = "qwen2.5:7b") -> dict:
    """
    Проверяет какие governance-контроли не имеют AI_GENERATED evidence.
    Генерирует недостающие через PolicyAgent(use_anthropic=True) — Anthropic Haiku API.
    Возвращает dict: generated (int), skipped (int), total (int), errors (list).
    """
    from policy_agent import PolicyAgent, GOVERNANCE_CONTROLS, POLICY_CONTROLS

    # Получаем уже существующие AI_GENERATED evidence
    ai_covered: set = set()
    try:
        resp = requests.get(
            f"{EVIDENCE_TRACKER_URL}/api/v1/evidence/?limit=200",
            headers=_api_headers(),
            timeout=10,
        )
        if resp.status_code == 200:
            evidence_list = resp.json()
            ai_items = [e for e in evidence_list if e.get("source") == "AI_GENERATED"]
            # Сопоставляем control_id с кодом контроля
            code_by_id = {v: k for k, v in controls_map.items()}
            for item in ai_items:
                ctrl_id = str(item.get("control_id", ""))
                code = code_by_id.get(ctrl_id)
                if code:
                    ai_covered.add(code)
    except Exception as exc:
        print(f"  [WARN] Не удалось проверить существующие AI evidence: {exc}")

    # Контроли, которые нужно сгенерировать
    needed = [code for code in GOVERNANCE_CONTROLS if code not in ai_covered and code in POLICY_CONTROLS]

    total     = len(GOVERNANCE_CONTROLS)
    generated = 0
    errors: list = []

    if not needed:
        print(f"  [AI] Все {total} governance-контролей уже имеют AI_GENERATED evidence")
        return {"generated": 0, "skipped": total, "total": total, "errors": []}

    # Инициализируем агент: Ollama (локально) или Anthropic API
    if use_ollama:
        agent = PolicyAgent(model=ollama_model, use_ollama=True)
        print(f"  [AI] Бэкенд: Ollama ({ollama_model}) @ {_OLLAMA_BASE_URL}")
    else:
        _ant_key = os.getenv("ANTHROPIC_API_KEY", "")
        _model   = os.getenv("POLICY_MODEL", "claude-haiku-4-5-20251001")
        agent    = PolicyAgent(api_key=_ant_key, model=_model, use_anthropic=True)
        print(f"  [AI] Бэкенд: Anthropic API ({_model})")
    evidence_creds = None
    try:
        from evidence_client import EvidenceClient
        evidence_creds = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="policy_agent")
    except Exception as exc:
        errors.append(f"EvidenceClient init: {exc}")

    env_context = agent.collect_environment_context()

    # Менеджер жизненного цикла политик (SoD: AI создаёт черновик, human approves)
    from policy_lifecycle import PolicyLifecycleManager
    _plm = PolicyLifecycleManager()

    for code in needed:
        info = POLICY_CONTROLS[code]
        print(f"  [AI] {code} генерируем...", end=" ", flush=True)
        try:
            policy_text = agent.generate_policy(code, info, env_context)
            if evidence_creds and code in controls_map:
                content = json.dumps({
                    "policy_title": info["title"],
                    "control":      code,
                    "generated_by": getattr(agent, "model", "policy_agent"),
                    "status":       "draft:pending_human_approval",
                    "policy_text":  policy_text,
                })
                evidence_creds.create_evidence(
                    control_id=controls_map[code],
                    title=f"[AI Draft] {info['title']}",
                    content=content,
                    source="AI_GENERATED",
                )
                # SoD: НЕ ставим PASS автоматически — статус контроля обновится
                # только после human approve через /api/policy-lifecycle/{id}/approve
                _plm.create_draft(
                    control_id=controls_map.get(code, code),
                    control_code=code,
                    title=info["title"],
                    content=policy_text,
                    created_by=f"ai:{getattr(agent, 'model', 'policy_agent')}",
                )
            generated += 1
            print("OK")
        except Exception as exc:
            errors.append(f"{code}: {exc}")
            print(f"ERROR: {exc}")

    return {"generated": generated, "skipped": total - len(needed), "total": total, "errors": errors}


# ── Phase 4: Remediation Tickets ─────────────────────────────────────────────

def create_tickets(controls_assessment: dict) -> dict:
    """
    Создаёт Jira-тикеты для всех FAIL-контролей.
    Возвращает dict: created (int), tickets (list[dict]), errors (list[str]).
    """
    from remediation_agent import RemediationAgent

    fail_controls = [c for c in controls_assessment.get("controls", [])
                     if str(c.get("status", "")).upper() == "FAIL"]

    agent   = RemediationAgent()
    created = 0
    tickets: list = []
    errors: list  = []

    for ctrl in fail_controls:
        code    = ctrl.get("code", "UNKNOWN")
        finding = ctrl.get("title", f"{code} control failed")
        try:
            record = agent.create_remediation_ticket(code, finding)
            key    = record.get("jira_key", "?")
            mock   = record.get("mock", False)
            suffix = " (mock)" if mock else ""
            print(f"  [JIRA] {key}{suffix} создан для {code}")
            tickets.append(record)
            created += 1
        except Exception as exc:
            errors.append(f"{code}: {exc}")
            print(f"  [JIRA] ERROR для {code}: {exc}")

    return {"created": created, "tickets": tickets, "errors": errors}


# ── Phase 5: E-Signature ─────────────────────────────────────────────────────

def request_signature(controls_map: dict) -> dict:
    """
    Отправляет пакет SOC 2 политик на подпись CISO.
    Возвращает dict: envelope_id (str | None), url (str), errors (list[str]).
    """
    from esignature_agent import ESignatureAgent, SIGNATURE_REQUIRED_CONTROLS

    agent  = ESignatureAgent()
    errors: list = []

    # Отправляем первый контроль из SIGNATURE_REQUIRED_CONTROLS
    # (send_all_policies создаёт по одному envelope на каждый контроль)
    # Для единого "пакета" достаточно одного envelope
    signer_email = os.getenv("CISO_EMAIL", "ciso@marineso.com")
    signer_name  = os.getenv("CISO_NAME", "Chief Information Security Officer")

    # Ищем первый подходящий контроль из requirements
    first_code = next(iter(SIGNATURE_REQUIRED_CONTROLS), None)
    if first_code is None or first_code not in controls_map:
        return {"envelope_id": None, "url": "", "errors": ["Нет доступных контролей для подписи"]}

    try:
        result = agent.create_signature_request(
            control_code=first_code,
            policy_title="SOC2 Audit Package",
            signer_email=signer_email,
            signer_name=signer_name,
        )
        envelope_id = result.get("envelope_id")
        url         = result.get("signature_url", "")
        print(f"  [ESIGN] envelope {envelope_id[:16]}... отправлен на {signer_email}")
        return {"envelope_id": envelope_id, "url": url, "errors": []}
    except Exception as exc:
        errors.append(str(exc))
        print(f"  [ESIGN] ERROR: {exc}")
        return {"envelope_id": None, "url": "", "errors": errors}


# ── Phase 6: Final Report ─────────────────────────────────────────────────────

def print_report(
    start_time:   float,
    evidence_res: list,
    ctrl_res:     dict,
    policy_res:   Optional[dict],
    ticket_res:   Optional[dict],
    esign_res:    Optional[dict],
    phase_errors: list,
    run_mode:     str = "sequential",
) -> None:
    """Выводит финальный отчёт в виде ASCII-блока."""

    total_elapsed = time.time() - start_time
    now_str       = datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M:%S")
    company       = os.getenv("COMPANY_NAME", "MARINESO")

    # Заголовок
    title_line  = f"{company} — SOC 2 AUDIT SIMULATION REPORT"
    print()
    print("╔" + "═" * REPORT_WIDTH + "╗")
    print("║" + title_line.center(REPORT_WIDTH) + "║")
    print("║" + now_str.center(REPORT_WIDTH) + "║")
    print("╚" + "═" * REPORT_WIDTH + "╝")

    # ── Evidence Collection ──
    print()
    print("EVIDENCE COLLECTION")
    for ag in evidence_res:
        status  = "✓" if ag["error"] is None else "✗"
        name    = ag["name"]
        items   = ag["items"]
        elapsed = ag["elapsed"]
        err_sfx = f"  ERROR: {ag['error']}" if ag["error"] else ""
        print(f"  {name:<14} {status}  {items:>3} items   {elapsed:>5.1f}s{err_sfx}")

    # ── Control Status ──
    total   = ctrl_res["total"]
    p_cnt   = ctrl_res["pass_count"]
    f_cnt   = ctrl_res["fail_count"]
    pnd_cnt = ctrl_res["pending_count"]

    print()
    print(f"CONTROL STATUS ({total} total)")
    if total > 0:
        print(f"  PASS    {_bar(p_cnt,   total):<24} {p_cnt:>3}  ({_pct(p_cnt, total)})")
        print(f"  FAIL    {_bar(f_cnt,   total):<24} {f_cnt:>3}  ({_pct(f_cnt, total)})")
        print(f"  PENDING {_bar(pnd_cnt, total):<24} {pnd_cnt:>3}  ({_pct(pnd_cnt, total)})")
    else:
        print("  (нет данных — Evidence Tracker недоступен)")

    # ── Top Failures ──
    top = ctrl_res.get("top_failures", [])
    if top:
        print()
        print("TOP FAILURES")
        for ctrl in top:
            code  = ctrl.get("code", "?")
            title = ctrl.get("title", "")[:40]
            sev   = ctrl.get("_severity", "?")
            print(f"  {code:<7} {title:<42} {sev}")

    # ── Policies ──
    if policy_res is not None:
        gen   = policy_res.get("generated", 0)
        tot_p = policy_res.get("total", 0)
        print()
        print(f"POLICIES GENERATED    {gen} / {tot_p} governance controls")

    # ── Remediation Tickets ──
    if ticket_res is not None:
        crt = ticket_res.get("created", 0)
        print(f"REMEDIATION TICKETS   {crt} created")

    # ── E-Signature ──
    if esign_res is not None:
        env_id = esign_res.get("envelope_id") or "—"
        short  = env_id[:16] + "..." if len(env_id) > 16 else env_id
        print(f"E-SIGNATURE           envelope {short} sent")

    # ── Overall Readiness ──
    print()
    readiness_pct = round(p_cnt / total * 100) if total > 0 else 0
    readiness_bar = _bar(readiness_pct, 100, width=16)
    print(f"OVERALL READINESS     {readiness_bar}  {readiness_pct}%")

    # Вердикт
    if f_cnt == 0 and total > 0:
        verdict = "READY — все контроли PASS"
        icon    = "✓"
    elif f_cnt > 0:
        verdict = f"NOT READY — {f_cnt} control(s) require remediation"
        icon    = "⚠"
    else:
        verdict = "UNKNOWN — нет данных"
        icon    = "?"

    print(f"AUDIT VERDICT         {icon}  {verdict}")

    # ── Phase Errors ──
    if phase_errors:
        print()
        print("PHASE ERRORS")
        for err in phase_errors:
            print(f"  ! {err}")

    # Итого время и режим запуска
    print()
    print(f"Mode: {run_mode}")
    print(f"Duration: {total_elapsed:.1f}s")
    print()


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    """Точка входа: разбирает аргументы, запускает все фазы, выводит отчёт."""

    parser = argparse.ArgumentParser(
        description="SOC 2 Audit Simulation — одна кнопка"
    )
    parser.add_argument("--skip-policy",      action="store_true", help="Пропустить фазу генерации политик")
    parser.add_argument("--skip-remediation", action="store_true", help="Пропустить фазу создания тикетов")
    parser.add_argument("--skip-esign",       action="store_true", help="Пропустить фазу e-подписи")
    parser.add_argument(
        "--parallel",
        action="store_true",
        help=(
            "Запускать агентов Phase 1 (Scanner, GitHub, MDM, HR) параллельно "
            "через ThreadPoolExecutor(max_workers=4). "
            "Training и Vuln запускаются sequential после параллельного блока. "
            "Ожидаемый прирост скорости: ~3x по сравнению с sequential."
        ),
    )
    parser.add_argument(
        "--anthropic-key",
        type=str,
        default="",
        help="Anthropic API key для генерации политик (или задай ANTHROPIC_API_KEY в .env)",
    )
    parser.add_argument(
        "--ollama",
        action="store_true",
        help="Использовать локальный Ollama (qwen2.5:7b) вместо Anthropic API",
    )
    parser.add_argument(
        "--ollama-model",
        type=str,
        default="qwen2.5:7b",
        help="Модель Ollama (default: qwen2.5:7b)",
    )
    args = parser.parse_args()

    # Ключ из флага перекрывает .env
    if args.anthropic_key:
        os.environ["ANTHROPIC_API_KEY"] = args.anthropic_key

    start_time   = time.time()
    phase_errors: list = []

    # Загружаем controls_map.json
    controls_map = _load_controls_map()
    if not controls_map:
        print(f"[WARN] {CONTROLS_MAP_FILE} не найден — некоторые агенты могут не работать")

    # ── Phase 1: Evidence Collection ──
    print("\n" + "=" * 60)
    mode_label = "parallel (4 threads)" if args.parallel else "sequential"
    print(f" PHASE 1: EVIDENCE COLLECTION  [{mode_label}]")
    print("=" * 60)
    t_phase = time.time()
    evidence_results = collect_evidence(controls_map, parallel=args.parallel)
    phase1_elapsed = time.time() - t_phase
    print(f"  Фаза завершена за {phase1_elapsed:.1f}s  [Mode: {mode_label}]")

    # Добавляем ошибки агентов в общий лог
    for ag in evidence_results:
        if ag["error"]:
            phase_errors.append(f"[Evidence/{ag['name']}] {ag['error']}")

    # ── Phase 2: Control Assessment ──
    print("\n" + "=" * 60)
    print(" PHASE 2: CONTROL ASSESSMENT")
    print("=" * 60)
    t_phase = time.time()
    ctrl_results = assess_controls()

    # Синхронизация Risk Register
    try:
        from risk_register import RiskRegister
        rr = RiskRegister()
        sync_result = rr.sync_from_controls(ctrl_results.get("controls", []))
        print(f"  Risk Register: {sync_result['created']} created, {sync_result['updated']} updated")
    except Exception as e:
        print(f"  [WARN] Failed to sync Risk Register: {e}")

    print(
        f"  Итог: {ctrl_results['total']} контролей — "
        f"PASS={ctrl_results['pass_count']} "
        f"FAIL={ctrl_results['fail_count']} "
        f"PENDING={ctrl_results['pending_count']} "
        f"[{time.time() - t_phase:.1f}s]"
    )

    # ── Phase 3: Policy Drafts ──
    policy_results: Optional[dict] = None
    if not args.skip_policy:
        print("\n" + "=" * 60)
        print(" PHASE 3: POLICY GENERATION")
        print("=" * 60)
        t_phase = time.time()
        try:
            policy_results = generate_policies(
                controls_map,
                use_ollama=args.ollama,
                ollama_model=args.ollama_model,
            )
            for err in policy_results.get("errors", []):
                phase_errors.append(f"[Policy] {err}")
            print(f"  Сгенерировано {policy_results['generated']} из {policy_results['total']} [{time.time() - t_phase:.1f}s]")
        except Exception as exc:
            phase_errors.append(f"[Policy] {exc}")
            print(f"  ERROR: {exc}")
            policy_results = {"generated": 0, "skipped": 0, "total": 0, "errors": [str(exc)]}
    else:
        print("\n[SKIP] Phase 3: Policy Generation")

    # ── Phase 4: Remediation Tickets ──
    ticket_results: Optional[dict] = None
    if not args.skip_remediation:
        print("\n" + "=" * 60)
        print(" PHASE 4: REMEDIATION TICKETS")
        print("=" * 60)
        t_phase = time.time()
        try:
            ticket_results = create_tickets(ctrl_results)
            for err in ticket_results.get("errors", []):
                phase_errors.append(f"[Tickets] {err}")
            print(f"  Создано {ticket_results['created']} тикетов [{time.time() - t_phase:.1f}s]")
        except Exception as exc:
            phase_errors.append(f"[Tickets] {exc}")
            print(f"  ERROR: {exc}")
            ticket_results = {"created": 0, "tickets": [], "errors": [str(exc)]}
    else:
        print("\n[SKIP] Phase 4: Remediation Tickets")

    # ── Phase 5: E-Signature ──
    esign_results: Optional[dict] = None
    if not args.skip_esign:
        print("\n" + "=" * 60)
        print(" PHASE 5: E-SIGNATURE")
        print("=" * 60)
        t_phase = time.time()
        try:
            esign_results = request_signature(controls_map)
            for err in esign_results.get("errors", []):
                phase_errors.append(f"[ESign] {err}")
            print(f"  Фаза завершена [{time.time() - t_phase:.1f}s]")
        except Exception as exc:
            phase_errors.append(f"[ESign] {exc}")
            print(f"  ERROR: {exc}")
            esign_results = {"envelope_id": None, "url": "", "errors": [str(exc)]}
    else:
        print("\n[SKIP] Phase 5: E-Signature")

    # ── Phase 6: Final Report ──
    print("\n" + "=" * 60)
    print(" PHASE 6: FINAL REPORT")
    print("=" * 60)
    print_report(
        start_time   = start_time,
        evidence_res = evidence_results,
        ctrl_res     = ctrl_results,
        policy_res   = policy_results,
        ticket_res   = ticket_results,
        esign_res    = esign_results,
        phase_errors = phase_errors,
        run_mode     = mode_label,
    )

    # ── Генерация HTML отчёта ──────────────────────────────────────────────────
    # Запускается после ASCII-отчёта, не влияет на exit-код
    try:
        from html_report import HTMLReportGenerator
        report_path = HTMLReportGenerator().generate_standalone()
        print(f"HTML Report: {report_path}")
    except Exception as exc:
        print(f"[WARN] HTML отчёт не сгенерирован: {exc}")


if __name__ == "__main__":
    main()
