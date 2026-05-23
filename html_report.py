"""
html_report.py — Генератор HTML отчёта для SOC 2 Compliance Audit.
Создаёт standalone HTML файл (всё встроено, без внешних зависимостей).
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from log_config import get_logger

log = get_logger(__name__)

# Пути к директориям
_BASE_DIR = Path(__file__).parent
REPORTS_DIR = _BASE_DIR / "reports"
TEMPLATES_DIR = _BASE_DIR / "templates"

# URL Evidence Tracker из переменных окружения
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")

# Описания категорий контролей по коду
_CONTROL_CATEGORIES: Dict[str, str] = {
    "CC1": "Control Environment",
    "CC2": "Communication & Information",
    "CC3": "Risk Assessment",
    "CC4": "Monitoring Activities",
    "CC5": "Control Activities",
    "CC6": "Logical Access Controls",
    "CC7": "System Operations",
    "CC8": "Change Management",
    "CC9": "Risk Mitigation",
}

# Уровень критичности для FAIL-контролей
_SEVERITY_MAP: Dict[str, str] = {
    "CC6.1": "CRITICAL",
    "CC6.2": "HIGH",
    "CC6.3": "HIGH",
    "CC6.7": "HIGH",
    "CC7.1": "HIGH",
    "CC7.2": "HIGH",
    "CC8.1": "HIGH",
    "CC3.4": "MEDIUM",
}

# Рекомендации по устранению для часто встречающихся FAIL-контролей
_REMEDIATION_MAP: Dict[str, str] = {
    "CC6.1": "Реализовать MFA для всех привилегированных аккаунтов. Провести ревью прав доступа.",
    "CC6.2": "Внедрить автоматизированный onboarding/offboarding workflow. Формализовать процесс регистрации.",
    "CC6.3": "Применить принцип наименьших привилегий. Провести ревью RBAC.",
    "CC6.4": "Усилить физический контроль доступа. Внедрить журнал доступа.",
    "CC6.5": "Создать процедуры уничтожения данных. Задокументировать политику хранения.",
    "CC6.6": "Развернуть endpoint protection. Обновить антивирусное ПО.",
    "CC6.7": "Включить шифрование TLS 1.2+. Провести проверку передачи данных.",
    "CC6.8": "Развернуть EDR-систему. Настроить мониторинг аномальной активности.",
    "CC7.1": "Внедрить SIEM. Настроить алерты на изменения конфигурации.",
    "CC7.2": "Настроить мониторинг аномалий. Определить пороги срабатывания.",
    "CC8.1": "Внедрить CI/CD pipeline с обязательным code review. Формализовать change management.",
    "CC3.4": "Создать процесс оценки влияния изменений на систему внутреннего контроля.",
    "CC2.2": "Задокументировать цели и ответственность. Провести коммуникацию внутри организации.",
    "CC9.1": "Разработать BCP/DR план. Провести учения по восстановлению.",
}

# Mock данные для случая недоступности Evidence Tracker
_MOCK_CONTROLS: List[Dict[str, Any]] = [
    {"id": "1", "code": "CC6.1", "title": "Logical Access Security Software and Architectures", "status": "FAIL", "description": "Controls over logical access", "evidence": []},
    {"id": "2", "code": "CC6.2", "title": "Registration and Authorization of New Users",          "status": "PASS", "description": "User provisioning controls",   "evidence": []},
    {"id": "3", "code": "CC7.1", "title": "Detection and Monitoring",                             "status": "FAIL", "description": "Threat monitoring",            "evidence": []},
]


class HTMLReportGenerator:
    """Генератор HTML отчёта SOC 2."""

    def __init__(self) -> None:
        # Инициализируем Jinja2 окружение с автоэскейпингом
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "j2"]),
        )
        # Создаём папку reports/ если не существует
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Публичные методы ──────────────────────────────────────────────────────

    def generate(self, audit_data: Dict[str, Any], output_filename: Optional[str] = None) -> Path:
        """
        Генерирует HTML отчёт из уже собранных данных audit_runner.

        :param audit_data: dict из audit_runner (результаты всех фаз)
        :param output_filename: имя файла (без расширения), авто если None
        :return: Path к созданному HTML файлу
        """
        # Дополняем данные из внешних источников (vendors, remediations, policies)
        enriched = self._enrich_audit_data(audit_data)
        return self._render_and_save(enriched, output_filename)

    def generate_standalone(self, output_filename: Optional[str] = None) -> Path:
        """
        Собирает данные самостоятельно из всех источников и генерирует отчёт.
        Используется при прямом вызове без audit_runner.

        :param output_filename: имя файла без расширения, авто если None
        :return: Path к созданному HTML файлу
        """
        data = self._collect_data()
        return self._render_and_save(data, output_filename)

    # ── Сбор данных ───────────────────────────────────────────────────────────

    def _collect_data(self) -> Dict[str, Any]:
        """
        Собирает данные для шаблона из всех источников:
        - EvidenceClient: контроли + evidence
        - controls_map.json: описания контролей
        - policies/ директория: список политик
        - vendor_inventory.json: вендоры
        - remediations.json: тикеты
        """
        company_name = os.getenv("COMPANY_NAME", "MARINESO INC.")

        # --- Контроли и evidence из Evidence Tracker ---
        controls = self._fetch_controls_with_evidence()

        # --- Вычисляем сводку ---
        summary = self._compute_summary(controls)

        # --- Список политик из папки policies/ ---
        policies = self._load_policies()

        # --- Вендоры ---
        vendors = self._load_vendors()

        # --- Тикеты на устранение ---
        remediations = self._load_remediations()

        # --- FAIL-контроли с finding/remediation текстом ---
        findings = self._build_findings(controls, remediations)

        return {
            "company_name":  company_name,
            "generated_at":  datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "period_start":  "2025-05-22",
            "period_end":    datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "controls":      controls,
            "summary":       summary,
            "findings":      findings,
            "policies":      policies,
            "vendors":       vendors,
            "remediations":  remediations,
        }

    def _enrich_audit_data(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Обогащает данные audit_runner данными из файлов.
        Добавляет vendors, remediations, policies если они не переданы.
        """
        base = self._collect_data()

        # Перекрываем данные из audit_runner если они есть
        if audit_data.get("controls"):
            base["controls"] = audit_data["controls"]
            base["summary"]  = self._compute_summary(audit_data["controls"])
            base["findings"]  = self._build_findings(audit_data["controls"], base["remediations"])

        return base

    def _fetch_controls_with_evidence(self) -> List[Dict[str, Any]]:
        """
        Получает список контролей из Evidence Tracker.
        При ошибке возвращает mock данные с предупреждением.
        """
        try:
            import requests

            api_key = os.getenv("EVIDENCE_API_KEY", "soc2-dev-key")
            headers = {"X-API-Key": api_key}

            resp = requests.get(
                f"{EVIDENCE_TRACKER_URL}/api/v1/controls/?limit=100",
                headers=headers,
                timeout=8,
            )
            resp.raise_for_status()
            raw_controls: List[Dict[str, Any]] = resp.json()

        except Exception as exc:
            log.warning("Evidence Tracker недоступен, используем mock данные", extra={"error": str(exc)})
            return _MOCK_CONTROLS

        # Для каждого контроля подтягиваем evidence
        controls: List[Dict[str, Any]] = []
        for ctrl in raw_controls:
            ctrl_id = ctrl.get("id", "")
            evidence_items: List[Dict[str, Any]] = []

            try:
                import requests as req_inner
                ev_resp = req_inner.get(
                    f"{EVIDENCE_TRACKER_URL}/api/v1/evidence/",
                    headers={"X-API-Key": os.getenv("EVIDENCE_API_KEY", "soc2-dev-key")},
                    params={"control_id": ctrl_id, "limit": 50},
                    timeout=8,
                )
                if ev_resp.status_code == 200:
                    evidence_items = ev_resp.json()
            except Exception:
                pass  # evidence не критично — продолжаем

            code = ctrl.get("code", "")
            controls.append({
                "id":          ctrl_id,
                "code":        code,
                "title":       ctrl.get("title", ""),
                "status":      ctrl.get("status", "not_started"),
                "description": ctrl.get("description", ""),
                "category":    _CONTROL_CATEGORIES.get(code[:3], "General"),
                "evidence":    evidence_items,
            })

        return controls

    # ── Вспомогательные методы сбора данных ──────────────────────────────────

    def _compute_summary(self, controls: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Вычисляет сводную статистику по контролям."""
        total = len(controls)
        pass_count = sum(1 for c in controls if str(c.get("status", "")).upper() == "PASS")
        fail_count = sum(1 for c in controls if str(c.get("status", "")).upper() == "FAIL")
        pending    = total - pass_count - fail_count

        pass_pct     = round(pass_count / total * 100) if total else 0
        readiness    = pass_pct  # общая готовность = % PASS контролей

        return {
            "pass":           pass_count,
            "fail":           fail_count,
            "not_started":    pending,
            "total":          total,
            "compliance_pct": pass_pct,
            "readiness_pct":  readiness,
            "pass_pct":       pass_pct,
            "fail_pct":       round(fail_count / total * 100) if total else 0,
        }

    def _build_findings(
        self,
        controls: List[Dict[str, Any]],
        remediations: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Строит список findings для FAIL-контролей.
        Каждый finding включает severity, описание и рекомендацию.
        """
        # Индексируем remediations по коду контроля
        rem_by_code: Dict[str, Dict[str, Any]] = {r["control_code"]: r for r in remediations}

        findings: List[Dict[str, Any]] = []
        for ctrl in controls:
            if str(ctrl.get("status", "")).upper() != "FAIL":
                continue

            code = ctrl.get("code", "")
            rem  = rem_by_code.get(code, {})

            findings.append({
                "code":        code,
                "title":       ctrl.get("title", ""),
                "severity":    _SEVERITY_MAP.get(code, "MEDIUM"),
                "evidence_count": len(ctrl.get("evidence", [])),
                "finding":     ctrl.get("description", f"{code} control requires attention."),
                "remediation": _REMEDIATION_MAP.get(code, "Провести детальный анализ и разработать план устранения."),
                "jira_key":    rem.get("jira_key", ""),
                "jira_url":    rem.get("jira_url", ""),
                "priority":    rem.get("priority", "Medium"),
            })

        # Сортируем: CRITICAL → HIGH → MEDIUM → LOW
        _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: _order.get(f["severity"], 9))

        return findings

    def _load_policies(self) -> List[Dict[str, Any]]:
        """Загружает список политик из директории policies/."""
        policies_dir = _BASE_DIR / "policies"
        if not policies_dir.exists():
            return []

        policies: List[Dict[str, Any]] = []
        for path in sorted(policies_dir.glob("*.md")):
            stat = path.stat()
            # Форматируем дату создания
            created_at = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d")
            policies.append({
                "filename": path.name,
                "title":    path.stem.replace("_", " ").replace("-", " ").title(),
                "created_at": created_at,
                "size_kb":  round(stat.st_size / 1024, 1),
            })

        return policies

    def _load_vendors(self) -> List[Dict[str, Any]]:
        """Загружает список вендоров из vendor_inventory.json."""
        vendor_file = _BASE_DIR / "vendor_inventory.json"
        if not vendor_file.exists():
            return []

        try:
            with open(vendor_file) as f:
                data = json.load(f)
            vendors = data.get("vendors", [])
            # Нормализуем поля для шаблона
            return [
                {
                    "name":           v.get("name", ""),
                    "category":       v.get("category", "").replace("_", " ").title(),
                    "soc2_certified": v.get("soc2_certified", False),
                    "risk_level":     v.get("risk_level") or "TBD",
                    "contract_review_date": v.get("contract_review_date") or "—",
                    "data_processed": ", ".join(v.get("data_processed", [])),
                }
                for v in vendors
            ]
        except Exception as exc:
            log.warning("Не удалось загрузить vendor_inventory.json", extra={"error": str(exc)})
            return []

    def _load_remediations(self) -> List[Dict[str, Any]]:
        """Загружает тикеты из remediations.json."""
        rem_file = _BASE_DIR / "remediations.json"
        if not rem_file.exists():
            return []

        try:
            with open(rem_file) as f:
                data = json.load(f)
            raw = data.get("remediations", {})

            # remediations.json хранит dict {code: {...}}, преобразуем в список
            items: List[Dict[str, Any]] = []
            for code, ticket in raw.items():
                items.append({
                    "control_code": ticket.get("control_code", code),
                    "jira_key":     ticket.get("jira_key", ""),
                    "jira_url":     ticket.get("jira_url", "#"),
                    "finding":      ticket.get("finding", ""),
                    "priority":     ticket.get("priority", "Medium"),
                    "status":       ticket.get("status", "open").upper(),
                    "created_at":   ticket.get("created_at", "")[:10],
                    "is_mock":      ticket.get("mock", False),
                })

            # Сортируем по приоритету
            _prio = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            items.sort(key=lambda t: _prio.get(t["priority"], 9))
            return items

        except Exception as exc:
            log.warning("Не удалось загрузить remediations.json", extra={"error": str(exc)})
            return []

    # ── Рендеринг и сохранение ───────────────────────────────────────────────

    def _render_and_save(self, data: Dict[str, Any], output_filename: Optional[str]) -> Path:
        """
        Рендерит Jinja2 шаблон и сохраняет HTML файл.
        Возвращает абсолютный путь к файлу.
        """
        # Формируем имя файла с меткой времени
        if not output_filename:
            ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
            output_filename = f"audit_report_{ts}"

        # Гарантируем расширение .html
        if not output_filename.endswith(".html"):
            output_filename = output_filename + ".html"

        output_path = REPORTS_DIR / output_filename

        try:
            template = self._env.get_template("audit_report.html.j2")
        except Exception as exc:
            log.error("Шаблон audit_report.html.j2 не найден", extra={"error": str(exc)})
            raise

        html_content = template.render(**data)

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

        log.info("HTML отчёт сгенерирован", extra={"path": str(output_path)})
        return output_path


# ── CLI запуск ────────────────────────────────────────────────────────────────

def main() -> None:
    """Точка входа для запуска из командной строки."""
    import argparse
    parser = argparse.ArgumentParser(description="Генератор HTML отчёта SOC 2")
    parser.add_argument("--output", default=None, help="Имя выходного файла (без расширения)")
    args = parser.parse_args()

    generator = HTMLReportGenerator()
    report_path = generator.generate_standalone(output_filename=args.output)
    print(f"HTML Report: {report_path}")


if __name__ == "__main__":
    main()
