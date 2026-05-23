"""
Модуль управления временной шкалой аудита и мастером определения области (scoping wizard).
Хранит данные в audit_timeline.json рядом с файлом.
"""

import json
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from log_config import get_logger

log = get_logger(__name__)

TIMELINE_FILE = Path(__file__).parent / "audit_timeline.json"

# Стандартные milestone-шаблоны (weeks_before: недель ДО даты аудита)
MILESTONE_TEMPLATES: dict[str, list[dict]] = {
    "soc2_type2": [
        {
            "weeks_before": 16,
            "name": "Readiness Assessment",
            "description": "Initial gap analysis and scoping",
            "owner": "ciso",
        },
        {
            "weeks_before": 14,
            "name": "Evidence Collection Start",
            "description": "Begin automated evidence collection",
            "owner": "compliance_team",
        },
        {
            "weeks_before": 12,
            "name": "Policy Review & Updates",
            "description": "Update all policies to current standards",
            "owner": "legal",
        },
        {
            "weeks_before": 10,
            "name": "Access Review",
            "description": "Complete quarterly access review",
            "owner": "it_admin",
        },
        {
            "weeks_before": 8,
            "name": "Vendor Risk Assessments",
            "description": "Complete vendor SOC2 reviews",
            "owner": "procurement",
        },
        {
            "weeks_before": 6,
            "name": "Internal Audit",
            "description": "Internal control testing",
            "owner": "internal_audit",
        },
        {
            "weeks_before": 4,
            "name": "Remediation Sprint",
            "description": "Fix all HIGH/CRITICAL findings",
            "owner": "engineering",
        },
        {
            "weeks_before": 2,
            "name": "Pre-Audit Review",
            "description": "Final evidence package review",
            "owner": "ciso",
        },
        {
            "weeks_before": 0,
            "name": "Audit Start",
            "description": "External auditor begins fieldwork",
            "owner": "auditor",
        },
        {
            "weeks_before": -4,
            "name": "Audit Report",
            "description": "Receive final SOC2 Type II report",
            "owner": "auditor",
        },
    ],
    "soc2_type1": [
        {
            "weeks_before": 8,
            "name": "Readiness Assessment",
            "description": "Initial gap analysis and scoping",
            "owner": "ciso",
        },
        {
            "weeks_before": 6,
            "name": "Evidence Collection Start",
            "description": "Сбор доказательств по всем контролям",
            "owner": "compliance_team",
        },
        {
            "weeks_before": 4,
            "name": "Policy Review & Updates",
            "description": "Обновление политик до актуальных стандартов",
            "owner": "legal",
        },
        {
            "weeks_before": 2,
            "name": "Remediation Sprint",
            "description": "Устранение всех HIGH/CRITICAL находок",
            "owner": "engineering",
        },
        {
            "weeks_before": 0,
            "name": "Audit Start",
            "description": "Внешний аудитор начинает работу",
            "owner": "auditor",
        },
        {
            "weeks_before": -2,
            "name": "Audit Report",
            "description": "Получение финального отчёта SOC2 Type I",
            "owner": "auditor",
        },
    ],
}

# Задачи для каждого milestone-а (для генерации чеклиста)
MILESTONE_TASKS: dict[str, list[str]] = {
    "Readiness Assessment": [
        "Провести интервью с владельцами систем",
        "Определить границы области аудита",
        "Выявить пробелы в документации",
        "Оценить зрелость текущих контролей",
        "Сформировать план устранения пробелов",
    ],
    "Evidence Collection Start": [
        "Настроить автоматический сбор логов доступа",
        "Проверить подключение к системам мониторинга",
        "Собрать политики и процедуры в единый реестр",
        "Настроить экспорт конфигураций из AWS/GCP/Azure",
        "Верифицировать полноту evidence для каждого контроля",
    ],
    "Policy Review & Updates": [
        "Актуализировать Acceptable Use Policy",
        "Обновить Information Security Policy",
        "Пересмотреть Incident Response Plan",
        "Обновить Business Continuity Plan",
        "Проверить и подписать все политики у руководства",
    ],
    "Access Review": [
        "Выгрузить список всех активных пользователей",
        "Верифицировать права доступа с владельцами систем",
        "Отозвать доступ уволенных сотрудников",
        "Проверить MFA для всех привилегированных учёток",
        "Задокументировать результаты ревью",
    ],
    "Vendor Risk Assessments": [
        "Составить реестр критических вендоров",
        "Запросить SOC2 отчёты у субпроцессоров",
        "Проверить Data Processing Agreements",
        "Оценить риски для каждого вендора",
        "Обновить реестр вендорских рисков",
    ],
    "Internal Audit": [
        "Провести тестирование CC6.x контролей (логический доступ)",
        "Проверить CC7.x контроли (мониторинг и инциденты)",
        "Провести выборочную проверку Change Management",
        "Задокументировать результаты тестирования",
        "Согласовать план устранения находок",
    ],
    "Remediation Sprint": [
        "Устранить все CRITICAL находки внутреннего аудита",
        "Закрыть HIGH находки или получить risk acceptance",
        "Актуализировать evidence после исправлений",
        "Провести повторное тестирование исправленных контролей",
        "Зафиксировать закрытие находок",
    ],
    "Pre-Audit Review": [
        "Собрать финальный пакет evidence",
        "Провести mock-интервью с ключевыми сотрудниками",
        "Верифицировать доступ аудиторов к системам",
        "Подготовить PBC (Provided by Client) список",
        "Провести финальный брифинг с командой",
    ],
    "Audit Start": [
        "Провести kick-off встречу с аудиторами",
        "Предоставить доступ к системам управления",
        "Начать обработку PBC запросов",
        "Организовать ежедневные статус-колы с аудиторами",
    ],
    "Audit Report": [
        "Получить черновик отчёта от аудиторов",
        "Проверить точность описания контролей",
        "Подать management response на находки",
        "Утвердить финальный отчёт",
    ],
}

# Список систем для мастера определения области
SCOPE_SYSTEMS: list[dict] = [
    {
        "id": "aws",
        "name": "AWS Infrastructure",
        "description": "EC2, S3, RDS, IAM, CloudTrail",
        "controls": ["CC6.1", "CC6.6", "CC6.7", "CC7.1", "CC7.2"],
    },
    {
        "id": "okta",
        "name": "Okta (Identity Provider)",
        "description": "SSO, MFA, пользовательские учётки",
        "controls": ["CC6.1", "CC6.2", "CC6.3"],
    },
    {
        "id": "github",
        "name": "GitHub",
        "description": "Репозитории, CI/CD, управление кодом",
        "controls": ["CC8.1", "CC6.4", "CC6.5"],
    },
    {
        "id": "jira",
        "name": "Jira / Confluence",
        "description": "Управление изменениями и документация",
        "controls": ["CC3.1", "CC3.2", "CC8.1"],
    },
    {
        "id": "datadog",
        "name": "Datadog",
        "description": "Мониторинг, алертинг, логи",
        "controls": ["CC7.1", "CC7.2", "CC7.3"],
    },
    {
        "id": "postgres",
        "name": "PostgreSQL (Production DB)",
        "description": "Основная база данных приложения",
        "controls": ["CC6.1", "CC6.6", "CC9.1"],
    },
    {
        "id": "gsuite",
        "name": "Google Workspace",
        "description": "Email, Drive, корпоративные сервисы",
        "controls": ["CC1.1", "CC6.2", "CC5.1"],
    },
    {
        "id": "slack",
        "name": "Slack",
        "description": "Корпоративные коммуникации",
        "controls": ["CC2.1", "CC6.2"],
    },
]


def _now_iso() -> str:
    """Текущее время в ISO 8601 UTC формате."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_timelines() -> list[dict]:
    """Загружает все timelines из JSON файла."""
    if not TIMELINE_FILE.exists():
        TIMELINE_FILE.write_text(json.dumps([], indent=2))
        return []
    try:
        data = json.loads(TIMELINE_FILE.read_text())
        return data if isinstance(data, list) else []
    except Exception as e:
        log.error("Ошибка чтения audit_timeline.json", extra={"error": str(e)})
        return []


def _save_timelines(timelines: list[dict]) -> None:
    """Сохраняет все timelines в JSON файл."""
    TIMELINE_FILE.write_text(json.dumps(timelines, indent=2, ensure_ascii=False))


class AuditTimeline:
    """
    Управляет временной шкалой аудита: создание, обновление, статус.
    Данные хранятся в audit_timeline.json.
    """

    def create_timeline(
        self,
        audit_date: str,
        framework: str,
        scope: dict,
        created_by: str,
    ) -> dict:
        """
        Создаёт новый timeline на основе шаблона.

        audit_date: ISO дата в формате "YYYY-MM-DD"
        framework: "soc2_type2" | "soc2_type1"
        scope: {"systems": [...], "in_scope_controls": [...], "excluded": [...]}
        created_by: email создателя
        """
        if framework not in MILESTONE_TEMPLATES:
            raise ValueError(f"Неизвестный фреймворк: {framework}. Доступно: {list(MILESTONE_TEMPLATES.keys())}")

        # Парсим дату аудита
        try:
            target_date = date.fromisoformat(audit_date)
        except ValueError:
            raise ValueError(f"Некорректный формат даты: {audit_date}. Ожидается YYYY-MM-DD")

        # Генерируем milestones с реальными датами
        template = MILESTONE_TEMPLATES[framework]
        milestones = []
        for tmpl in template:
            delta_days = tmpl["weeks_before"] * 7
            milestone_date = target_date - timedelta(days=delta_days)
            milestones.append({
                "id": str(uuid.uuid4()),
                "name": tmpl["name"],
                "description": tmpl["description"],
                "owner": tmpl["owner"],
                "date": milestone_date.isoformat(),
                "weeks_before": tmpl["weeks_before"],
                "status": "not_started",
                "notes": "",
                "updated_at": None,
                "updated_by": None,
            })

        # Сортируем по дате
        milestones.sort(key=lambda m: m["date"])

        timeline = {
            "id": str(uuid.uuid4()),
            "audit_date": audit_date,
            "framework": framework,
            "scope": scope,
            "created_by": created_by,
            "created_at": _now_iso(),
            "status": "active",
            "milestones": milestones,
        }

        # Деактивируем предыдущие активные timelines
        timelines = _load_timelines()
        for tl in timelines:
            if tl.get("status") == "active":
                tl["status"] = "archived"

        timelines.append(timeline)
        _save_timelines(timelines)

        log.info(
            "Создан новый audit timeline",
            extra={"id": timeline["id"], "framework": framework, "audit_date": audit_date, "created_by": created_by},
        )
        return timeline

    def get_active_timeline(self) -> Optional[dict]:
        """Возвращает текущий активный timeline или None."""
        timelines = _load_timelines()
        for tl in reversed(timelines):  # последний созданный первым
            if tl.get("status") == "active":
                return tl
        return None

    def get_all_timelines(self) -> list[dict]:
        """Возвращает все timelines (активные и архивные)."""
        return _load_timelines()

    def get_timeline_by_id(self, timeline_id: str) -> Optional[dict]:
        """Возвращает timeline по ID или None."""
        timelines = _load_timelines()
        for tl in timelines:
            if tl["id"] == timeline_id:
                return tl
        return None

    def update_milestone_status(
        self,
        timeline_id: str,
        milestone_id: str,
        status: str,
        notes: str,
        updated_by: str = "system",
    ) -> dict:
        """
        Обновляет статус milestone.
        status: not_started | in_progress | completed | blocked
        """
        valid_statuses = {"not_started", "in_progress", "completed", "blocked"}
        if status not in valid_statuses:
            raise ValueError(f"Недопустимый статус: {status}. Допустимые: {valid_statuses}")

        timelines = _load_timelines()
        for tl in timelines:
            if tl["id"] == timeline_id:
                for ms in tl["milestones"]:
                    if ms["id"] == milestone_id:
                        ms["status"] = status
                        ms["notes"] = notes
                        ms["updated_at"] = _now_iso()
                        ms["updated_by"] = updated_by
                        _save_timelines(timelines)
                        log.info(
                            "Обновлён статус milestone",
                            extra={"timeline_id": timeline_id, "milestone": ms["name"], "status": status},
                        )
                        return ms
                raise ValueError(f"Milestone {milestone_id} не найден в timeline {timeline_id}")
        raise ValueError(f"Timeline {timeline_id} не найден")

    def get_current_status(self) -> dict:
        """
        Возвращает текущий статус активного timeline:
        days_to_audit, current_phase, overdue_milestones, upcoming_milestones,
        overall_progress_pct, risk_level: green|yellow|red
        """
        tl = self.get_active_timeline()
        if not tl:
            return {"active": False, "message": "Нет активного audit timeline"}

        today = date.today()
        audit_date = date.fromisoformat(tl["audit_date"])
        days_to_audit = (audit_date - today).days

        milestones = tl["milestones"]
        total = len(milestones)
        completed = [m for m in milestones if m["status"] == "completed"]
        progress_pct = round(len(completed) / total * 100) if total > 0 else 0

        # Просроченные milestones — дата прошла, но не completed
        overdue = [
            m for m in milestones
            if date.fromisoformat(m["date"]) < today and m["status"] not in ("completed",)
        ]

        # Ближайшие незавершённые milestones (следующие 3)
        upcoming = sorted(
            [m for m in milestones if date.fromisoformat(m["date"]) >= today and m["status"] != "completed"],
            key=lambda m: m["date"],
        )[:3]

        # Текущая фаза — первый milestone in_progress или ближайший не_начатый
        current_phase = None
        for m in milestones:
            if m["status"] == "in_progress":
                current_phase = m["name"]
                break
        if not current_phase and upcoming:
            current_phase = upcoming[0]["name"]

        # Оценка риска
        if overdue:
            risk_level = "red"
        elif days_to_audit < 28 and progress_pct < 70:
            risk_level = "red"
        elif days_to_audit < 56 and progress_pct < 50:
            risk_level = "yellow"
        elif len(overdue) == 0 and progress_pct >= 70:
            risk_level = "green"
        else:
            risk_level = "yellow"

        return {
            "active": True,
            "timeline_id": tl["id"],
            "framework": tl["framework"],
            "audit_date": tl["audit_date"],
            "days_to_audit": days_to_audit,
            "current_phase": current_phase,
            "overall_progress_pct": progress_pct,
            "risk_level": risk_level,
            "overdue_milestones": [
                {"id": m["id"], "name": m["name"], "date": m["date"], "status": m["status"]}
                for m in overdue
            ],
            "upcoming_milestones": [
                {"id": m["id"], "name": m["name"], "date": m["date"], "status": m["status"]}
                for m in upcoming
            ],
            "total_milestones": total,
            "completed_milestones": len(completed),
        }

    def generate_checklist(self, timeline_id: str) -> list[dict]:
        """
        Генерирует детальный чеклист задач для каждого milestone.
        Основан на MILESTONE_TASKS + scope контролей.
        """
        tl = self.get_timeline_by_id(timeline_id)
        if not tl:
            raise ValueError(f"Timeline {timeline_id} не найден")

        scope_controls = tl.get("scope", {}).get("in_scope_controls", [])
        checklist = []

        for ms in tl["milestones"]:
            base_tasks = MILESTONE_TASKS.get(ms["name"], [])
            tasks = [{"text": t, "type": "general"} for t in base_tasks]

            # Добавляем задачи для контролей в области (только для milestone Evidence Collection)
            if ms["name"] == "Evidence Collection Start" and scope_controls:
                for ctrl in scope_controls[:10]:  # топ-10 чтобы не перегружать
                    tasks.append({
                        "text": f"Собрать evidence для контроля {ctrl}",
                        "type": "control",
                        "control": ctrl,
                    })

            checklist.append({
                "milestone_id": ms["id"],
                "milestone_name": ms["name"],
                "milestone_date": ms["date"],
                "milestone_status": ms["status"],
                "owner": ms["owner"],
                "tasks": tasks,
            })

        return checklist
