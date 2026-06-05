"""
Control Mapping Engine — граф соответствий между фреймворками.

Один контроль покрывает сразу несколько стандартов:
  CC6.1 ↔ ISO 27001 A.5.15 ↔ NIST AC-2 ↔ CIS 6.1

Данные маппинга основаны на публичных cross-walk таблицах:
- AICPA SOC 2 Trust Services Criteria 2017 (updated 2022)
- ISO/IEC 27001:2022 Annex A
- NIST SP 800-53 Rev 5
- CIS Controls v8
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Optional

_LOCK = Lock()


# ── Модель данных ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class FrameworkMapping:
    """Неизменяемый объект: маппинг одного SOC 2 контроля на другие фреймворки.

    Все коллекции — tuple для полной иммутабельности frozen dataclass.
    """

    soc2: str                       # "CC6.1"
    iso27001: tuple[str, ...]       # ("A.5.15", "A.8.2")
    nist_800_53: tuple[str, ...]    # ("AC-2", "AC-3")
    cis_v8: tuple[str, ...]         # ("6.1", "6.2")
    gdpr: tuple[str, ...]           # ("Art.32(1)(b)", "Art.24")
    hipaa: tuple[str, ...]          # ("164.312(a)(1)", "164.308(a)(3)")
    pci_dss_v4: tuple[str, ...]     # ("7.1", "8.3")
    description: str                # краткое описание назначения контроля
    category: str                   # категория TSC: CC1–CC9 / A / PI / C / P


# ── Данные маппинга (все 33 контроля SOC 2 TSC 2017) ───────────────────────────

CONTROL_MAPPINGS: list[FrameworkMapping] = [

    # ── CC1 — Control Environment (COSO) ──────────────────────────────────────
    FrameworkMapping(
        soc2="CC1.1",
        iso27001=("A.5.1", "A.5.2", "A.6.1"),
        nist_800_53=("PM-1", "PM-2", "AT-1"),
        cis_v8=("14.1", "14.2"),
        gdpr=("Art.5(2)", "Art.24"),
        hipaa=("164.308(a)(1)", "164.308(a)(2)"),
        pci_dss_v4=("12.1", "12.4"),
        description="Демонстрирует приверженность руководства честности и этическим ценностям",
        category="CC1",
    ),
    FrameworkMapping(
        soc2="CC1.2",
        iso27001=("A.5.2", "A.6.1"),
        nist_800_53=("PM-2", "SA-2", "PL-2"),
        cis_v8=("14.1",),
        gdpr=("Art.5(2)", "Art.24"),
        hipaa=("164.308(a)(2)",),
        pci_dss_v4=("12.4",),
        description="Совет директоров независим от руководства и осуществляет надзор за внутренним контролем",
        category="CC1",
    ),
    FrameworkMapping(
        soc2="CC1.3",
        iso27001=("A.5.2", "A.6.1", "A.6.3"),
        nist_800_53=("PM-2", "PS-1", "PS-2"),
        cis_v8=("14.1", "14.6"),
        gdpr=("Art.24", "Art.37"),
        hipaa=("164.308(a)(2)", "164.308(a)(3)"),
        pci_dss_v4=("12.4", "12.5"),
        description="Структура, полномочия и ответственность установлены в соответствии с целями",
        category="CC1",
    ),
    FrameworkMapping(
        soc2="CC1.4",
        iso27001=("A.6.3", "A.6.4", "A.7.2"),
        nist_800_53=("AT-2", "AT-3", "PM-13"),
        cis_v8=("14.1", "14.2", "14.7"),
        gdpr=("Art.39(1)(b)", "Art.47"),
        hipaa=("164.308(a)(5)",),
        pci_dss_v4=("12.6",),
        description="Компетентность персонала подтверждена, политика найма и удержания разработана",
        category="CC1",
    ),
    FrameworkMapping(
        soc2="CC1.5",
        iso27001=("A.5.1", "A.5.2", "A.6.1"),
        nist_800_53=("PM-1", "IR-8", "AU-1"),
        cis_v8=("14.1", "14.2"),
        gdpr=("Art.5(2)", "Art.24"),
        hipaa=("164.308(a)(1)", "164.308(a)(2)"),
        pci_dss_v4=("12.4",),
        description="Ответственность за внутренний контроль закреплена на уровне всей организации",
        category="CC1",
    ),

    # ── CC2 — Communication and Information ───────────────────────────────────
    FrameworkMapping(
        soc2="CC2.1",
        iso27001=("A.5.1", "A.5.37", "A.8.12"),
        nist_800_53=("PL-2", "PL-4", "SA-5"),
        cis_v8=("14.1", "14.2"),
        gdpr=("Art.30",),
        hipaa=("164.316(b)(1)",),
        pci_dss_v4=("12.1",),
        description="Информация, необходимая для поддержки функционирования внутреннего контроля, доступна",
        category="CC2",
    ),
    FrameworkMapping(
        soc2="CC2.2",
        iso27001=("A.5.1", "A.6.3", "A.7.2"),
        nist_800_53=("PL-4", "AT-2", "PM-1"),
        cis_v8=("14.1", "14.2"),
        gdpr=("Art.12", "Art.24"),
        hipaa=("164.308(a)(5)",),
        pci_dss_v4=("12.6",),
        description="Внутреннее взаимодействие поддерживает функционирование внутреннего контроля",
        category="CC2",
    ),
    FrameworkMapping(
        soc2="CC2.3",
        iso27001=("A.5.6", "A.5.14", "A.6.7"),
        nist_800_53=("IR-6", "SA-3", "PL-4"),
        cis_v8=("14.1",),
        gdpr=("Art.12", "Art.13", "Art.14"),
        hipaa=("164.520",),
        pci_dss_v4=("12.9",),
        description="Внешнее взаимодействие с заинтересованными сторонами организовано надлежащим образом",
        category="CC2",
    ),

    # ── CC3 — Risk Assessment ──────────────────────────────────────────────────
    FrameworkMapping(
        soc2="CC3.1",
        iso27001=("A.5.29", "A.6.1", "A.8.16"),
        nist_800_53=("RA-1", "RA-2", "PM-9"),
        cis_v8=("18.1", "18.2"),
        gdpr=("Art.32(2)", "Art.35"),
        hipaa=("164.308(a)(1)(ii)(A)",),
        pci_dss_v4=("12.3",),
        description="Чёткие цели сформулированы для выявления и оценки рисков",
        category="CC3",
    ),
    FrameworkMapping(
        soc2="CC3.2",
        iso27001=("A.5.29", "A.8.2", "A.8.16"),
        nist_800_53=("RA-3", "RA-5", "PM-9"),
        cis_v8=("18.1", "18.2", "18.3"),
        gdpr=("Art.32(2)", "Art.35(7)"),
        hipaa=("164.308(a)(1)(ii)(A)",),
        pci_dss_v4=("12.3",),
        description="Риски достижения целей выявляются и анализируются для управления ими",
        category="CC3",
    ),
    FrameworkMapping(
        soc2="CC3.3",
        iso27001=("A.5.29", "A.6.6", "A.8.3"),
        nist_800_53=("RA-3", "SA-11", "PM-16"),
        cis_v8=("18.1", "18.3"),
        gdpr=("Art.32(2)",),
        hipaa=("164.308(a)(1)(ii)(A)",),
        pci_dss_v4=("12.3",),
        description="Оценивается потенциал мошенничества при выявлении рисков",
        category="CC3",
    ),
    FrameworkMapping(
        soc2="CC3.4",
        iso27001=("A.5.29", "A.8.2", "A.8.16"),
        nist_800_53=("RA-3", "SA-9", "PM-9"),
        cis_v8=("18.1", "18.2"),
        gdpr=("Art.32(2)", "Art.35"),
        hipaa=("164.308(a)(1)(ii)(A)",),
        pci_dss_v4=("12.3",),
        description="Выявляются и оцениваются изменения, способные существенно повлиять на систему контроля",
        category="CC3",
    ),

    # ── CC4 — Monitoring Activities ───────────────────────────────────────────
    FrameworkMapping(
        soc2="CC4.1",
        iso27001=("A.5.35", "A.5.36", "A.8.16"),
        nist_800_53=("CA-7", "SI-4", "AU-6"),
        cis_v8=("13.1", "13.3"),
        gdpr=("Art.32(1)(d)",),
        hipaa=("164.308(a)(1)(ii)(D)",),
        pci_dss_v4=("10.4", "11.3"),
        description="Проводится непрерывный и/или отдельный мониторинг эффективности контролей",
        category="CC4",
    ),
    FrameworkMapping(
        soc2="CC4.2",
        iso27001=("A.5.35", "A.5.36", "A.6.1"),
        nist_800_53=("CA-5", "CA-7", "PM-4"),
        cis_v8=("13.1", "13.2"),
        gdpr=("Art.32(1)(d)",),
        hipaa=("164.308(a)(1)(ii)(D)",),
        pci_dss_v4=("10.4",),
        description="Недостатки внутреннего контроля своевременно выявляются и передаются ответственным",
        category="CC4",
    ),

    # ── CC5 — Control Activities ───────────────────────────────────────────────
    FrameworkMapping(
        soc2="CC5.1",
        iso27001=("A.5.1", "A.5.37", "A.8.1"),
        nist_800_53=("PL-1", "SA-8", "PM-1"),
        cis_v8=("14.1", "14.2"),
        gdpr=("Art.25", "Art.32"),
        hipaa=("164.316(b)(1)",),
        pci_dss_v4=("12.1",),
        description="Выбираются и разрабатываются контрольные мероприятия для снижения рисков",
        category="CC5",
    ),
    FrameworkMapping(
        soc2="CC5.2",
        iso27001=("A.5.37", "A.8.1", "A.8.8"),
        nist_800_53=("CM-6", "CM-7", "SA-8"),
        cis_v8=("4.1", "4.2", "14.1"),
        gdpr=("Art.25", "Art.32(1)(b)"),
        hipaa=("164.312(b)",),
        pci_dss_v4=("2.2", "6.3"),
        description="Выбираются и разрабатываются общие технологические контроли",
        category="CC5",
    ),
    FrameworkMapping(
        soc2="CC5.3",
        iso27001=("A.5.1", "A.5.37", "A.7.2"),
        nist_800_53=("PM-1", "PL-4", "AT-1"),
        cis_v8=("14.1", "14.2", "14.7"),
        gdpr=("Art.24", "Art.25"),
        hipaa=("164.316(a)",),
        pci_dss_v4=("12.1",),
        description="Политики и процедуры разворачиваются для реализации выбранных контрольных мероприятий",
        category="CC5",
    ),

    # ── CC6 — Logical and Physical Access Controls ─────────────────────────────
    FrameworkMapping(
        soc2="CC6.1",
        iso27001=("A.5.15", "A.5.16", "A.8.2", "A.8.3"),
        nist_800_53=("AC-2", "AC-3", "IA-2", "IA-5"),
        cis_v8=("5.1", "5.2", "6.1", "6.2"),
        gdpr=("Art.32(1)(b)", "Art.24"),
        hipaa=("164.312(a)(1)", "164.312(d)"),
        pci_dss_v4=("7.1", "7.2", "7.3", "8.2"),
        description="Логический доступ к активам ограничен и управляется аутентификацией",
        category="CC6",
    ),
    FrameworkMapping(
        soc2="CC6.2",
        iso27001=("A.5.16", "A.5.18", "A.8.2"),
        nist_800_53=("AC-2", "IA-2", "IA-8"),
        cis_v8=("5.1", "5.2", "6.1"),
        gdpr=("Art.32(1)(b)",),
        hipaa=("164.312(d)",),
        pci_dss_v4=("8.3", "8.4"),
        description="Доступ к информационным активам аутентифицирован перед предоставлением",
        category="CC6",
    ),
    FrameworkMapping(
        soc2="CC6.3",
        iso27001=("A.5.15", "A.5.18", "A.8.2", "A.8.3"),
        nist_800_53=("AC-2", "AC-17", "AC-20", "IA-2"),
        cis_v8=("5.4", "6.1", "6.2", "6.3"),
        gdpr=("Art.32(1)(b)",),
        hipaa=("164.308(a)(3)", "164.308(a)(4)"),
        pci_dss_v4=("7.2",),
        description="Роли и ответственности создаются для управления доступом к системам",
        category="CC6",
    ),
    FrameworkMapping(
        soc2="CC6.4",
        iso27001=("A.7.1", "A.7.2", "A.7.3"),
        nist_800_53=("PE-1", "PE-2", "PE-3"),
        cis_v8=("10.1", "10.2"),
        gdpr=("Art.32(1)(b)",),
        hipaa=("164.310(a)(1)", "164.310(b)"),
        pci_dss_v4=("9.1", "9.2"),
        description="Физический доступ к объектам управляется с мерами по ограничению доступа",
        category="CC6",
    ),
    FrameworkMapping(
        soc2="CC6.5",
        iso27001=("A.5.18", "A.7.3", "A.8.1"),
        nist_800_53=("AC-2", "MP-6", "PE-16"),
        cis_v8=("3.7", "5.3", "6.2"),
        gdpr=("Art.17", "Art.32(1)(b)"),
        hipaa=("164.308(a)(3)(ii)(C)",),
        pci_dss_v4=("8.7",),
        description="Логический и физический доступ прекращается при увольнении или смене ролей",
        category="CC6",
    ),
    FrameworkMapping(
        soc2="CC6.6",
        iso27001=("A.8.20", "A.8.21", "A.8.22"),
        nist_800_53=("SC-7", "CA-3", "AC-17"),
        cis_v8=("12.1", "12.2", "13.4"),
        gdpr=("Art.32(1)(b)", "Art.46"),
        hipaa=("164.312(e)(1)",),
        pci_dss_v4=("1.3", "1.4"),
        description="Логический доступ защищается от угроз за пределами системных границ",
        category="CC6",
    ),
    FrameworkMapping(
        soc2="CC6.7",
        iso27001=("A.8.10", "A.8.11", "A.8.12"),
        nist_800_53=("MP-2", "MP-3", "MP-5", "MP-6"),
        cis_v8=("3.6", "3.7", "10.2"),
        gdpr=("Art.32(1)(a)", "Art.46"),
        hipaa=("164.312(e)(2)(ii)",),
        pci_dss_v4=("4.2",),
        description="Ограничения применяются к передаче информации для защиты от несанкционированного доступа",
        category="CC6",
    ),
    FrameworkMapping(
        soc2="CC6.8",
        iso27001=("A.8.7", "A.8.8", "A.8.16"),
        nist_800_53=("SI-3", "SI-4", "SI-7"),
        cis_v8=("10.1", "10.5", "13.2"),
        gdpr=("Art.32(1)(b)",),
        hipaa=("164.308(a)(5)(ii)(B)",),
        pci_dss_v4=("5.1", "5.2", "5.3"),
        description="Предотвращение, обнаружение и устранение вредоносного ПО",
        category="CC6",
    ),

    # ── CC7 — System Operations ────────────────────────────────────────────────
    FrameworkMapping(
        soc2="CC7.1",
        iso27001=("A.8.8", "A.8.16", "A.8.19"),
        nist_800_53=("CM-2", "CM-6", "SI-2"),
        cis_v8=("2.1", "2.2", "7.4"),
        gdpr=("Art.25", "Art.32"),
        hipaa=("164.312(b)",),
        pci_dss_v4=("2.2", "6.3", "6.4"),
        description="Эталонные конфигурации разработаны, внедрены и управляются",
        category="CC7",
    ),
    FrameworkMapping(
        soc2="CC7.2",
        iso27001=("A.8.15", "A.8.16", "A.5.28"),
        nist_800_53=("AU-6", "IR-4", "SI-4"),
        cis_v8=("8.1", "8.2", "13.1", "13.2"),
        gdpr=("Art.32(1)(d)",),
        hipaa=("164.308(a)(1)(ii)(D)",),
        pci_dss_v4=("10.4", "10.7"),
        description="Ведётся мониторинг системных компонентов для обнаружения аномалий и инцидентов",
        category="CC7",
    ),
    FrameworkMapping(
        soc2="CC7.3",
        iso27001=("A.5.26", "A.5.28", "A.6.8"),
        nist_800_53=("IR-4", "IR-5", "IR-6"),
        cis_v8=("17.1", "17.2", "17.4"),
        gdpr=("Art.33", "Art.34"),
        hipaa=("164.308(a)(6)(i)",),
        pci_dss_v4=("12.10",),
        description="События безопасности оцениваются и определяются как инциденты безопасности",
        category="CC7",
    ),
    FrameworkMapping(
        soc2="CC7.4",
        iso27001=("A.5.26", "A.5.27", "A.6.8"),
        nist_800_53=("IR-4", "IR-5", "IR-7", "IR-8"),
        cis_v8=("17.1", "17.3", "17.4", "17.6"),
        gdpr=("Art.33", "Art.34"),
        hipaa=("164.308(a)(6)", "164.308(a)(6)(ii)"),
        pci_dss_v4=("12.10", "12.10.2"),
        description="Инциденты безопасности идентифицируются, реагирование задокументировано и уведомления направлены",
        category="CC7",
    ),
    FrameworkMapping(
        soc2="CC7.5",
        iso27001=("A.5.26", "A.5.27", "A.8.16"),
        nist_800_53=("IR-4", "CA-5", "RA-5"),
        cis_v8=("17.3", "17.4", "17.8"),
        gdpr=("Art.32(1)(c)",),
        hipaa=("164.308(a)(6)(ii)",),
        pci_dss_v4=("12.10.5",),
        description="Выявленные инциденты устраняются, а причины анализируются для предотвращения повторения",
        category="CC7",
    ),

    # ── CC8 — Change Management ────────────────────────────────────────────────
    FrameworkMapping(
        soc2="CC8.1",
        iso27001=("A.8.19", "A.8.32", "A.8.33"),
        nist_800_53=("CM-3", "CM-4", "CM-5", "SA-10"),
        cis_v8=("2.5", "4.1", "16.1", "16.2"),
        gdpr=("Art.25", "Art.32"),
        hipaa=("164.312(c)(1)",),
        pci_dss_v4=("6.5",),
        description="Управление изменениями инфраструктуры, данных, ПО и процедур",
        category="CC8",
    ),

    # ── CC9 — Risk Mitigation ──────────────────────────────────────────────────
    FrameworkMapping(
        soc2="CC9.1",
        iso27001=("A.5.29", "A.5.30", "A.8.14"),
        nist_800_53=("CP-2", "RA-3", "PM-9"),
        cis_v8=("11.1", "11.2", "11.3"),
        gdpr=("Art.32(1)(c)",),
        hipaa=("164.308(a)(7)",),
        pci_dss_v4=("12.3.4",),
        description="Организация выявляет и оценивает риски от прерывания бизнеса и стратегии реагирования",
        category="CC9",
    ),
    FrameworkMapping(
        soc2="CC9.2",
        iso27001=("A.5.19", "A.5.20", "A.5.21", "A.5.22"),
        nist_800_53=("SA-9", "SR-1", "SR-2", "SR-3"),
        cis_v8=("15.1", "15.2", "15.3"),
        gdpr=("Art.28", "Art.29"),
        hipaa=("164.308(b)(1)",),
        pci_dss_v4=("12.8",),
        description="Управление рисками со стороны поставщиков и деловых партнёров",
        category="CC9",
    ),

    # ── A — Availability ───────────────────────────────────────────────────────
    FrameworkMapping(
        soc2="A1.1",
        iso27001=("A.5.29", "A.5.30", "A.8.14"),
        nist_800_53=("CP-2", "CP-7", "CP-9"),
        cis_v8=("11.1", "11.2"),
        gdpr=("Art.32(1)(b)", "Art.32(1)(c)"),
        hipaa=("164.308(a)(7)(ii)(C)",),
        pci_dss_v4=("12.3.3",),
        description="Плановые и нормативные требования к доступности задокументированы",
        category="A",
    ),
    FrameworkMapping(
        soc2="A1.2",
        iso27001=("A.8.14", "A.8.15", "A.5.29"),
        nist_800_53=("CP-2", "CP-9", "CA-7"),
        cis_v8=("11.1", "11.3"),
        gdpr=("Art.32(1)(b)", "Art.32(1)(c)"),
        hipaa=("164.308(a)(7)",),
        pci_dss_v4=("12.3",),
        description="Мощность среды управляется и отслеживается для достижения целей доступности",
        category="A",
    ),
    FrameworkMapping(
        soc2="A1.3",
        iso27001=("A.5.29", "A.5.30", "A.8.14"),
        nist_800_53=("CP-4", "CP-9", "IR-3"),
        cis_v8=("11.1", "11.4"),
        gdpr=("Art.32(1)(c)",),
        hipaa=("164.308(a)(7)(ii)(D)",),
        pci_dss_v4=("12.3",),
        description="Процедуры восстановления тестируются для соответствия требованиям доступности",
        category="A",
    ),

    # ── PI — Processing Integrity ──────────────────────────────────────────────
    FrameworkMapping(
        soc2="PI1.1",
        iso27001=("A.8.4", "A.8.5", "A.8.9"),
        nist_800_53=("SI-10", "SI-12", "AU-12"),
        cis_v8=("3.3", "8.3"),
        gdpr=("Art.5(1)(d)", "Art.22"),
        hipaa=("164.312(c)(1)",),
        pci_dss_v4=("6.4",),
        description="Политики и процедуры обработки реализованы для соответствия требованиям",
        category="PI",
    ),

    # ── C — Confidentiality ────────────────────────────────────────────────────
    FrameworkMapping(
        soc2="C1.1",
        iso27001=("A.5.12", "A.5.13", "A.8.11"),
        nist_800_53=("AC-3", "AU-9", "SC-28"),
        cis_v8=("3.3", "3.11"),
        gdpr=("Art.5(1)(f)", "Art.32(1)(a)"),
        hipaa=("164.312(a)(2)(iv)", "164.514"),
        pci_dss_v4=("3.2", "3.3"),
        description="Конфиденциальная информация идентифицируется и классифицируется",
        category="C",
    ),
    FrameworkMapping(
        soc2="C1.2",
        iso27001=("A.5.12", "A.5.13", "A.8.3", "A.8.10"),
        nist_800_53=("MP-3", "SC-28", "AC-3"),
        cis_v8=("3.3", "3.7"),
        gdpr=("Art.5(1)(e)", "Art.17"),
        hipaa=("164.310(d)(2)(i)", "164.312(a)(2)(iii)"),
        pci_dss_v4=("3.2",),
        description="Конфиденциальная информация удаляется по окончании срока хранения",
        category="C",
    ),

    # ── P — Privacy ────────────────────────────────────────────────────────────
    FrameworkMapping(
        soc2="P1.1",
        iso27001=("A.5.31", "A.5.34", "A.5.11"),
        nist_800_53=("PT-1", "PT-2", "AP-1"),
        cis_v8=("3.3",),
        gdpr=("Art.12", "Art.13", "Art.14"),
        hipaa=("164.520",),
        pci_dss_v4=("12.9",),
        description="Уведомление о конфиденциальности предоставляется субъектам данных",
        category="P",
    ),
]

# Быстрый индекс: soc2_id → FrameworkMapping
_SOC2_INDEX: dict[str, FrameworkMapping] = {m.soc2: m for m in CONTROL_MAPPINGS}

# Быстрый индекс: iso_id → list[soc2_id]
_ISO_INDEX: dict[str, list[str]] = {}
for _m in CONTROL_MAPPINGS:
    for _iso in _m.iso27001:
        _ISO_INDEX.setdefault(_iso, []).append(_m.soc2)

# Быстрый индекс: nist_id → list[soc2_id]
_NIST_INDEX: dict[str, list[str]] = {}
for _m in CONTROL_MAPPINGS:
    for _nist in _m.nist_800_53:
        _NIST_INDEX.setdefault(_nist, []).append(_m.soc2)

# Быстрый индекс: cis_id → list[soc2_id]
_CIS_INDEX: dict[str, list[str]] = {}
for _m in CONTROL_MAPPINGS:
    for _cis in _m.cis_v8:
        _CIS_INDEX.setdefault(_cis, []).append(_m.soc2)

# Быстрый индекс: gdpr_id → list[soc2_id]
_GDPR_INDEX: dict[str, list[str]] = {}
for _m in CONTROL_MAPPINGS:
    for _gdpr in _m.gdpr:
        _GDPR_INDEX.setdefault(_gdpr, []).append(_m.soc2)

# Быстрый индекс: hipaa_id → list[soc2_id]
_HIPAA_INDEX: dict[str, list[str]] = {}
for _m in CONTROL_MAPPINGS:
    for _hipaa in _m.hipaa:
        _HIPAA_INDEX.setdefault(_hipaa, []).append(_m.soc2)

# Быстрый индекс: pci_id → list[soc2_id]
_PCI_INDEX: dict[str, list[str]] = {}
for _m in CONTROL_MAPPINGS:
    for _pci in _m.pci_dss_v4:
        _PCI_INDEX.setdefault(_pci, []).append(_m.soc2)


# ── Поддерживаемые фреймворки ─────────────────────────────────────────────────

SUPPORTED_FRAMEWORKS: list[dict] = [
    {
        "id": "soc2",
        "name": "SOC 2 TSC 2017",
        "version": "Trust Services Criteria 2017 (updated 2022)",
        "total_controls": len(CONTROL_MAPPINGS),
    },
    {
        "id": "iso27001",
        "name": "ISO/IEC 27001:2022",
        "version": "Annex A controls",
        "total_controls": len(_ISO_INDEX),
    },
    {
        "id": "nist_800_53",
        "name": "NIST SP 800-53 Rev 5",
        "version": "Rev 5 (September 2020)",
        "total_controls": len(_NIST_INDEX),
    },
    {
        "id": "cis_v8",
        "name": "CIS Controls v8",
        "version": "v8.0 (2021)",
        "total_controls": len(_CIS_INDEX),
    },
    {
        "id": "gdpr",
        "name": "EU GDPR",
        "version": "Regulation (EU) 2016/679",
        "total_controls": len(_GDPR_INDEX),
    },
    {
        "id": "hipaa",
        "name": "HIPAA Security Rule",
        "version": "45 CFR Part 164",
        "total_controls": len(_HIPAA_INDEX),
    },
    {
        "id": "pci_dss_v4",
        "name": "PCI DSS v4.0",
        "version": "v4.0.1 (2022)",
        "total_controls": len(_PCI_INDEX),
    },
]


# ── Engine ─────────────────────────────────────────────────────────────────────

class ControlMappingEngine:
    """Движок запросов к графу соответствий между фреймворками.

    Все данные хранятся как immutable dataclass-объекты в памяти —
    никакого I/O нет, engine безопасен для параллельного использования.
    """

    # ── Основные lookup-методы ─────────────────────────────────────────────

    def get_all_mappings(self) -> list[FrameworkMapping]:
        """Вернуть все маппинги (неизменяемые объекты)."""
        return list(CONTROL_MAPPINGS)

    def get_mappings_for_control(self, soc2_id: str) -> Optional[FrameworkMapping]:
        """Маппинг для конкретного SOC 2 контроля. None — если не найден."""
        return _SOC2_INDEX.get(soc2_id)

    def get_soc2_for_iso(self, iso_id: str) -> list[str]:
        """Какие SOC 2 контролы покрывает указанный ISO 27001 ID."""
        return list(_ISO_INDEX.get(iso_id, []))

    def get_soc2_for_nist(self, nist_id: str) -> list[str]:
        """Какие SOC 2 контролы покрывает указанный NIST 800-53 ID."""
        return list(_NIST_INDEX.get(nist_id, []))

    def get_soc2_for_cis(self, cis_id: str) -> list[str]:
        """Какие SOC 2 контролы покрывает указанный CIS v8 ID."""
        return list(_CIS_INDEX.get(cis_id, []))

    def get_soc2_for_gdpr(self, gdpr_id: str) -> list[str]:
        """Какие SOC 2 контролы покрывает указанный GDPR артикул (например Art.32)."""
        return list(_GDPR_INDEX.get(gdpr_id, []))

    def get_soc2_for_hipaa(self, hipaa_id: str) -> list[str]:
        """Какие SOC 2 контролы покрывает указанный HIPAA CFR ref (например 164.312(a)(1))."""
        return list(_HIPAA_INDEX.get(hipaa_id, []))

    def get_soc2_for_pci(self, pci_id: str) -> list[str]:
        """Какие SOC 2 контролы покрывает указанный PCI DSS v4 ref (например 8.3)."""
        return list(_PCI_INDEX.get(pci_id, []))

    # ── Поиск ─────────────────────────────────────────────────────────────

    def search(self, query: str) -> list[FrameworkMapping]:
        """Поиск по любому ID или описанию (case-insensitive substring).

        Ищет совпадения в: soc2, iso27001[], nist_800_53[], cis_v8[], description.
        """
        q = query.strip().upper()
        results: list[FrameworkMapping] = []
        for m in CONTROL_MAPPINGS:
            if (
                q in m.soc2.upper()
                or any(q in x.upper() for x in m.iso27001)
                or any(q in x.upper() for x in m.nist_800_53)
                or any(q in x.upper() for x in m.cis_v8)
                or any(q in x.upper() for x in m.gdpr)
                or any(q in x.upper() for x in m.hipaa)
                or any(q in x.upper() for x in m.pci_dss_v4)
                or q in m.description.upper()
                or q in m.category.upper()
            ):
                results.append(m)
        return results

    # ── Отчёт покрытия ─────────────────────────────────────────────────────

    def get_coverage_report(self) -> dict:
        """Статистика покрытия каждого фреймворка.

        Возвращает:
          - total_soc2_controls: общее число SOC 2 контролей
          - по каждому фреймворку: уникальные mapped IDs, процент покрытия
        """
        total = len(CONTROL_MAPPINGS)

        all_iso: set[str] = set()
        all_nist: set[str] = set()
        all_cis: set[str] = set()
        all_gdpr: set[str] = set()
        all_hipaa: set[str] = set()
        all_pci: set[str] = set()
        soc2_with_iso = soc2_with_nist = soc2_with_cis = 0
        soc2_with_gdpr = soc2_with_hipaa = soc2_with_pci = 0

        for m in CONTROL_MAPPINGS:
            all_iso.update(m.iso27001)
            all_nist.update(m.nist_800_53)
            all_cis.update(m.cis_v8)
            all_gdpr.update(m.gdpr)
            all_hipaa.update(m.hipaa)
            all_pci.update(m.pci_dss_v4)
            if m.iso27001:
                soc2_with_iso += 1
            if m.nist_800_53:
                soc2_with_nist += 1
            if m.cis_v8:
                soc2_with_cis += 1
            if m.gdpr:
                soc2_with_gdpr += 1
            if m.hipaa:
                soc2_with_hipaa += 1
            if m.pci_dss_v4:
                soc2_with_pci += 1

        def _pct(n: int) -> float:
            return round(n / total * 100, 1) if total else 0.0

        return {
            "total_soc2_controls": total,
            "generated_at": _now_iso(),
            "frameworks": {
                "soc2": {
                    "name": "SOC 2 TSC 2017",
                    "total_controls": total,
                    "coverage_pct": 100.0,
                },
                "iso27001": {
                    "name": "ISO/IEC 27001:2022",
                    "unique_mapped_controls": len(all_iso),
                    "soc2_controls_with_mapping": soc2_with_iso,
                    "coverage_pct": _pct(soc2_with_iso),
                },
                "nist_800_53": {
                    "name": "NIST SP 800-53 Rev 5",
                    "unique_mapped_controls": len(all_nist),
                    "soc2_controls_with_mapping": soc2_with_nist,
                    "coverage_pct": _pct(soc2_with_nist),
                },
                "cis_v8": {
                    "name": "CIS Controls v8",
                    "unique_mapped_controls": len(all_cis),
                    "soc2_controls_with_mapping": soc2_with_cis,
                    "coverage_pct": _pct(soc2_with_cis),
                },
                "gdpr": {
                    "name": "EU GDPR (2016/679)",
                    "unique_mapped_controls": len(all_gdpr),
                    "soc2_controls_with_mapping": soc2_with_gdpr,
                    "coverage_pct": _pct(soc2_with_gdpr),
                },
                "hipaa": {
                    "name": "HIPAA Security Rule (45 CFR 164)",
                    "unique_mapped_controls": len(all_hipaa),
                    "soc2_controls_with_mapping": soc2_with_hipaa,
                    "coverage_pct": _pct(soc2_with_hipaa),
                },
                "pci_dss_v4": {
                    "name": "PCI DSS v4.0",
                    "unique_mapped_controls": len(all_pci),
                    "soc2_controls_with_mapping": soc2_with_pci,
                    "coverage_pct": _pct(soc2_with_pci),
                },
            },
        }

    def get_supported_frameworks(self) -> list[dict]:
        """Список поддерживаемых фреймворков с мета-информацией."""
        return list(SUPPORTED_FRAMEWORKS)

    def enrich_with_ontology(self, soc2_id: str) -> dict:
        """
        Обогащает FrameworkMapping семантикой из онтологии.

        Берёт данные маппинга для контроля soc2_id и дополняет их
        полной семантикой из ControlOntology: risk_weight, evidence_types,
        требования, SLA, шаги устранения, категория.

        Args:
            soc2_id: идентификатор SOC 2 контроля, например "CC6.1"

        Returns:
            Словарь с объединёнными данными FrameworkMapping и ControlOntology.
            Если контроль не найден ни в одном источнике — возвращает пустой dict.
            Если онтология недоступна — возвращает только данные из mapping.
        """
        # Получаем базовый маппинг фреймворков
        mapping = self.get_mappings_for_control(soc2_id)
        if mapping is None:
            return {}

        result: dict = {
            "soc2": mapping.soc2,
            "description": mapping.description,
            "category": mapping.category,
            "iso27001": list(mapping.iso27001),
            "nist_800_53": list(mapping.nist_800_53),
            "cis_v8": list(mapping.cis_v8),
        }

        # Дополняем данными из онтологии (если доступна)
        try:
            from compliance_ontology import get_ontology_engine
            engine = get_ontology_engine()
            ctrl = engine.get_control(soc2_id)
            if ctrl is not None:
                result.update({
                    "title": ctrl.title,
                    "risk_weight": ctrl.risk_weight,
                    "sla_hours": ctrl.sla_hours,
                    "evidence_types": list(ctrl.evidence_types),
                    "requires": list(ctrl.requires),
                    "auto_remediable": ctrl.auto_remediable,
                    "owner_role": ctrl.owner_role,
                    "audit_frequency": ctrl.audit_frequency,
                    "remediation_steps": list(ctrl.remediation_steps),
                    "ontology_enriched": True,
                })
            else:
                result["ontology_enriched"] = False
        except Exception:
            # Если онтология не загружена — возвращаем базовый маппинг
            result["ontology_enriched"] = False

        return result


# ── Вспомогательные функции ────────────────────────────────────────────────────

def _now_iso() -> str:
    """Текущее время UTC в ISO 8601."""
    return datetime.now(timezone.utc).isoformat()


# ── Thread-safe singleton для использования в роутерах ────────────────────────

_engine: Optional[ControlMappingEngine] = None


def get_engine() -> ControlMappingEngine:
    """Получить singleton ControlMappingEngine (thread-safe ленивая инициализация).

    ControlMappingEngine не имеет изменяемого состояния, поэтому singleton
    безопасен для чтения из множества потоков FastAPI без доп. блокировок.
    Lock используется только при первом создании экземпляра.
    """
    global _engine
    if _engine is None:
        with _LOCK:
            if _engine is None:  # double-checked locking
                _engine = ControlMappingEngine()
    return _engine
