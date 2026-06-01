"""
Gap Analysis Agent — AI-анализ несоответствий SOC 2 контролей.

Аналог Vanta AI Recommendations: для каждого FAIL-контроля генерирует
конкретный plan действий с приоритетом и оценкой трудозатрат.
"""

import os
import json
import time
import logging
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

from openai import OpenAI, RateLimitError
from dotenv import load_dotenv

from evidence_client import EvidenceClient
from constants import CONTROLS_MAP_FILE
from ai_decision_log import get_decision_logger, DecisionType

load_dotenv()

# ── Настройки LLM (тот же паттерн что в policy_agent.py) ─────────────────────
_INTER_REQUEST_DELAY = float(os.getenv("POLICY_REQUEST_DELAY", "4.0"))
_RATE_LIMIT_RETRIES  = 4
_RATE_LIMIT_BACKOFF  = [10, 30, 60, 120]

OPENROUTER_API_KEY  = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_MODEL    = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku")
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")

# Файл кеша — рядом со скриптом, с fallback на /tmp если нет прав на запись
_default_gap_cache = Path(__file__).parent / "gap_analysis_cache.json"
GAP_CACHE_FILE = (
    Path("/tmp/gap_analysis_cache.json")
    if _default_gap_cache.exists() and not os.access(_default_gap_cache, os.W_OK)
    else _default_gap_cache
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class GapAnalysisAgent:
    """Агент анализа несоответствий SOC 2 контролей через LLM."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        # Создаём клиент OpenRouter (тот же паттерн, что в PolicyAgent)
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key or OPENROUTER_API_KEY,
            default_headers={
                "HTTP-Referer": "compliance-sandbox",
                "X-Title":      "Compliance Sandbox Gap Analysis",
            },
        )
        self.model = model or OPENROUTER_MODEL
        self._evidence_client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="gap_analysis")

    # ── Загрузка данных из Evidence Tracker ───────────────────────────────────

    def _load_controls_map(self) -> dict:
        """Читает controls_map.json → {code: uuid}."""
        if not Path(CONTROLS_MAP_FILE).exists():
            raise FileNotFoundError(f"{CONTROLS_MAP_FILE} не найден. Запустите controls_seed.py.")
        with open(CONTROLS_MAP_FILE, "r") as f:
            return json.load(f)

    def _get_fail_controls(self) -> list[dict]:
        """Возвращает список контролей со статусом FAIL из Evidence Tracker."""
        try:
            controls = self._evidence_client.get_controls()
            return [c for c in controls if c.get("status", "").upper() == "FAIL"]
        except Exception as exc:
            logger.warning(f"Не удалось получить контроли: {exc}")
            return []

    def _get_evidences_for_control(self, control_id: str) -> list[dict]:
        """Возвращает список evidence для одного контроля."""
        try:
            return self._evidence_client.get_evidence(control_id=control_id, limit=20)
        except Exception as exc:
            logger.warning(f"Не удалось получить evidence для {control_id}: {exc}")
            return []

    # ── Формирование промта ───────────────────────────────────────────────────

    def _build_prompt(self, control_code: str, control_title: str, control_desc: str, evidences: list[dict]) -> str:
        """Строит промт для LLM с контекстом контроля и его evidence."""

        # Формируем краткое резюме evidence (берём title + source, не весь контент)
        ev_summary_lines = []
        for ev in evidences[:10]:
            title  = ev.get("title", "N/A")
            source = ev.get("source", "UNKNOWN")
            ev_summary_lines.append(f"  - [{source}] {title}")
        ev_summary = "\n".join(ev_summary_lines) if ev_summary_lines else "  (нет собранных evidence)"

        prompt = f"""You are a senior SOC 2 compliance engineer performing a gap analysis.

A SOC 2 control is currently FAILING and needs a concrete remediation plan.

CONTROL INFORMATION:
- Control ID: {control_code}
- Title: {control_title}
- Requirement: {control_desc}

COLLECTED EVIDENCE (showing what was found/tested):
{ev_summary}

Your task: analyze why this control is likely failing based on the control requirements and evidence, then provide a concrete, actionable remediation plan.

IMPORTANT: Respond ONLY with a valid JSON object. No markdown, no explanation, no code fences. Just the raw JSON.

Required JSON structure:
{{
  "gap_description": "2-3 sentence description of what specific gap or deficiency causes this control to fail",
  "actions": [
    "Concrete action step 1 (specific command, configuration, or task — not vague)",
    "Concrete action step 2",
    "Concrete action step 3",
    "Verification step to confirm the fix"
  ],
  "priority": "critical",
  "estimated_days": 3
}}

Rules:
- priority must be exactly one of: "critical", "high", "medium"
- Use "critical" if the gap exposes customer data or blocks authentication
- Use "high" if the gap violates a key technical control (MFA, encryption, access review)
- Use "medium" if the gap is procedural or governance-related
- estimated_days: realistic integer (1–30) based on complexity
- actions: 3–6 items, each specific (e.g. "Run: aws iam enable-mfa-device ...", "Configure Okta MFA policy to require TOTP for all users", "Update GitHub branch protection to require 1 reviewer approval")
- gap_description: be specific about what is missing or broken, not generic"""

        return prompt

    # ── LLM вызов с retry (паттерн из policy_agent.py) ───────────────────────

    def _call_llm(self, prompt: str, control_code: str) -> str:
        """Отправляет запрос в OpenRouter с обработкой rate limit."""
        for attempt, wait in enumerate(_RATE_LIMIT_BACKOFF):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,   # низкая температура — нам нужны факты, не фантазии
                )
                return response.choices[0].message.content
            except RateLimitError as exc:
                if attempt == len(_RATE_LIMIT_BACKOFF) - 1:
                    raise
                logger.warning(
                    f"Rate limit для {control_code} (попытка {attempt + 1}), "
                    f"ждём {wait}с..."
                )
                time.sleep(wait)

        # Сюда никогда не доходим, но для mypy:
        raise RuntimeError("Все попытки вызова LLM исчерпаны")

    def _parse_llm_response(self, raw: str, control_code: str) -> dict:
        """Парсит JSON из ответа LLM, возвращает дефолтную структуру при ошибке."""
        # Убираем возможные markdown-блоки ```json ... ```
        text = raw.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            # Отрезаем первую и последнюю строку (``` маркеры)
            text = "\n".join(lines[1:-1] if lines[-1].startswith("```") else lines[1:])

        try:
            data = json.loads(text)
            # Валидируем обязательные поля
            if not isinstance(data.get("actions"), list):
                data["actions"] = ["Проверить конфигурацию контроля вручную"]
            if data.get("priority") not in ("critical", "high", "medium"):
                data["priority"] = "high"
            if not isinstance(data.get("estimated_days"), int):
                data["estimated_days"] = 7
            return data
        except json.JSONDecodeError as exc:
            logger.error(f"Не удалось разобрать JSON для {control_code}: {exc}\nОтвет LLM: {raw[:300]}")
            return {
                "gap_description": f"Автоматический анализ не выполнен — ошибка парсинга ответа LLM. Проверьте {control_code} вручную.",
                "actions": [
                    "Проверить evidence для контроля в Evidence Tracker",
                    "Изучить требования контроля в AICPA TSC",
                    "Связаться с ответственным за контроль",
                ],
                "priority": "high",
                "estimated_days": 7,
            }

    # ── Публичные методы ──────────────────────────────────────────────────────

    async def analyze_control(self, control_id: str, evidences: list) -> dict:
        """
        Анализирует один контроль + его evidence → план устранения.

        Args:
            control_id: UUID контроля (не код CC6.1, а UUID из Evidence Tracker)
            evidences: список evidence dict из EvidenceClient

        Returns:
            dict с полями: control_id, control_code, gap_description, actions, priority, estimated_days
        """
        # Находим код контроля по его UUID
        controls_map = self._load_controls_map()
        code_by_id   = {v: k for k, v in controls_map.items()}
        control_code = code_by_id.get(control_id, control_id)

        # Получаем метаданные контроля из Evidence Tracker
        try:
            all_controls = self._evidence_client.get_controls()
            ctrl_meta    = next((c for c in all_controls if str(c["id"]) == control_id), {})
        except Exception:
            ctrl_meta = {}

        ctrl_title = ctrl_meta.get("title", control_code)
        ctrl_desc  = ctrl_meta.get("description", "SOC 2 control requirement")

        logger.info(f"[GapAnalysis] Анализируем {control_code}: {ctrl_title}")

        if not OPENROUTER_API_KEY:
            logger.warning(f"[GapAnalysis] API key not found. Using mock data for {control_code}")
            return {
                "control_id":       control_id,
                "control_code":     control_code,
                "control_title":    ctrl_title,
                "gap_description":  "Control requires manual configuration — API key not configured for AI analysis",
                "actions":          ["Configure OPENROUTER_API_KEY in .env", "Re-run gap analysis"],
                "priority":         "medium",
                "estimated_days":   1,
            }

        # ── Вызов через AIAdvisor (advisory path) ─────────────────────────────
        # GapAnalysisAgent делегирует LLM-вызов через AIAdvisor,
        # явно обозначая что результат является рекомендацией (advisory).
        try:
            from ai_advisor import AIAdvisor
            advisor = AIAdvisor(api_key=OPENROUTER_API_KEY, model=self.model)
            gap_summary = f"{ctrl_title}: {ctrl_desc}"
            evidence_ids_for_advisor = [str(ev.get("id", "")) for ev in evidences[:10] if ev.get("id")]
            advice = advisor.suggest_remediation(
                control_id=control_code,
                gap_description=gap_summary,
                evidence_ids=evidence_ids_for_advisor,
            )
            # Парсим структурированный ответ из advice.suggestion
            prompt   = self._build_prompt(control_code, ctrl_title, ctrl_desc, evidences)
            _t0 = time.time()
            raw_resp = self._call_llm(prompt, control_code)
            _duration_ms = int((time.time() - _t0) * 1000)
            parsed   = self._parse_llm_response(raw_resp, control_code)
            is_advisory = True
        except ImportError:
            # Fallback если ai_advisor не доступен
            prompt   = self._build_prompt(control_code, ctrl_title, ctrl_desc, evidences)
            _t0 = time.time()
            raw_resp = self._call_llm(prompt, control_code)
            _duration_ms = int((time.time() - _t0) * 1000)
            parsed   = self._parse_llm_response(raw_resp, control_code)
            is_advisory = False
            evidence_ids_for_advisor = [str(ev.get("id", "")) for ev in evidences[:10] if ev.get("id")]

        outcome = f"priority:{parsed.get('priority', 'high')}"
        try:
            get_decision_logger().record(
                decision_type=DecisionType.GAP_ANALYSIS,
                model=self.model,
                prompt=prompt[:500],
                output=raw_resp,
                outcome=outcome,
                control_id=control_code,
                evidence_used=evidence_ids_for_advisor,
                duration_ms=_duration_ms,
                metadata={
                    "estimated_days": parsed.get("estimated_days", 7),
                    "is_advisory": True,  # явный маркер advisory
                },
            )
        except Exception as _log_exc:
            logger.warning("AI decision log failed: %s", _log_exc)

        return {
            "control_id":       control_id,
            "control_code":     control_code,
            "control_title":    ctrl_title,
            "gap_description":  parsed.get("gap_description", ""),
            "actions":          parsed.get("actions", []),
            "priority":         parsed.get("priority", "high"),
            "estimated_days":   parsed.get("estimated_days", 7),
            "is_advisory":      True,   # результат gap_analysis всегда advisory
            "advisory_disclaimer": "AI suggestion — requires human review",
        }

    async def run_full_analysis(self) -> dict:
        """
        Анализирует все FAIL-контроли → полный gap report.

        Returns:
            dict с полями: generated_at, model, total_fail, gaps (list)
        """
        logger.info("[GapAnalysis] Начинаем полный анализ всех FAIL-контролей")

        fail_controls = self._get_fail_controls()
        if not fail_controls:
            logger.info("[GapAnalysis] Нет FAIL-контролей — анализ завершён")
            return {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "model":        self.model,
                "total_fail":   0,
                "gaps":         [],
            }

        logger.info(f"[GapAnalysis] Найдено FAIL-контролей: {len(fail_controls)}")

        gaps = []
        for ctrl in fail_controls:
            control_id   = str(ctrl["id"])
            evidences    = self._get_evidences_for_control(control_id)

            try:
                gap = await self.analyze_control(control_id, evidences)
                gaps.append(gap)
                logger.info(f"[GapAnalysis] {gap['control_code']} → {gap['priority'].upper()}, {gap['estimated_days']} дней")
            except Exception as exc:
                logger.error(f"[GapAnalysis] Ошибка анализа {control_id}: {exc}")
                # Добавляем заглушку, чтобы не потерять контроль из отчёта
                gaps.append({
                    "control_id":      control_id,
                    "control_code":    ctrl.get("code", control_id),
                    "control_title":   ctrl.get("title", ""),
                    "gap_description": f"Анализ не выполнен из-за ошибки: {exc}",
                    "actions":         ["Повторить анализ вручную"],
                    "priority":        "high",
                    "estimated_days":  7,
                })

            # Пауза между запросами — соблюдаем rate limit OpenRouter
            time.sleep(_INTER_REQUEST_DELAY)

        # Сортируем по приоритету: critical → high → medium
        priority_order = {"critical": 0, "high": 1, "medium": 2}
        gaps.sort(key=lambda g: priority_order.get(g["priority"], 9))

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model":        self.model,
            "total_fail":   len(fail_controls),
            "gaps":         gaps,
        }

        logger.info(f"[GapAnalysis] Анализ завершён: {len(gaps)} контролей обработано")
        return report


# ── Утилиты кеширования ────────────────────────────────────────────────────────

def load_cache() -> Optional[dict]:
    """Загружает кешированный результат из gap_analysis_cache.json."""
    if not GAP_CACHE_FILE.exists():
        return None
    try:
        with open(GAP_CACHE_FILE, "r") as f:
            return json.load(f)
    except Exception as exc:
        logger.warning(f"Не удалось прочитать кеш: {exc}")
        return None


def save_cache(report: dict) -> None:
    """Сохраняет отчёт в gap_analysis_cache.json."""
    try:
        with open(GAP_CACHE_FILE, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info(f"[GapAnalysis] Кеш сохранён: {GAP_CACHE_FILE}")
    except Exception as exc:
        logger.error(f"Не удалось сохранить кеш: {exc}")
