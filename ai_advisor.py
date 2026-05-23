"""
ai_advisor.py — Advisory-обёртка для AI в compliance-системе.

Явно разделяет роли: AI = советник (advisor), не authority.
Все методы возвращают AIAdvice с дисклеймером о необходимости human review.

Ключевые инварианты:
  1. AIAdvisor НИКОГДА не меняет статус контролей напрямую.
  2. Каждый вызов логируется через AIDecisionLogger.
  3. Флаг is_advisory_only=True присутствует в каждом ответе.
  4. ComplianceEngine не используется внутри AIAdvisor для определения статусов.
"""

from __future__ import annotations

import time
import os
from dataclasses import dataclass, field
from typing import Optional

from log_config import get_logger
from ai_decision_log import get_decision_logger, DecisionType

log = get_logger(__name__)

# Дисклеймер по умолчанию — добавляется ко всем AI-советам
_DEFAULT_DISCLAIMER = "AI suggestion — requires human review"

# Конфиг LLM (используется только если нет mock-режима)
_OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
_OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku")


# ── Dataclass для AI-советов ────────────────────────────────────────────────────

@dataclass
class AIAdvice:
    """
    Контейнер для AI-рекомендации.

    Поле is_advisory_only всегда True — это архитектурный инвариант.
    AI не является authority: его совет требует human approval.
    """
    suggestion:      str
    confidence:      float                  # 0.0–1.0 (эвристическая оценка)
    reasoning:       str
    advice_type:     str                    # "remediation" | "policy_draft" | "explanation" | "risk_priority"
    control_id:      Optional[str] = None
    disclaimer:      str = _DEFAULT_DISCLAIMER
    is_advisory_only: bool = True           # ВСЕГДА True — не менять!
    metadata:        dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "suggestion":       self.suggestion,
            "confidence":       self.confidence,
            "reasoning":        self.reasoning,
            "advice_type":      self.advice_type,
            "control_id":       self.control_id,
            "disclaimer":       self.disclaimer,
            "is_advisory_only": self.is_advisory_only,
            "metadata":         self.metadata,
        }


# ── AI Advisor ──────────────────────────────────────────────────────────────────

class AIAdvisor:
    """
    Советник на основе AI для compliance-системы.

    Предоставляет рекомендации по устранению несоответствий, черновики политик,
    объяснения находок и приоритизацию рисков.

    НЕ МЕНЯЕТ состояние контролей или evidence напрямую.
    НЕ ЯВЛЯЕТСЯ authority — только советник (advisor).
    """

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        self._model   = model or _OPENROUTER_MODEL
        self._api_key = api_key or _OPENROUTER_API_KEY
        self._logger  = get_decision_logger()

    # ── Публичные методы ────────────────────────────────────────────────────────

    def suggest_remediation(
        self,
        control_id:   str,
        gap_description: str,
        evidence_ids: Optional[list[str]] = None,
    ) -> AIAdvice:
        """
        Предлагает план устранения несоответствия для контроля.

        Args:
            control_id:      код контроля ("CC6.1")
            gap_description: описание несоответствия
            evidence_ids:    список ID evidence, использованных в анализе

        Returns:
            AIAdvice с планом устранения (помечен advisory).
        """
        t0 = time.time()
        prompt = (
            f"Как senior SOC 2 compliance engineer, предложи конкретный план устранения "
            f"для контроля {control_id}.\n"
            f"Описание проблемы: {gap_description}\n"
            f"Дай 3-5 конкретных шагов с указанием инструментов (Okta, AWS, GitHub, Jira)."
        )

        output = self._call_llm(prompt, control_id=control_id)
        duration_ms = int((time.time() - t0) * 1000)

        advice = AIAdvice(
            suggestion=output,
            confidence=self._estimate_confidence(output),
            reasoning=f"Gap analysis для {control_id}: {gap_description[:200]}",
            advice_type="remediation",
            control_id=control_id,
        )

        # Логируем каждый вызов — аудиторская прозрачность
        self._log_decision(
            decision_type=DecisionType.GAP_ANALYSIS,
            prompt=prompt,
            output=output,
            outcome=f"remediation_advice:{control_id}",
            control_id=control_id,
            evidence_ids=evidence_ids or [],
            duration_ms=duration_ms,
            metadata={"advice_type": "remediation"},
        )

        log.info(
            "AIAdvisor.suggest_remediation: control=%s confidence=%.2f (advisory only)",
            control_id, advice.confidence,
        )
        return advice

    def draft_policy(
        self,
        control_id:   str,
        control_title: str,
        context:      Optional[dict] = None,
    ) -> AIAdvice:
        """
        Создаёт черновик политики для контроля.

        Черновик ВСЕГДА получает статус DRAFT — только человек (admin) может
        изменить статус на APPROVED. AIAdvisor не может устанавливать APPROVED.

        Args:
            control_id:    код контроля ("CC6.1")
            control_title: название контроля
            context:       дополнительный контекст (company_name, tools, etc.)

        Returns:
            AIAdvice с черновиком политики. Статус policy = DRAFT.
        """
        t0 = time.time()
        ctx_str = ""
        if context:
            parts = [f"{k}: {v}" for k, v in context.items() if v]
            ctx_str = "\nКонтекст:\n" + "\n".join(parts[:5])

        prompt = (
            f"Напиши черновик политики SOC 2 для контроля {control_id}: {control_title}.\n"
            f"Политика должна быть конкретной, с указанием ролей и сроков.{ctx_str}\n"
            f"Это DRAFT — требует human review и approval перед внедрением."
        )

        output = self._call_llm(prompt, control_id=control_id)
        duration_ms = int((time.time() - t0) * 1000)

        advice = AIAdvice(
            suggestion=output,
            confidence=self._estimate_confidence(output),
            reasoning=f"Policy draft для {control_id}: {control_title}",
            advice_type="policy_draft",
            control_id=control_id,
            metadata={"policy_status": "DRAFT", "requires_human_approval": True},
        )

        self._log_decision(
            decision_type=DecisionType.POLICY_GENERATION,
            prompt=prompt,
            output=output,
            outcome="draft",
            control_id=control_id,
            evidence_ids=[],
            duration_ms=duration_ms,
            metadata={"policy_status": "DRAFT"},
        )

        log.info(
            "AIAdvisor.draft_policy: control=%s status=DRAFT (requires human approval)",
            control_id,
        )
        return advice

    def explain_finding(
        self,
        control_id: str,
        finding:    str,
        audience:   str = "auditor",
    ) -> AIAdvice:
        """
        Объясняет compliance-находку простым языком.

        Args:
            control_id: код контроля
            finding:    описание находки
            audience:   для кого объяснение ("auditor" | "management" | "engineer")

        Returns:
            AIAdvice с объяснением находки.
        """
        t0 = time.time()
        prompt = (
            f"Объясни следующую compliance-находку по контролю {control_id} "
            f"для аудитории '{audience}'.\n"
            f"Находка: {finding}\n"
            f"Объяснение должно быть чётким, без жаргона, с указанием бизнес-риска."
        )

        output = self._call_llm(prompt, control_id=control_id)
        duration_ms = int((time.time() - t0) * 1000)

        advice = AIAdvice(
            suggestion=output,
            confidence=self._estimate_confidence(output),
            reasoning=f"Explanation для {control_id} для {audience}",
            advice_type="explanation",
            control_id=control_id,
            metadata={"audience": audience},
        )

        self._log_decision(
            decision_type=DecisionType.CONTROL_ASSESSMENT,
            prompt=prompt,
            output=output,
            outcome=f"explanation:{audience}",
            control_id=control_id,
            evidence_ids=[],
            duration_ms=duration_ms,
            metadata={"audience": audience},
        )

        return advice

    def prioritize_risks(
        self,
        findings: list[dict],
    ) -> AIAdvice:
        """
        Приоритизирует список compliance-рисков по бизнес-влиянию.

        Args:
            findings: список dict с ключами control_id, description, status

        Returns:
            AIAdvice с приоритизированным списком рисков.
        """
        t0 = time.time()
        # Формируем краткое резюме находок для промта (без sensitive данных)
        findings_summary = "\n".join(
            f"- {f.get('control_id', 'unknown')}: {f.get('description', '')[:100]}"
            for f in findings[:15]
        )

        prompt = (
            f"Ты senior SOC 2 compliance engineer. Приоритизируй следующие compliance-риски "
            f"по бизнес-влиянию (critical → high → medium → low):\n\n"
            f"{findings_summary}\n\n"
            f"Для каждого укажи приоритет и одну конкретную причину."
        )

        output = self._call_llm(prompt)
        duration_ms = int((time.time() - t0) * 1000)

        control_ids = [f.get("control_id", "") for f in findings if f.get("control_id")]

        advice = AIAdvice(
            suggestion=output,
            confidence=self._estimate_confidence(output),
            reasoning=f"Risk prioritization для {len(findings)} находок",
            advice_type="risk_priority",
            metadata={"findings_count": len(findings), "control_ids": control_ids[:10]},
        )

        self._log_decision(
            decision_type=DecisionType.RISK_SCORING,
            prompt=prompt,
            output=output,
            outcome=f"risk_priority:{len(findings)}_findings",
            control_id=None,
            evidence_ids=[],
            duration_ms=duration_ms,
            metadata={"findings_count": len(findings)},
        )

        return advice

    # ── Внутренние методы ───────────────────────────────────────────────────────

    def _call_llm(self, prompt: str, control_id: Optional[str] = None) -> str:
        """
        Вызывает LLM через OpenRouter. При отсутствии API key — mock-режим.

        AIAdvisor не меняет статус контролей по итогам этого вызова.
        """
        if not self._api_key:
            # Mock-режим: для тестов и environments без API key
            log.warning(
                "AIAdvisor: OPENROUTER_API_KEY не задан, используем mock-ответ%s",
                f" (control={control_id})" if control_id else "",
            )
            return self._mock_response(prompt, control_id)

        try:
            from openai import OpenAI, RateLimitError
            client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=self._api_key,
                default_headers={
                    "HTTP-Referer": "compliance-sandbox",
                    "X-Title":      "Compliance Sandbox AI Advisor",
                },
            )
            response = client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=800,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            log.error("AIAdvisor LLM call failed: %s — using mock response", exc)
            return self._mock_response(prompt, control_id)

    def _mock_response(self, prompt: str, control_id: Optional[str] = None) -> str:
        """Детерминированный mock-ответ для тестов и environments без API key."""
        if "remediation" in prompt.lower() or "plan" in prompt.lower():
            return (
                f"[MOCK] Рекомендация по устранению для {control_id or 'контроля'}:\n"
                "1. Проверить текущую конфигурацию в Okta/AWS/GitHub\n"
                "2. Создать Jira-тикет для отслеживания\n"
                "3. Внедрить изменение через PR с review\n"
                "4. Собрать evidence и обновить Evidence Tracker\n"
                "5. Провести повторную проверку через 7 дней"
            )
        elif "policy" in prompt.lower() or "черновик" in prompt.lower():
            return (
                f"[MOCK DRAFT] Черновик политики для {control_id or 'контроля'}.\n"
                "СТАТУС: DRAFT — требует human review и approval.\n\n"
                "## Назначение\nОписание политики...\n\n"
                "## Область применения\nВсе сотрудники...\n\n"
                "## Требования\nКонкретные требования...\n\n"
                "## Ответственные\nCISO, HR, Engineering Lead"
            )
        elif "объясни" in prompt.lower() or "explain" in prompt.lower():
            return (
                f"[MOCK] Объяснение находки по {control_id or 'контролу'}:\n"
                "Данная находка указывает на несоответствие требованиям SOC 2.\n"
                "Бизнес-риск: потенциальная уязвимость в системе управления доступом.\n"
                "Рекомендуется устранить в течение 30 дней."
            )
        else:
            return (
                f"[MOCK] Анализ для {control_id or 'запроса'}:\n"
                "Требует дополнительного рассмотрения compliance-командой.\n"
                "Настоятельно рекомендуется привлечь CISO для оценки."
            )

    def _estimate_confidence(self, output: str) -> float:
        """Эвристическая оценка уверенности по длине и структуре ответа."""
        if not output:
            return 0.1
        words = len(output.split())
        base = min(words / 200, 0.6)  # до 0.6 от длины
        if "[MOCK]" in output:
            base = 0.4
        if any(marker in output for marker in ["##", "1.", "2.", "3."]):
            base += 0.1
        return round(min(base, 0.85), 2)  # никогда не выше 0.85 (AI не authority)

    def _log_decision(
        self,
        decision_type: DecisionType,
        prompt:        str,
        output:        str,
        outcome:       str,
        control_id:    Optional[str],
        evidence_ids:  list[str],
        duration_ms:   int,
        metadata:      dict,
    ) -> None:
        """Логирует AI-вызов через AIDecisionLogger."""
        try:
            # Добавляем advisory-маркер в metadata
            meta = {**metadata, "is_advisory_only": True, "advisor": "AIAdvisor"}
            self._logger.record(
                decision_type=decision_type,
                model=self._model,
                prompt=prompt,
                output=output,
                outcome=outcome,
                control_id=control_id,
                evidence_used=evidence_ids,
                duration_ms=duration_ms,
                metadata=meta,
            )
        except Exception as exc:
            log.warning("AIAdvisor: не удалось залогировать decision: %s", exc)


# ── Singleton ──────────────────────────────────────────────────────────────────

_advisor_instance: Optional[AIAdvisor] = None


def get_ai_advisor() -> AIAdvisor:
    """Singleton AIAdvisor (ленивая инициализация)."""
    global _advisor_instance
    if _advisor_instance is None:
        _advisor_instance = AIAdvisor()
    return _advisor_instance
