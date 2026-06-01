"""
Questionnaire Knowledge Base — поиск похожих ответов из прошлых QuestionnaireResponse.

MVP: keyword-based поиск (без векторов).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from database import AsyncSessionLocal
from models import QuestionnaireResponse

logger = logging.getLogger(__name__)

# Stopwords для фильтрации при разбивке на ключевые слова
_STOPWORDS: frozenset[str] = frozenset(
    {
        "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
        "do", "does", "did", "have", "has", "had", "will", "would", "could",
        "should", "may", "might", "shall", "can",
        "what", "how", "when", "where", "why", "who", "which",
        "your", "our", "their", "you", "we", "they", "it", "its",
        "of", "in", "to", "for", "on", "at", "by", "with", "from",
        "and", "or", "but", "not", "all", "any", "each",
    }
)


def _extract_keywords(text: str) -> list[str]:
    """Разбить текст на ключевые слова, отфильтровав stopwords."""
    words = text.lower().split()
    keywords: list[str] = []
    for w in words:
        # Удаляем символы пунктуации по краям
        clean = w.strip("?.!,;:()'\"")
        if clean and clean not in _STOPWORDS and len(clean) > 2:
            keywords.append(clean)
    return keywords


def _score_entry(question_lower: str, answer_lower: str, keywords: list[str]) -> int:
    """Подсчитать количество ключевых слов, встречающихся в вопросе или ответе."""
    score = 0
    for kw in keywords:
        if kw in question_lower or kw in answer_lower:
            score += 1
    return score


class QuestionnaireKB:
    """Поиск похожих ответов из прошлых QuestionnaireResponse записей."""

    async def find_similar(
        self, question: str, limit: int = 3
    ) -> list[dict[str, Any]]:
        """
        Keyword-based поиск похожих ответов из БД.

        Алгоритм:
        1. Извлечь ключевые слова из question (без stopwords).
        2. Для каждой QuestionnaireResponse извлечь answers (JSON-массив).
        3. Ранжировать отдельные answer-объекты по числу совпадений + recency.
        4. Вернуть top-limit результатов.

        Возвращает список словарей вида:
            {id, response_id, question, answer, score, created_at}
        """
        keywords = _extract_keywords(question)
        if not keywords:
            return []

        # Загружаем все QuestionnaireResponse из БД (записей немного)
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(QuestionnaireResponse).order_by(
                    QuestionnaireResponse.created_at.desc()
                )
            )
            rows = result.scalars().all()

        candidates: list[dict[str, Any]] = []
        seen_answers: set[str] = set()

        for row in rows:
            answers: list[dict[str, Any]] = row.answers or []
            created_at_str = (
                row.created_at.isoformat() if row.created_at else ""
            )
            for ans in answers:
                q_text: str = ans.get("question", "")
                a_text: str = ans.get("answer", "")
                if not q_text or not a_text:
                    continue

                # Дедупликация по тексту ответа
                dedup_key = a_text[:120]
                if dedup_key in seen_answers:
                    continue

                score = _score_entry(q_text.lower(), a_text.lower(), keywords)
                if score == 0:
                    continue

                seen_answers.add(dedup_key)
                candidates.append(
                    {
                        "id": f"{row.id}::{ans.get('question_id', '')}",
                        "response_id": row.id,
                        "question": q_text,
                        "answer": a_text,
                        "score": score,
                        "created_at": created_at_str,
                    }
                )

        # Сортируем: сначала по score (desc), потом по дате (desc через id порядка)
        candidates.sort(key=lambda c: c["score"], reverse=True)
        return candidates[:limit]

    async def record_accepted(
        self,
        question: str,
        answer: str,
        source: str = "kb",
        original_id: str | None = None,
    ) -> str:
        """Сохранить принятый ответ в QuestionnaireResponse как отдельную запись."""
        now = datetime.now(timezone.utc)
        response_id = str(uuid.uuid4())

        answer_entry: dict[str, Any] = {
            "question_id": "KB-1",
            "question": question,
            "category": "Knowledge Base",
            "answer": answer,
            "confidence": "high",
            "policy_references": [],
            "needs_review": False,
            "source": source,
            "original_id": original_id,
        }

        obj = QuestionnaireResponse(
            id=response_id,
            questionnaire="kb_entry",
            questionnaire_name="KB Accepted Answer",
            requester={"company": "Internal KB", "email": "kb@system"},
            total_questions=1,
            high_confidence=1,
            needs_review_count=0,
            answers=[answer_entry],
            generated_at=now,
        )

        async with AsyncSessionLocal() as session:
            session.add(obj)
            await session.commit()

        logger.info("KB: saved accepted answer, response_id=%s", response_id)
        return response_id
