import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict


def _run_async(coro):
    """Запускает async корутину из синхронного контекста."""
    import concurrent.futures
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


class RiskRegister:
    # Маппинг контролей на категории рисков
    CONTROL_CATEGORY_MAP = {
        "CC6.1": "access_control", "CC6.2": "access_control",
        "CC6.3": "access_control", "CC6.7": "data_protection",
        "CC6.8": "operational",    "CC7.1": "operational",
        "CC7.2": "operational",    "CC7.3": "operational",
        "CC7.4": "operational",    "CC8.1": "change_management",
        "CC5.3": "change_management", "CC9.2": "vendor",
        "CC1.4": "compliance",     "CC3.4": "change_management",
    }
    
    # ── Async DB helpers ──────────────────────────────────────────────────────

    async def _load_db(self) -> List[Dict]:
        """Загружает риски из SQLite. Возвращает список dict."""
        from database import AsyncSessionLocal
        from models import RiskEntry
        from sqlalchemy import select as sa_select
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                sa_select(RiskEntry).order_by(RiskEntry.created_at)
            )
            rows = result.scalars().all()
            if not rows:
                return []
            return [
                {
                    "id":             r.id,
                    "title":          r.title,
                    "description":    r.description,
                    "source":         r.source,
                    "control_id":     r.control_id,
                    "likelihood":     r.likelihood,
                    "impact":         r.impact,
                    "risk_score":     r.score,
                    "category":       r.category,
                    "owner":          r.owner or "",
                    "treatment":      r.treatment,
                    "treatment_plan": r.treatment_plan,
                    "status":         r.status,
                    "jira_ticket":    r.jira_ticket,
                    "target_date":    r.target_date,
                    "created_at":     r.created_at.isoformat(),
                    "updated_at":     r.updated_at.isoformat() if r.updated_at else r.created_at.isoformat(),
                }
                for r in rows
            ]

    async def _save_db(self, risks: List[Dict]) -> None:
        """Upsert рисков в SQLite по полю id."""
        from database import AsyncSessionLocal
        from models import RiskEntry
        from sqlalchemy import select as sa_select
        async with AsyncSessionLocal() as session:
            for risk in risks:
                risk_id = risk.get("id")
                if not risk_id:
                    continue
                result = await session.execute(
                    sa_select(RiskEntry).where(RiskEntry.id == risk_id)
                )
                existing = result.scalar_one_or_none()
                if existing:
                    existing.title          = risk.get("title", existing.title)
                    existing.description    = risk.get("description", existing.description)
                    existing.source         = risk.get("source", existing.source)
                    existing.control_id     = risk.get("control_id", existing.control_id)
                    existing.likelihood     = int(risk.get("likelihood", existing.likelihood))
                    existing.impact         = int(risk.get("impact", existing.impact))
                    existing.score          = int(risk.get("risk_score", existing.score))
                    existing.category       = risk.get("category", existing.category)
                    existing.owner          = risk.get("owner", existing.owner)
                    existing.treatment      = risk.get("treatment", existing.treatment)
                    existing.treatment_plan = risk.get("treatment_plan", existing.treatment_plan)
                    existing.status         = risk.get("status", existing.status)
                    existing.jira_ticket    = risk.get("jira_ticket", existing.jira_ticket)
                    existing.target_date    = risk.get("target_date", existing.target_date)
                    existing.updated_at     = datetime.now(timezone.utc)
                else:
                    entry = RiskEntry(
                        id=risk_id,
                        title=risk.get("title", "Untitled Risk"),
                        description=risk.get("description", ""),
                        source=risk.get("source", "manual"),
                        control_id=risk.get("control_id"),
                        likelihood=int(risk.get("likelihood", 3)),
                        impact=int(risk.get("impact", 3)),
                        score=int(risk.get("risk_score", 9)),
                        category=risk.get("category", "operational"),
                        owner=risk.get("owner"),
                        treatment=risk.get("treatment", "mitigate"),
                        treatment_plan=risk.get("treatment_plan", ""),
                        status=risk.get("status", "open"),
                        jira_ticket=risk.get("jira_ticket"),
                        target_date=risk.get("target_date"),
                    )
                    session.add(entry)
            try:
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    # ── JSON helpers (fallback) ───────────────────────────────────────────────

    def _load(self) -> List[Dict]:
        """Загружает риски из SQLite."""
        return _run_async(self._load_db())

    def _save(self, risks: List[Dict]):
        """Сохраняет риски в SQLite."""
        _run_async(self._save_db(risks))
    
    def get_all(self, status: str = None, category: str = None) -> List[Dict]:
        """Возвращает все риски с фильтрацией."""
        risks = self._load()
        if status:
            risks = [r for r in risks if r["status"] == status]
        if category:
            risks = [r for r in risks if r["category"] == category]
        return risks
    
    def get_by_id(self, risk_id: str) -> Optional[Dict]:
        """Возвращает риск по ID."""
        risks = self._load()
        for r in risks:
            if r["id"] == risk_id:
                return r
        return None
    
    def create(self, data: Dict) -> Dict:
        """Создает новый риск."""
        risks = self._load()
        
        # Генерация ID: RISK-001, RISK-002...
        max_id = 0
        for r in risks:
            try:
                num = int(r["id"].split("-")[1])
                if num > max_id:
                    max_id = num
            except (ValueError, IndexError, KeyError):
                pass
        
        new_id = f"RISK-{str(max_id + 1).zfill(3)}"
        
        likelihood = int(data.get("likelihood", 3))
        impact = int(data.get("impact", 3))
        
        risk = {
            "id": new_id,
            "title": data.get("title", "Untitled Risk"),
            "description": data.get("description", ""),
            "source": data.get("source", "manual"),
            "control_id": data.get("control_id"),
            "likelihood": likelihood,
            "impact": impact,
            "risk_score": likelihood * impact,
            "category": data.get("category", "operational"),
            "owner": data.get("owner", "ciso@marineso.com"),
            "treatment": data.get("treatment", "mitigate"),
            "treatment_plan": data.get("treatment_plan", ""),
            "status": data.get("status", "open"),
            "jira_ticket": data.get("jira_ticket"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "target_date": data.get("target_date", (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"))
        }
        
        risks.append(risk)
        self._save(risks)
        return risk
    
    def update(self, risk_id: str, data: Dict) -> Optional[Dict]:
        """Обновляет поля риска."""
        risks = self._load()
        for r in risks:
            if r["id"] == risk_id:
                # Обновляем поля
                for key in ["title", "description", "likelihood", "impact", "category", "owner", "treatment", "treatment_plan", "status", "jira_ticket", "target_date"]:
                    if key in data:
                        r[key] = data[key]
                
                # Пересчитываем score
                r["risk_score"] = int(r["likelihood"]) * int(r["impact"])
                r["updated_at"] = datetime.now(timezone.utc).isoformat()
                
                self._save(risks)
                return r
        return None
    
    def delete(self, risk_id: str) -> bool:
        """Удаляет риск."""
        risks = self._load()
        initial_len = len(risks)
        risks = [r for r in risks if r["id"] != risk_id]
        if len(risks) < initial_len:
            self._save(risks)
            return True
        return False
    
    def sync_from_controls(self, controls: List[Dict]) -> Dict:
        """Синхронизирует риски из FAIL-контролей."""
        risks = self._load()
        created = 0
        updated = 0
        skipped = 0
        
        # Получаем список FAIL контролей (или всех, если фильтрация была снаружи)
        fail_controls = [c for c in controls if str(c.get("status", "")).upper() == "FAIL"]
        
        for ctrl in fail_controls:
            ctrl_code = ctrl.get("code")
            if not ctrl_code:
                continue
                
            # Проверяем, есть ли уже риск для этого контроля
            existing = None
            for r in risks:
                if r.get("source") == "control" and r.get("control_id") == ctrl_code:
                    existing = r
                    break
            
            if existing:
                # Если риск уже есть и он решен, но контроль снова упал — можем переоткрыть
                # Но в рамках задания просто пропускаем или обновляем
                skipped += 1
            else:
                # Создаем новый риск
                category = self.CONTROL_CATEGORY_MAP.get(ctrl_code, "compliance")
                
                # Дефолтные значения из задания
                risk_data = {
                    "title": f"Control {ctrl_code} failed: {ctrl.get('title', '')}",
                    "description": ctrl.get("description", "Control failed in automated compliance scan"),
                    "source": "control",
                    "control_id": ctrl_code,
                    "likelihood": 3,
                    "impact": 4,
                    "category": category,
                    "owner": "ciso@marineso.com",
                    "treatment": "mitigate",
                    "status": "open",
                    "target_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
                }
                self.create(risk_data)
                created += 1
                # Перезагружаем риски после создания, чтобы ID шли правильно
                risks = self._load()
                
        return {"created": created, "updated": updated, "skipped": skipped}
    
    def get_summary(self) -> Dict:
        """Возвращает статистику рисков."""
        risks = self._load()
        total = len(risks)
        
        by_status = {"open": 0, "in_progress": 0, "resolved": 0, "accepted": 0}
        by_category = {}
        
        critical_count = 0  # >= 20
        high_count = 0      # 15-19
        medium_count = 0    # 8-14
        low_count = 0       # <= 7
        total_score = 0
        
        for r in risks:
            score = r["risk_score"]
            status = r["status"]
            cat = r["category"]
            
            if status in by_status:
                by_status[status] += 1
            else:
                by_status[status] = 1
                
            by_category[cat] = by_category.get(cat, 0) + 1
            
            if score >= 20: critical_count += 1
            elif score >= 15: high_count += 1
            elif score >= 8: medium_count += 1
            else: low_count += 1
            
            total_score += score
            
        avg_score = total_score / total if total > 0 else 0
        
        return {
            "total": total,
            "by_status": by_status,
            "by_category": by_category,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "average_score": round(avg_score, 1)
        }
    
    def get_risk_matrix(self) -> List[Dict]:
        """Возвращает данные для матрицы 5x5."""
        risks = self._load()
        # Возвращаем упрощенный список для фронта
        return [{
            "id": r["id"],
            "title": r["title"],
            "likelihood": r["likelihood"],
            "impact": r["impact"],
            "risk_score": r["risk_score"]
        } for r in risks if r["status"] != "resolved"]
