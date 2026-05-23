import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict

class RiskRegister:
    RISK_FILE = Path(__file__).parent / "risk_register.json"
    
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
    
    def _load(self) -> List[Dict]:
        """Загружает риски из risk_register.json."""
        if not self.RISK_FILE.exists():
            return []
        try:
            with open(self.RISK_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    
    def _save(self, risks: List[Dict]):
        """Сохраняет риски в risk_register.json."""
        with open(self.RISK_FILE, "w", encoding="utf-8") as f:
            json.dump(risks, f, indent=2, ensure_ascii=False)
    
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
