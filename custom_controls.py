import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional

class CustomControlsManager:
    CONTROLS_FILE = Path(__file__).parent / "custom_controls.json"
    
    TEMPLATES = {
        "gdpr_13": {
            "code": "GDPR-13", "name": "GDPR Article 13 — Privacy Notice",
            "framework": "GDPR", "category": "data_protection",
            "description": "Data subjects must be informed about data processing at collection time",
            "pass_criteria": "Privacy notice displayed at all data collection points"
        },
        "gdpr_17": {
            "code": "GDPR-17", "name": "GDPR Article 17 — Right to Erasure",
            "framework": "GDPR", "category": "data_protection",
            "description": "The right to be forgotten allows individuals to request the deletion of their personal data",
            "pass_criteria": "Data deletion requests processed within 30 days"
        },
        "hipaa_safeguards": {
            "code": "HIPAA-164.308", "name": "HIPAA Administrative Safeguards",
            "framework": "HIPAA", "category": "access_control",
            "description": "Administrative actions, and policies and procedures, to manage the selection, development, implementation, and maintenance of security measures",
            "pass_criteria": "Designated security officer assigned and documented"
        },
        "pci_encryption": {
            "code": "PCI-3.4", "name": "PCI DSS — Cardholder Data Encryption",
            "framework": "PCI_DSS", "category": "data_protection",
            "description": "Render PAN unreadable anywhere it is stored",
            "pass_criteria": "All stored cardholder data encrypted with AES-256"
        },
    }
    
    def _load(self) -> List[Dict]:
        if not self.CONTROLS_FILE.exists():
            return []
        try:
            return json.loads(self.CONTROLS_FILE.read_text(encoding="utf-8"))
        except:
            return []
    
    def _save(self, controls: List[Dict]):
        self.CONTROLS_FILE.write_text(json.dumps(controls, indent=2, ensure_ascii=False), encoding="utf-8")
    
    def get_all(self, framework: str = None, status: str = None) -> List[Dict]:
        controls = self._load()
        if framework:
            controls = [c for c in controls if c["framework"] == framework]
        if status:
            controls = [c for c in controls if c["current_status"] == status]
        return controls
    
    def get_by_id(self, control_id: str) -> Optional[Dict]:
        controls = self._load()
        for c in controls:
            if c["id"] == control_id or c["code"] == control_id:
                return c
        return None
    
    def get_templates(self) -> List[Dict]:
        return [{"id": tid, **t} for tid, t in self.TEMPLATES.items()]
    
    def create_from_template(self, template_id: str, created_by: str) -> Dict:
        template = self.TEMPLATES.get(template_id)
        if not template:
            raise ValueError("Template not found")
        
        data = dict(template)
        data["owner"] = created_by
        data["current_status"] = "NOT_ASSESSED"
        return self.create(data, created_by)
    
    def create(self, data: Dict, created_by: str) -> Dict:
        controls = self._load()
        
        # Check uniqueness
        if any(c["code"] == data["code"] for c in controls):
            raise ValueError(f"Control with code {data['code']} already exists")
            
        # ID generation
        max_num = 0
        for c in controls:
            try:
                num = int(c["id"].split("-")[1])
                if num > max_num: max_num = num
            except: pass
        
        new_id = f"CUSTOM-{str(max_num + 1).zfill(3)}"
        
        control = {
            "id": new_id,
            "code": data["code"],
            "name": data["name"],
            "description": data.get("description", ""),
            "framework": data.get("framework", "CUSTOM"),
            "category": data.get("category", "compliance"),
            "owner": data.get("owner", created_by),
            "status": "manual",
            "evidence_description": data.get("evidence_description", ""),
            "evidence_links": data.get("evidence_links", []),
            "pass_criteria": data.get("pass_criteria", ""),
            "current_status": data.get("current_status", "NOT_ASSESSED"),
            "last_checked": None,
            "notes": "",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": created_by,
            "tags": data.get("tags", [])
        }
        
        controls.append(control)
        self._save(controls)
        return control
    
    def update(self, control_id: str, data: Dict) -> Optional[Dict]:
        controls = self._load()
        for c in controls:
            if c["id"] == control_id:
                for key in ["name", "description", "framework", "category", "owner", "evidence_description", "evidence_links", "pass_criteria", "tags"]:
                    if key in data:
                        c[key] = data[key]
                self._save(controls)
                return c
        return None
    
    def update_status(self, control_id: str, status: str, notes: str, updated_by: str) -> Optional[Dict]:
        controls = self._load()
        for c in controls:
            if c["id"] == control_id:
                c["current_status"] = status
                c["notes"] = notes
                c["last_checked"] = datetime.now(timezone.utc).isoformat()
                self._save(controls)
                return c
        return None
    
    def delete(self, control_id: str) -> bool:
        controls = self._load()
        initial_len = len(controls)
        controls = [c for c in controls if c["id"] != control_id]
        if len(controls) < initial_len:
            self._save(controls)
            return True
        return False
    
    def get_summary(self) -> Dict:
        controls = self._load()
        total = len(controls)
        
        by_framework = {}
        by_status = {"PASS": 0, "FAIL": 0, "NOT_ASSESSED": 0, "IN_PROGRESS": 0}
        
        for c in controls:
            fw = c["framework"]
            by_framework[fw] = by_framework.get(fw, 0) + 1
            
            st = c["current_status"]
            by_status[st] = by_status.get(st, 0) + 1
            
        pass_rate = (by_status["PASS"] / total * 100) if total > 0 else 0
        
        return {
            "total": total,
            "by_framework": by_framework,
            "by_status": by_status,
            "pass_rate": round(pass_rate, 1)
        }
    
    def get_all_controls_combined(self, standard_controls: List[Dict]) -> List[Dict]:
        custom = self._load()
        
        combined = []
        for sc in standard_controls:
            c = dict(sc)
            c["is_custom"] = False
            c["framework"] = "SOC2"
            combined.append(c)
            
        for cc in custom:
            c = {
                "id": cc["id"],
                "code": cc["code"],
                "title": cc["name"],
                "description": cc["description"],
                "status": cc["current_status"],
                "framework": cc["framework"],
                "owner": cc["owner"],
                "is_custom": True
            }
            combined.append(c)
            
        return combined
