import json
import os
from typing import List, Optional
from constants import CONTROLS_MAP_FILE

REGISTRY_FILE = "service_registry.json"

def load_registry() -> dict:
    # Use absolute path relative to registry.py
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, REGISTRY_FILE)
    with open(path) as f:
        return json.load(f)

def get_active_services(env: dict) -> List[str]:
    """Возвращает список сервисов для которых есть все обязательные env vars."""
    registry = load_registry()
    active = []
    for service_id, service in registry["services"].items():
        required = service.get("env_vars", [])
        if required and all(env.get(k) for k in required):
            active.append(service_id)
    return active

def get_controls_for_service(service_id: str, framework: str = "soc2") -> List[str]:
    registry = load_registry()
    if service_id not in registry["services"]:
        return []
    return registry["services"][service_id]["controls"].get(framework, [])

def get_agent_for_service(service_id: str) -> Optional[str]:
    registry = load_registry()
    if service_id not in registry["services"]:
        return None
    return registry["services"][service_id].get("agent")

def get_coverage_report(framework: str = "soc2") -> dict:
    """Показывает какие контроли покрыты и каким сервисом."""
    registry = load_registry()
    coverage = {}
    for service_id, service in registry["services"].items():
        for control in service["controls"].get(framework, []):
            if control not in coverage:
                coverage[control] = []
            coverage[control].append(service_id)
    return coverage

def get_controls_for_stack(service_ids: List[str], framework: str = "soc2") -> dict:
    """
    Для заданного набора сервисов клиента — какие контроли покрываются,
    какие не покрываются.
    """
    registry = load_registry()
    all_controls = set()
    for sid in service_ids:
        if sid in registry["services"]:
            for c in registry["services"][sid]["controls"].get(framework, []):
                all_controls.add(c)

    # Все контроли фреймворка (из controls_map.json)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    map_path = os.path.join(base_dir, CONTROLS_MAP_FILE)
    
    if os.path.exists(map_path):
        with open(map_path) as f:
            controls_map = json.load(f)
        all_framework_controls = set(controls_map.keys())
    else:
        # Fallback if map not seeded yet
        all_framework_controls = all_controls

    return {
        "covered": sorted(list(all_controls)),
        "not_covered": sorted(list(all_framework_controls - all_controls)),
        "coverage_pct": round(len(all_controls) / len(all_framework_controls) * 100, 1) if all_framework_controls else 0
    }
