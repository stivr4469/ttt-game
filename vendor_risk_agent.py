#!/usr/bin/env python3

import os
import json
import argparse
from datetime import date
from typing import Optional
from openai import OpenAI
from dotenv import load_dotenv
from evidence_client import EvidenceClient
from log_config import get_logger
from constants import CONTROLS_MAP_FILE

load_dotenv()
log = get_logger(__name__)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku")
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
VENDOR_INVENTORY_FILE = "vendor_inventory.json"

SOC2_VENDOR_CONTROL = "CC9.2"

_FALLBACK_ASSESSMENT = {
    "risk_level": "UNKNOWN",
    "key_concerns": ["AI analysis unavailable — manual review required"],
    "recommendations": ["Perform manual SOC 2 CC9.2 vendor risk review"],
    "soc2_status": "Not assessed",
}


class VendorRiskAgent:
    def __init__(self, api_key: Optional[str], model: str):
        self.model = model
        self.ai_available = bool(api_key)
        if self.ai_available:
            self.client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=api_key,
            )

    def load_vendors(self) -> list:
        if not os.path.exists(VENDOR_INVENTORY_FILE):
            log.error("Vendor inventory file not found", extra={"file": VENDOR_INVENTORY_FILE})
            return []
        with open(VENDOR_INVENTORY_FILE) as f:
            data = json.load(f)
        vendors = data.get("vendors", [])
        log.info("Vendors loaded", extra={"count": len(vendors)})
        return vendors

    def analyze_vendor(self, vendor: dict) -> dict:
        if not self.ai_available:
            log.warning(
                "OPENROUTER_API_KEY not set — using fallback assessment",
                extra={"vendor": vendor.get("name")},
            )
            return {**_FALLBACK_ASSESSMENT}

        prompt = (
            "You are a SOC 2 compliance auditor. Analyze this vendor for CC9.2 "
            "(Vendor Risk Management). "
            f"Vendor: {json.dumps(vendor)}. "
            "Rate risk: LOW/MEDIUM/HIGH. "
            "Give: risk_level, key_concerns (list), recommendations (list), soc2_status assessment. "
            "Return JSON only."
        )
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
            )
            raw = response.choices[0].message.content.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            result = json.loads(raw)
            log.info(
                "Vendor analyzed",
                extra={"vendor": vendor.get("name"), "risk_level": result.get("risk_level")},
            )
            return result
        except json.JSONDecodeError as exc:
            log.error(
                "Failed to parse AI response as JSON",
                extra={"vendor": vendor.get("name"), "error": str(exc)},
            )
            return {**_FALLBACK_ASSESSMENT}
        except Exception as exc:
            log.error(
                "AI analysis failed",
                extra={"vendor": vendor.get("name"), "error": str(exc)},
            )
            return {**_FALLBACK_ASSESSMENT}

    def run_assessment(self) -> list:
        vendors = self.load_vendors()
        results = []
        for vendor in vendors:
            name = vendor.get("name", "unknown")
            try:
                assessment = self.analyze_vendor(vendor)
                results.append({**vendor, "risk_level": assessment.get("risk_level"), "assessment": assessment})
            except Exception as exc:
                log.error("Vendor assessment error", extra={"vendor": name, "error": str(exc)})
                results.append({**vendor, "risk_level": "UNKNOWN", "assessment": {**_FALLBACK_ASSESSMENT}})
        return results


def main(controls_map: dict | None = None):
    if controls_map is None:
        if not os.path.exists(CONTROLS_MAP_FILE):
            log.error("controls_map.json not found — run controls_seed.py first")
            return
        with open(CONTROLS_MAP_FILE) as f:
            controls_map = json.load(f)

    control_id = controls_map.get(SOC2_VENDOR_CONTROL)
    if not control_id:
        log.error("Control not found in controls_map", extra={"control": SOC2_VENDOR_CONTROL})
        return

    agent = VendorRiskAgent(api_key=OPENROUTER_API_KEY, model=OPENROUTER_MODEL)
    assessed_vendors = agent.run_assessment()

    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}
    for v in assessed_vendors:
        level = v.get("risk_level") or "UNKNOWN"
        risk_counts[level] = risk_counts.get(level, 0) + 1

    report = {
        "generated_at": date.today().isoformat(),
        "control": SOC2_VENDOR_CONTROL,
        "total_vendors": len(assessed_vendors),
        "risk_summary": risk_counts,
        "vendors": assessed_vendors,
    }

    evidence_client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="vendor_risk_agent")
    try:
        evidence_client.create_evidence(
            control_id=control_id,
            title="Vendor Risk Assessment — AI Analysis",
            content=json.dumps(report),
            source="AI_GENERATED",
        )
        evidence_client.update_control_status(control_id, "PASS")
        log.info("Evidence saved and control status updated", extra={"control": SOC2_VENDOR_CONTROL})
    except Exception as exc:
        log.error("Failed to save evidence", extra={"error": str(exc)})

    print(f"\n{'='*60}")
    print(f" VENDOR RISK ASSESSMENT — {SOC2_VENDOR_CONTROL}")
    print(f" Дата: {report['generated_at']} | Вендоров: {len(assessed_vendors)}")
    print(f"{'='*60}")
    for v in assessed_vendors:
        level = v.get("risk_level") or "UNKNOWN"
        icon = {"LOW": "✅", "MEDIUM": "🟠", "HIGH": "🔴"}.get(level, "❓")
        print(f"  {icon} {v['name']:<20} {level:<8} [{v.get('category', '')}]")
    print(f"\n  Сводка: LOW={risk_counts['LOW']} | MEDIUM={risk_counts['MEDIUM']} "
          f"| HIGH={risk_counts['HIGH']} | UNKNOWN={risk_counts['UNKNOWN']}")
    print(f"  Evidence → {EVIDENCE_TRACKER_URL}/docs (source=AI_GENERATED)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
