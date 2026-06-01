import asyncio
import os
import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv

from evidence_client import EvidenceClient
from log_config import get_logger
from constants import CONTROLS_MAP_FILE, SEVERITY_HIGH, SEVERITY_CRITICAL

load_dotenv()
log = get_logger(__name__)


# ── Async helper ──────────────────────────────────────────────────────────────

def _run_async(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result(timeout=30)
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")

POLICY = {
    "screen_lock_max_minutes": 10,
    "require_filevault": True,
    "require_edr": True,
    "require_os_current": True,
}

MDM_CONTROLS = {
    "CC6.6": "Unauthorized Software Control",
    "CC6.8": "Anti-Malware and Device Security",
}


class MDMAgent:
    def __init__(self, base_url: str, controls_map: Optional[dict]):
        self.evidence_client = EvidenceClient(base_url, agent_name="mdm")
        self.controls_map = controls_map or {}

    def load_devices(self) -> list:
        # 1. Jamf если настроен
        if os.getenv("JAMF_URL") and os.getenv("JAMF_USER"):
            try:
                from jamf_client import JamfClient
                client = JamfClient(
                    os.getenv("JAMF_URL", ""),
                    os.getenv("JAMF_USER", ""),
                    os.getenv("JAMF_PASSWORD", ""),
                )
                devices = client.get_all_devices()
                log.info("MDM: loaded devices from Jamf", extra={"count": len(devices)})
                return devices
            except Exception as e:
                log.warning("Jamf unavailable, falling back", extra={"error": str(e)})

        # 2. Intune если настроен
        if os.getenv("INTUNE_TENANT_ID") and os.getenv("INTUNE_CLIENT_ID"):
            try:
                from intune_client import IntuneClient
                client = IntuneClient(
                    os.getenv("INTUNE_TENANT_ID", ""),
                    os.getenv("INTUNE_CLIENT_ID", ""),
                    os.getenv("INTUNE_CLIENT_SECRET", ""),
                )
                raw = client.get_managed_devices()
                devices = [client.to_mdm_device(d) for d in raw]
                log.info("MDM: loaded devices from Intune", extra={"count": len(devices)})
                return devices
            except Exception as e:
                log.warning("Intune unavailable, falling back", extra={"error": str(e)})

        # 3. Fallback: DB inventory
        return self._load_from_file()

    def _load_from_file(self) -> list:
        devices = _run_async(self._load_inventory_db())
        log.info("MDM inventory loaded from DB", extra={"device_count": len(devices)})
        return devices

    async def _load_inventory_db(self) -> list:
        """Загрузить устройства из SQLite через ORM."""
        from database import AsyncSessionLocal
        from models import MDMDevice
        from sqlalchemy import select

        async with AsyncSessionLocal() as session:
            result = await session.execute(select(MDMDevice))
            rows = result.scalars().all()

        devices = []
        for row in rows:
            devices.append({
                "device_id": row.device_id,
                "hostname": row.hostname,
                "owner": row.owner,
                "os": row.os,
                "device_type": row.device_type,
                "filevault_enabled": row.filevault_enabled,
                "screen_lock_minutes": row.screen_lock_minutes,
                "edr_installed": row.edr_installed,
                "edr_name": row.edr_name,
                "os_up_to_date": row.os_up_to_date,
                "last_check_in": row.last_check_in,
                "compliant": row.compliant,
            })
        return devices

    async def _save_inventory_db(self, devices: list) -> None:
        """Upsert устройств в SQLite (по device_id — unique)."""
        from database import AsyncSessionLocal
        from models import MDMDevice
        from sqlalchemy import select

        async with AsyncSessionLocal() as session:
            for dev in devices:
                device_id = dev.get("device_id", "")
                if not device_id:
                    continue
                result = await session.execute(
                    select(MDMDevice).where(MDMDevice.device_id == device_id)
                )
                existing = result.scalars().first()
                if existing:
                    existing.hostname = dev.get("hostname", existing.hostname)
                    existing.owner = dev.get("owner", existing.owner)
                    existing.os = dev.get("os", existing.os)
                    existing.device_type = dev.get("device_type", existing.device_type)
                    existing.filevault_enabled = bool(dev.get("filevault_enabled", False))
                    existing.screen_lock_minutes = int(dev.get("screen_lock_minutes", 5))
                    existing.edr_installed = bool(dev.get("edr_installed", False))
                    existing.edr_name = dev.get("edr_name")
                    existing.os_up_to_date = bool(dev.get("os_up_to_date", False))
                    existing.last_check_in = dev.get("last_check_in")
                    existing.compliant = bool(dev.get("compliant", False))
                else:
                    session.add(MDMDevice(
                        id=str(uuid.uuid4()),
                        device_id=device_id,
                        hostname=dev.get("hostname", ""),
                        owner=dev.get("owner", ""),
                        os=dev.get("os", ""),
                        device_type=dev.get("device_type", "laptop"),
                        filevault_enabled=bool(dev.get("filevault_enabled", False)),
                        screen_lock_minutes=int(dev.get("screen_lock_minutes", 5)),
                        edr_installed=bool(dev.get("edr_installed", False)),
                        edr_name=dev.get("edr_name"),
                        os_up_to_date=bool(dev.get("os_up_to_date", False)),
                        last_check_in=dev.get("last_check_in"),
                        compliant=bool(dev.get("compliant", False)),
                    ))
            await session.commit()

    def check_device(self, device: dict) -> dict:
        violations = []
        checks_total = 4
        checks_passed = 0

        if POLICY["require_filevault"] and not device.get("filevault_enabled", False):
            violations.append({
                "check": "filevault",
                "severity": SEVERITY_CRITICAL,
                "finding": f"FileVault disabled on {device.get('hostname', device['device_id'])}",
            })
        else:
            checks_passed += 1

        if POLICY["require_edr"] and not device.get("edr_installed", False):
            violations.append({
                "check": "edr",
                "severity": SEVERITY_HIGH,
                "finding": f"No EDR installed on {device.get('hostname', device['device_id'])}",
            })
        else:
            checks_passed += 1

        screen_lock = device.get("screen_lock_minutes")
        if screen_lock is None or screen_lock > POLICY["screen_lock_max_minutes"]:
            violations.append({
                "check": "screen_lock",
                "severity": SEVERITY_HIGH,
                "finding": (
                    f"Screen lock timeout {screen_lock} min exceeds policy "
                    f"{POLICY['screen_lock_max_minutes']} min on {device.get('hostname', device['device_id'])}"
                ),
            })
        else:
            checks_passed += 1

        if POLICY["require_os_current"] and not device.get("os_up_to_date", False):
            violations.append({
                "check": "os_current",
                "severity": SEVERITY_HIGH,
                "finding": (
                    f"OS not up to date on {device.get('hostname', device['device_id'])} "
                    f"({device.get('os', 'unknown')})"
                ),
            })
        else:
            checks_passed += 1

        compliant = len(violations) == 0
        compliance_score = round(checks_passed / checks_total * 100)

        return {
            "device_id": device["device_id"],
            "hostname": device.get("hostname", ""),
            "owner": device.get("owner", ""),
            "violations": violations,
            "compliant": compliant,
            "compliance_score": compliance_score,
        }

    def run_checks(self) -> dict:
        devices = self.load_devices()
        device_results = []
        all_violations = []

        for device in devices:
            result = self.check_device(device)
            device_results.append(result)
            all_violations.extend(result["violations"])
            if result["violations"]:
                log.warning(
                    "Device policy violations",
                    extra={
                        "device_id": result["device_id"],
                        "hostname": result["hostname"],
                        "violation_count": len(result["violations"]),
                    },
                )
            else:
                log.info(
                    "Device compliant",
                    extra={"device_id": result["device_id"], "hostname": result["hostname"]},
                )

        # Persist compliance state back to DB
        if devices:
            compliant_by_id = {r["device_id"]: r["compliant"] for r in device_results}
            enriched = []
            for dev in devices:
                dev_copy = dict(dev)
                dev_copy["compliant"] = compliant_by_id.get(dev.get("device_id", ""), False)
                enriched.append(dev_copy)
            try:
                _run_async(self._save_inventory_db(enriched))
            except Exception as exc:
                log.warning(f"DB save MDM devices failed: {exc}")

        total = len(device_results)
        compliant_count = sum(1 for r in device_results if r["compliant"])
        non_compliant_count = total - compliant_count
        compliance_rate = round(compliant_count / total * 100, 1) if total > 0 else 0.0

        return {
            "total_devices": total,
            "compliant": compliant_count,
            "non_compliant": non_compliant_count,
            "compliance_rate_pct": compliance_rate,
            "violations": all_violations,
            "devices": device_results,
        }

    def _save_evidence(self, results: dict, controls_map: dict) -> None:
        content = json.dumps(results)

        edr_violations = [v for v in results["violations"] if v["check"] == "edr"]
        screen_lock_violations = [v for v in results["violations"] if v["check"] == "screen_lock"]
        filevault_violations = [v for v in results["violations"] if v["check"] == "filevault"]
        os_violations = [v for v in results["violations"] if v["check"] == "os_current"]

        cc66_id = controls_map.get("CC6.6")
        if cc66_id:
            try:
                self.evidence_client.create_evidence(
                    control_id=cc66_id,
                    title=f"[MDM] CC6.6 — EDR coverage scan ({results['total_devices']} devices)",
                    content=content,
                    source="AI_GENERATED",
                )
                status = "PASS" if len(edr_violations) == 0 else "FAIL"
                self.evidence_client.update_control_status(cc66_id, status)
                log.info("CC6.6 evidence saved", extra={"status": status, "edr_violations": len(edr_violations)})
            except Exception as exc:
                log.error("Failed to save CC6.6 evidence", extra={"error": str(exc)})

        cc68_id = controls_map.get("CC6.8")
        if cc68_id:
            try:
                self.evidence_client.create_evidence(
                    control_id=cc68_id,
                    title=f"[MDM] CC6.8 — Device security scan ({results['total_devices']} devices)",
                    content=content,
                    source="AI_GENERATED",
                )
                cc68_fail = len(filevault_violations) > 0 or len(screen_lock_violations) > 0 or len(os_violations) > 0
                status = "FAIL" if cc68_fail else "PASS"
                self.evidence_client.update_control_status(cc68_id, status)
                log.info("CC6.8 evidence saved", extra={"status": status})
            except Exception as exc:
                log.error("Failed to save CC6.8 evidence", extra={"error": str(exc)})


def main(controls_map: Optional[dict] = None) -> None:
    if controls_map is None:
        if not os.path.exists(CONTROLS_MAP_FILE):
            print(f"Error: {CONTROLS_MAP_FILE} not found. Run controls_seed.py first.")
            sys.exit(1)
        with open(CONTROLS_MAP_FILE, "r") as f:
            controls_map = json.load(f)

    agent = MDMAgent(EVIDENCE_TRACKER_URL, controls_map)
    results = agent.run_checks()

    edr_violations = [v for v in results["violations"] if v["check"] == "edr"]
    filevault_violations = [v for v in results["violations"] if v["check"] == "filevault"]
    screen_lock_violations = [v for v in results["violations"] if v["check"] == "screen_lock"]
    os_violations = [v for v in results["violations"] if v["check"] == "os_current"]

    print(
        f"[MDM] Devices: {results['total_devices']} total, "
        f"{results['compliant']} compliant ({results['compliance_rate_pct']}%), "
        f"{results['non_compliant']} non-compliant"
    )

    cc66_status = "FAIL" if edr_violations else "PASS"
    cc66_detail = f"{len(edr_violations)} devices without EDR" if edr_violations else "all devices have EDR"
    print(f"[MDM] CC6.6: {cc66_status} — {cc66_detail}")

    cc68_parts = []
    if filevault_violations:
        cc68_parts.append(f"{len(filevault_violations)} device(s) without FileVault")
    if screen_lock_violations:
        cc68_parts.append(f"{len(screen_lock_violations)} device(s) with screen lock > {POLICY['screen_lock_max_minutes']} min")
    if os_violations:
        cc68_parts.append(f"{len(os_violations)} device(s) with outdated OS")
    cc68_status = "FAIL" if cc68_parts else "PASS"
    cc68_detail = ", ".join(cc68_parts) if cc68_parts else "all devices meet security policy"
    print(f"[MDM] CC6.8: {cc68_status} — {cc68_detail}")

    agent._save_evidence(results, controls_map)


if __name__ == "__main__":
    main()
