#!/usr/bin/env python3
"""
prowler_runner.py — запускает настоящий Prowler 5.x против LocalStack,
парсит JSON-OCSF вывод и сохраняет результаты в Evidence Tracker.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

from dotenv import load_dotenv

from constants import CONTROLS_MAP_FILE
from evidence_client import EvidenceClient
from log_config import get_logger

load_dotenv()
log = get_logger(__name__)

LOCALSTACK_ENDPOINT  = os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")
AWS_USE_LOCALSTACK   = os.getenv("AWS_USE_LOCALSTACK", "true").lower() == "true"
AWS_REGION           = os.getenv("AWS_DEFAULT_REGION", "us-east-1")


def _build_soc2_check_map() -> dict[str, list[str]]:
    """
    Читает soc2_aws.json из пакета prowler.
    Возвращает: check_id → ["CC6.1", "CC6.3", ...]
    """
    try:
        spec = importlib.util.find_spec("prowler")
        if spec is None:
            return {}
        soc2_path = Path(spec.origin).parent / "compliance" / "aws" / "soc2_aws.json"
        with open(soc2_path) as f:
            data = json.load(f)
    except Exception as e:
        log.error("Не удалось загрузить soc2_aws.json: %s", e)
        return {}

    mapping: dict[str, list[str]] = {}
    for req in data.get("Requirements", []):
        req_id = req.get("Id", "")         # "cc_6_1"
        parts  = req_id.split("_")         # ["cc", "6", "1"]
        if not parts or parts[0] != "cc" or len(parts) < 3:
            continue
        cc = "CC" + parts[1] + "." + ".".join(parts[2:])  # "CC6.1"
        for check_id in req.get("Checks", []):
            mapping.setdefault(check_id, [])
            if cc not in mapping[check_id]:
                mapping[check_id].append(cc)
    return mapping


def _prowler_status(raw: str) -> str:
    return {"PASS": "PASS", "FAIL": "FAIL"}.get(raw.upper(), "NA")


def run_prowler_scan(output_dir: str) -> Path | None:
    """Запускает prowler aws --compliance soc2_aws, возвращает путь к JSON файлу."""
    env = {
        **os.environ,
        "AWS_ACCESS_KEY_ID":     os.getenv("AWS_ACCESS_KEY_ID", "test"),
        "AWS_SECRET_ACCESS_KEY": os.getenv("AWS_SECRET_ACCESS_KEY", "test"),
        "AWS_DEFAULT_REGION":    AWS_REGION,
        "PYTHONUNBUFFERED":      "1",
    }
    if AWS_USE_LOCALSTACK:
        env["AWS_ENDPOINT_URL"] = LOCALSTACK_ENDPOINT

    cmd = [
        "prowler", "aws",
        "--compliance", "soc2_aws",
        "--no-banner",
        "--output-formats", "json-ocsf",
        "--output-directory", output_dir,
        "--ignore-exit-code-3",
    ]

    mode = f"LocalStack ({LOCALSTACK_ENDPOINT})" if AWS_USE_LOCALSTACK else f"Real AWS ({AWS_REGION})"
    print(f"\n{'='*60}")
    print(f" PROWLER SOC 2 v5 | {mode}")
    print(f"{'='*60}\n")

    proc = subprocess.run(cmd, env=env)

    matches = sorted(Path(output_dir).glob("*.ocsf.json"))
    if not matches:
        log.error("Prowler не создал ocsf.json в %s", output_dir)
        return None
    return matches[-1]


def process_findings(
    json_path: Path,
    soc2_check_map: dict[str, list[str]],
    controls_map: dict[str, str],
    ec: EvidenceClient,
) -> dict:
    """Читает OCSF JSON, сохраняет evidence + test_results."""
    with open(json_path) as f:
        findings = json.load(f)

    stats: dict[str, int] = {"PASS": 0, "FAIL": 0, "NA": 0, "total": 0}
    cc_results: dict[str, str] = {}
    batch_results: list[dict] = []

    for finding in findings:
        check_id = finding.get("metadata", {}).get("event_code", "unknown")
        raw_st   = finding.get("status_code") or finding.get("status", "UNKNOWN")
        status   = _prowler_status(raw_st)
        severity = finding.get("severity", "informational")
        resource = (finding.get("resources") or [{}])[0].get("uid", "*")
        message  = finding.get("message", "")[:500]

        cc_codes = soc2_check_map.get(check_id, [])

        stats[status] = stats.get(status, 0) + 1
        stats["total"] += 1

        icon = {"PASS": "✅", "FAIL": "❌"}.get(status, "⬜")
        print(f"{icon} {check_id:<55} {status:<6} {resource[:30]}")

        for cc in cc_codes:
            cid = controls_map.get(cc)
            if not cid:
                continue

            # Итоговый статус контрола
            if status == "FAIL":
                cc_results[cc] = "FAIL"
            elif status == "PASS" and cc_results.get(cc) != "FAIL":
                cc_results[cc] = "PASS"

            ec.create_evidence(
                control_id=cid,
                title=f"[Prowler] {check_id}: {status} — {resource[:50]}",
                content=json.dumps({
                    "check_id":  check_id,
                    "resource":  resource,
                    "status":    raw_st,
                    "severity":  severity,
                    "message":   message,
                    "cc":        cc,
                    "scan_date": str(date.today()),
                    "mode":      "localstack" if AWS_USE_LOCALSTACK else "real_aws",
                }, ensure_ascii=False),
                source="PROWLER",
            )

            if status in ("PASS", "FAIL"):
                batch_results.append({
                    "test_key":    f"prowler.{check_id}",
                    "resource_id": resource[:200],
                    "status":      status,
                    "details":     {
                        "control_id": cid,
                        "check_id":   check_id,
                        "severity":   severity,
                        "cc":         cc,
                    },
                })

    if batch_results:
        ec.submit_test_results(producer="prowler", results=batch_results)

    return {"stats": stats, "cc_results": cc_results}


def main(controls_map: dict | None = None):
    if controls_map is None:
        if not os.path.exists(CONTROLS_MAP_FILE):
            print(f"Error: {CONTROLS_MAP_FILE} not found.")
            sys.exit(1)
        with open(CONTROLS_MAP_FILE) as f:
            controls_map = json.load(f)

    soc2_check_map = _build_soc2_check_map()
    if not soc2_check_map:
        print("❌ Не удалось загрузить SOC2 маппинг из Prowler пакета")
        sys.exit(1)

    print(f"📋 SOC2 маппинг: {len(soc2_check_map)} checks → CC controls")

    ec = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="prowler")

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = run_prowler_scan(tmpdir)
        if json_path is None:
            print("❌ Prowler не вернул результаты")
            sys.exit(1)

        size_kb = json_path.stat().st_size // 1024
        print(f"\n📄 Результаты: {json_path.name} ({size_kb} KB)\n")
        result = process_findings(json_path, soc2_check_map, controls_map, ec)

    stats      = result["stats"]
    cc_results = result["cc_results"]

    print(f"\n{'='*60}")
    print(f" ИТОГ")
    print(f"{'='*60}")
    print(f"  Всего findings:  {stats['total']}")
    print(f"  ✅ PASS:         {stats.get('PASS', 0)}")
    print(f"  ❌ FAIL:         {stats.get('FAIL', 0)}")
    print(f"  ⬜ NA/MUTED:     {stats.get('NA', 0)}")
    fail_cc = [c for c, s in cc_results.items() if s == "FAIL"]
    pass_cc = [c for c, s in cc_results.items() if s == "PASS"]
    print(f"  CC PASS: {len(pass_cc)} | CC FAIL: {len(fail_cc)}")
    if fail_cc:
        print(f"  Проблемные controls: {fail_cc}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
