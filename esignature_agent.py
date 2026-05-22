import os
import json
import uuid
import argparse
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional
from dotenv import load_dotenv
from evidence_client import EvidenceClient
from log_config import get_logger
from constants import CONTROLS_MAP_FILE

load_dotenv()
log = get_logger(__name__)

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")
SIGNATURES_FILE = "policy_signatures.json"

SIGNATURE_REQUIRED_CONTROLS = {
    "CC1.1": "Information Security and Ethical Values Policy",
    "CC1.5": "Accountability and Disciplinary Action Policy",
    "CC3.1": "Risk Assessment Objectives and Risk Appetite Policy",
    "CC5.3": "Change Management Policy",
    "CC7.4": "Incident Response Policy",
    "CC9.1": "Business Continuity Policy",
}


def _load_signatures() -> dict:
    if not os.path.exists(SIGNATURES_FILE):
        return {"signatures": []}
    with open(SIGNATURES_FILE, "r") as f:
        return json.load(f)


def _save_signatures(data: dict) -> None:
    with open(SIGNATURES_FILE, "w") as f:
        json.dump(data, f, indent=2)


class ESignatureAgent:
    def __init__(self) -> None:
        self._client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="esignature")

    def create_signature_request(
        self,
        control_code: str,
        policy_title: str,
        signer_email: str,
        signer_name: str,
    ) -> dict:
        envelope_id = secrets.token_hex(16)
        signature_token = hashlib.sha256(
            f"{envelope_id}{control_code}{signer_email}".encode()
        ).hexdigest()

        signature_url = ""
        if os.getenv("DOCUSIGN_ACCESS_TOKEN") and os.getenv("DOCUSIGN_ACCOUNT_ID"):
            try:
                from docusign_client import DocuSignClient
                ds = DocuSignClient(
                    account_id=os.getenv("DOCUSIGN_ACCOUNT_ID", ""),
                    access_token=os.getenv("DOCUSIGN_ACCESS_TOKEN", ""),
                )
                content = f"Policy: {policy_title}\nControl: {control_code}\nSigner: {signer_name}"
                result = ds.create_envelope(
                    document_name=policy_title,
                    document_content=content,
                    signer_email=signer_email,
                    signer_name=signer_name,
                )
                envelope_id   = result["envelope_id"]
                signature_url = f"https://demo.docusign.net/Signing/MTRedeem/v1?t={envelope_id}"
                log.info("Real DocuSign envelope created", extra={"envelope_id": envelope_id})
            except Exception as e:
                log.warning("DocuSign unavailable, using mock", extra={"error": str(e)})
                signature_url = f"https://mock-docusign.example.com/sign/{envelope_id[:8]}"
        else:
            signature_url = f"https://mock-docusign.example.com/sign/{envelope_id[:8]}"

        record = {
            "envelope_id": envelope_id,
            "control_code": control_code,
            "policy_title": policy_title,
            "signer_email": signer_email,
            "signer_name": signer_name,
            "status": "sent",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "signed_at": None,
            "signature_token": signature_token,
        }

        data = _load_signatures()
        data["signatures"].append(record)
        _save_signatures(data)

        log.info(
            "Signature request created",
            extra={"envelope_id": envelope_id, "control": control_code, "signer": signer_email},
        )

        return {"envelope_id": envelope_id, "signature_url": signature_url}

    def simulate_signature(self, envelope_id: str) -> dict:
        data = _load_signatures()
        record = next(
            (s for s in data["signatures"] if s["envelope_id"] == envelope_id), None
        )
        if record is None:
            return {"error": "envelope not found"}

        record["status"] = "signed"
        record["signed_at"] = datetime.now(timezone.utc).isoformat()
        record["signatory_ip"] = "192.168.1.100"
        _save_signatures(data)

        return self.process_signed_policy(envelope_id)

    def process_signed_policy(self, envelope_id: str) -> dict:
        data = _load_signatures()
        record = next(
            (s for s in data["signatures"] if s["envelope_id"] == envelope_id), None
        )
        if record is None:
            return {"error": "envelope not found"}

        controls_map: Optional[dict] = None
        if os.path.exists(CONTROLS_MAP_FILE):
            with open(CONTROLS_MAP_FILE, "r") as f:
                controls_map = json.load(f)

        control_code = record["control_code"]
        policy_title = record["policy_title"]

        content = json.dumps({
            "envelope_id": envelope_id,
            "signer": record["signer_name"],
            "signed_at": record.get("signed_at"),
            "signature_token": record["signature_token"],
            "status": "signed",
            "audit_trail": "DocuSign-compatible sandbox signature",
        })

        evidence_id = None
        if controls_map and control_code in controls_map:
            control_id = controls_map[control_code]
            try:
                ev = self._client.create_evidence(
                    control_id=control_id,
                    title=f"[SIGNED] {policy_title}",
                    content=content,
                    source="MANUAL",
                )
                evidence_id = ev.get("id")
                self._client.update_control_status(control_id, "PASS")
                log.info(
                    "Signed policy evidence created",
                    extra={"envelope_id": envelope_id, "control": control_code, "evidence_id": evidence_id},
                )
            except Exception as e:
                log.error(
                    "Failed to create evidence for signed policy",
                    extra={"envelope_id": envelope_id, "control": control_code, "error": str(e)},
                )

        return {"status": "processed", "control_code": control_code, "evidence_id": evidence_id}

    def check_docusign_status(self, envelope_id: str) -> dict:
        """Проверяет реальный статус подписи в DocuSign (если настроен)."""
        if not os.getenv("DOCUSIGN_ACCESS_TOKEN"):
            return {"envelope_id": envelope_id, "source": "mock"}
        try:
            from docusign_client import DocuSignClient
            ds = DocuSignClient(os.getenv("DOCUSIGN_ACCOUNT_ID", ""), os.getenv("DOCUSIGN_ACCESS_TOKEN", ""))
            return ds.get_envelope_status(envelope_id)
        except Exception as e:
            log.error("DocuSign status check failed", extra={"envelope_id": envelope_id, "error": str(e)})
            return {"envelope_id": envelope_id, "error": str(e)}

    def get_pending_signatures(self) -> list:
        data = _load_signatures()
        return [s for s in data["signatures"] if s.get("status") == "sent"]

    def send_all_policies(
        self,
        controls_map: dict,
        signer_email: str,
        signer_name: str,
    ) -> list:
        envelope_ids = []
        for control_code, policy_title in SIGNATURE_REQUIRED_CONTROLS.items():
            if control_code not in controls_map:
                log.info("Control not in controls_map, skipping", extra={"control": control_code})
                continue
            result = self.create_signature_request(control_code, policy_title, signer_email, signer_name)
            envelope_ids.append(result["envelope_id"])
        return envelope_ids


def main(controls_map: Optional[dict] = None) -> None:
    parser = argparse.ArgumentParser(description="E-Signature Agent for SOC 2 Policies")
    parser.add_argument("--send", action="store_true", help="Send all policies for signature")
    parser.add_argument("--simulate", metavar="ENVELOPE_ID", help="Simulate signing of envelope")
    parser.add_argument("--simulate-all", action="store_true", help="Simulate signing all pending")
    parser.add_argument("--status", action="store_true", help="Show pending signatures")
    parser.add_argument("--signer-email", default="ciso@acme.com")
    parser.add_argument("--signer-name", default="Chief Information Security Officer")
    args = parser.parse_args()

    agent = ESignatureAgent()

    if args.status:
        pending = agent.get_pending_signatures()
        print(f"Pending signatures: {len(pending)}")
        for p in pending:
            print(f"  {p['envelope_id'][:8]}... | {p['control_code']} | {p['policy_title']} | {p['signer_email']}")
        return

    if controls_map is None:
        if os.path.exists(CONTROLS_MAP_FILE):
            with open(CONTROLS_MAP_FILE, "r") as f:
                controls_map = json.load(f)
        else:
            controls_map = {}

    if args.send:
        envelope_ids = agent.send_all_policies(controls_map, args.signer_email, args.signer_name)
        print(f"Sent {len(envelope_ids)} signature requests")
        for eid in envelope_ids:
            print(f"  envelope: {eid}")
        return

    if args.simulate:
        result = agent.simulate_signature(args.simulate)
        print(json.dumps(result, indent=2))
        return

    if args.simulate_all:
        pending = agent.get_pending_signatures()
        print(f"Simulating {len(pending)} pending signatures...")
        for p in pending:
            result = agent.simulate_signature(p["envelope_id"])
            print(f"  {p['envelope_id'][:8]}... → {result}")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
