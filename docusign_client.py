import os
import base64
import requests
from typing import Dict
from log_config import get_logger

log = get_logger(__name__)

DOCUSIGN_BASE_URL = os.getenv("DOCUSIGN_BASE_URL", "https://demo.docusign.net/restapi")


class DocuSignClient:
    """
    Клиент DocuSign eSignature REST API v2.1.
    Auth: Bearer token (DOCUSIGN_ACCESS_TOKEN).
    """

    def __init__(self, account_id: str, access_token: str, base_url: str = DOCUSIGN_BASE_URL):
        self.account_id = account_id
        self.base_url   = base_url.rstrip("/")
        self._session   = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {access_token}",
            "Content-Type":  "application/json",
        })

    def _api(self, method: str, path: str, **kwargs) -> Dict:
        url = f"{self.base_url}/v2.1/accounts/{self.account_id}{path}"
        resp = self._session.request(method, url, timeout=20, **kwargs)
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def create_envelope(
        self,
        document_name: str,
        document_content: str,
        signer_email: str,
        signer_name: str,
        email_subject: str = "Please sign this compliance policy",
    ) -> Dict:
        doc_b64 = base64.b64encode(document_content.encode()).decode()
        body = {
            "emailSubject": email_subject,
            "documents": [
                {
                    "documentBase64": doc_b64,
                    "name":           document_name,
                    "fileExtension":  "txt",
                    "documentId":     "1",
                }
            ],
            "recipients": {
                "signers": [
                    {
                        "email":        signer_email,
                        "name":         signer_name,
                        "recipientId":  "1",
                        "routingOrder": "1",
                        "tabs": {
                            "signHereTabs": [
                                {
                                    "documentId":  "1",
                                    "pageNumber":  "1",
                                    "xPosition":   "100",
                                    "yPosition":   "150",
                                }
                            ]
                        },
                    }
                ]
            },
            "status": "sent",
        }
        result = self._api("POST", "/envelopes", json=body)
        log.info(
            "DocuSign envelope created",
            extra={"envelope_id": result.get("envelopeId"), "signer": signer_email},
        )
        return {
            "envelope_id": result.get("envelopeId"),
            "status":      result.get("status"),
            "uri":         result.get("uri"),
        }

    def get_envelope_status(self, envelope_id: str) -> Dict:
        result = self._api("GET", f"/envelopes/{envelope_id}")
        return {
            "envelope_id":  envelope_id,
            "status":       result.get("status"),
            "completed_at": result.get("completedDateTime"),
        }

    def get_signing_url(self, envelope_id: str, signer_email: str, signer_name: str, return_url: str) -> str:
        body = {
            "authenticationMethod": "none",
            "email":       signer_email,
            "recipientId": "1",
            "returnUrl":   return_url,
            "userName":    signer_name,
        }
        result = self._api("POST", f"/envelopes/{envelope_id}/views/recipient", json=body)
        return result.get("url", "")
