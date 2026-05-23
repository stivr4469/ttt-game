import hmac, hashlib, json, os, datetime, urllib.parse
from pathlib import Path
from fastapi import APIRouter, Request, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
from log_config import get_logger
from auth import decode_token, require_admin, require_auth
from tasks import rescan_control
from slack_actions_handler import SlackActionsHandler

router = APIRouter(tags=["webhooks"])
log = get_logger(__name__)

# Singleton обработчика Slack actions — создаётся один раз при импорте модуля
actions_handler = SlackActionsHandler()

GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
OKTA_WEBHOOK_TOKEN    = os.getenv("OKTA_WEBHOOK_TOKEN", "")
EVENTS_FILE = Path(__file__).parent / "webhook_events.json"

GITHUB_EVENT_CONTROL_MAP = {
    "push":                     ["CC8.1", "CC5.3"],
    "pull_request":             ["CC5.3", "CC3.4"],
    "repository_vulnerability_alert": ["CC6.8", "CC7.3"],
    "security_advisory":        ["CC7.3"],
    "create":                   ["CC8.1"],
    "delete":                   ["CC8.1"],
}

OKTA_EVENT_CONTROL_MAP = {
    "user.lifecycle.deactivate":  ["CC6.2"],
    "user.lifecycle.create":      ["CC6.2"],
    "user.account.lock":          ["CC6.1"],
    "user.mfa.factor.deactivate": ["CC6.1"],
    "user.session.start":         ["CC6.1"],
}

def _verify_github_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not secret:
        return True  # верификация отключена
    if not signature:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

def _log_webhook_event(source: str, event: str, controls: list):
    entry = {
        "source": source,
        "event": event,
        "controls": controls,
        "ts": datetime.datetime.utcnow().isoformat()
    }
    events = []
    if EVENTS_FILE.exists():
        try:
            events = json.loads(EVENTS_FILE.read_text())
        except:
            events = []
    events.append(entry)
    events = events[-100:]
    EVENTS_FILE.write_text(json.dumps(events, indent=2, ensure_ascii=False))

@router.post("/webhooks/github")
async def github_webhook(request: Request, x_hub_signature_256: str = Header(None), x_github_event: str = Header(None)):
    payload = await request.body()
    if not _verify_github_signature(payload, x_hub_signature_256, GITHUB_WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid GitHub signature")
    
    controls = GITHUB_EVENT_CONTROL_MAP.get(x_github_event, [])
    for ctrl in controls:
        rescan_control.delay(ctrl, f"github_{x_github_event}")
    
    _log_webhook_event("github", x_github_event, controls)
    return {"received": True, "controls_triggered": controls}

@router.post("/webhooks/okta")
async def okta_webhook(request: Request, authorization: str = Header(None)):
    if OKTA_WEBHOOK_TOKEN and authorization != f"SSWS {OKTA_WEBHOOK_TOKEN}":
        raise HTTPException(status_code=401, detail="Invalid Okta token")
    
    data = await request.json()
    triggered_controls = []
    
    # Okta events structure can vary, but usually it's data.events
    events = data.get("data", {}).get("events", [])
    if not events and "eventType" in data: # sometimes it's a single event or different structure
        events = [data]

    for event in events:
        event_type = event.get("eventType")
        controls = OKTA_EVENT_CONTROL_MAP.get(event_type, [])
        for ctrl in controls:
            rescan_control.delay(ctrl, f"okta_{event_type}")
            if ctrl not in triggered_controls:
                triggered_controls.append(ctrl)
        
        if event_type:
            _log_webhook_event("okta", event_type, controls)

    return {"received": True, "controls_triggered": triggered_controls}

@router.post("/webhooks/slack")
async def slack_webhook(request: Request):
    """
    Обрабатывает входящие события от Slack:
    - Slack Interactivity (block_actions): application/x-www-form-urlencoded с полем payload
    - Обычные события Slack Events API: application/json
    """
    body = await request.body()

    # Slack Interactivity шлёт application/x-www-form-urlencoded с полем payload
    if b"payload=" in body:
        try:
            raw_form = body.decode("utf-8")
            raw_json = urllib.parse.unquote(raw_form.split("payload=", 1)[1])
            payload = json.loads(raw_json)
        except (ValueError, IndexError) as exc:
            log.error("Failed to parse Slack interactivity payload", extra={"error": str(exc)})
            raise HTTPException(status_code=400, detail="Invalid Slack payload format")

        result = actions_handler.handle(payload)
        _log_webhook_event("slack_action", payload.get("type", "block_actions"), [])
        return {"ok": True, "result": result.to_dict()}

    # Обычные события Slack Events API
    try:
        data = json.loads(body) if body else {}
    except (ValueError, json.JSONDecodeError):
        data = {}

    # Slack URL verification challenge
    if data.get("type") == "url_verification":
        return {"challenge": data.get("challenge", "")}

    _log_webhook_event("slack", data.get("type", "event"), [])
    return {"received": True}


@router.get("/api/slack/actions/history")
async def slack_actions_history(
    limit: int = 50,
    user: dict = Depends(require_auth),
):
    """Последние выполненные Slack actions (до 50 записей)."""
    clamped = min(max(limit, 1), 200)
    history = actions_handler.get_history(limit=clamped)
    return {"history": history, "total": len(history)}


@router.get("/api/slack/actions/stats")
async def slack_actions_stats(user: dict = Depends(require_auth)):
    """Агрегированная статистика выполненных Slack actions по типам."""
    return actions_handler.get_stats()

@router.get("/api/webhooks/log")
async def get_webhook_log(payload: dict = Depends(require_admin)):
    events = []
    if EVENTS_FILE.exists():
        try:
            events = json.loads(EVENTS_FILE.read_text())
        except:
            events = []
    return {"events": events[-50:], "total": len(events)}
