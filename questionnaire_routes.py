from fastapi import APIRouter, Depends, HTTPException, Body
from fastapi.responses import Response
from auth import require_auth, require_admin
from questionnaire_agent import QuestionnaireAgent

router = APIRouter(prefix="/api/questionnaires", tags=["questionnaires"])
_agent = QuestionnaireAgent()

@router.get("")
async def list_questionnaires(payload: dict = Depends(require_auth)):
    """Список ответов на вопросники (корневой GET — алиас для /responses)."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return _agent.get_all_responses()

@router.get("/templates")
async def get_templates():
    """Список доступных шаблонов (публичный)."""
    return [
        {"id": "sig_lite", "name": "SIG Lite", "questions_count": 20, "description": "Standardized Information Gathering Lite"},
        {"id": "caiq_lite", "name": "CAIQ Lite", "questions_count": 15, "description": "Consensus Assessments Initiative Questionnaire"}
    ]

@router.get("/templates/{template_id}")
async def get_template_questions(template_id: str):
    """Вопросы шаблона (публичный)."""
    template = _agent.QUESTIONNAIRES.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return template

@router.post("/generate")
async def generate_response(
    questionnaire_id: str = Body(..., embed=True),
    requester: dict = Body(..., embed=True),
    payload: dict = Depends(require_auth)
):
    """Сгенерировать ответы. Требует Admin или Auditor."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
        
    result = _agent.generate_response(questionnaire_id, requester)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.get("/responses")
async def get_responses(payload: dict = Depends(require_auth)):
    """Список всех сгенерированных ответов."""
    if payload.get("role") not in ("admin", "auditor"):
         raise HTTPException(status_code=403, detail="Insufficient permissions")
    return _agent.get_all_responses()

@router.get("/responses/{response_id}")
async def get_response(response_id: str, payload: dict = Depends(require_auth)):
    """Полный ответ с ответами на вопросы."""
    if payload.get("role") not in ("admin", "auditor"):
         raise HTTPException(status_code=403, detail="Insufficient permissions")
         
    resp = _agent.get_response_by_id(response_id)
    if not resp:
        raise HTTPException(status_code=404, detail="Response not found")
    return resp

@router.get("/responses/{response_id}/export")
async def export_response(response_id: str, payload: dict = Depends(require_auth)):
    """Текстовый экспорт ответов."""
    if payload.get("role") not in ("admin", "auditor"):
         raise HTTPException(status_code=403, detail="Insufficient permissions")
         
    text = _agent.export_to_text(response_id)
    return Response(
        content=text,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename=questionnaire_{response_id}.txt"}
    )
