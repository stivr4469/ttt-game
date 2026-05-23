from fastapi import APIRouter, Depends, HTTPException, Body
from auth import require_auth, require_admin
from training_agent import TrainingAgent
from typing import Dict

router = APIRouter(prefix="/api/training", tags=["training"])
_agent = TrainingAgent()

@router.get("/courses")
async def get_courses(payload: dict = Depends(require_auth)):
    """Список всех курсов (без вопросов)."""
    return _agent.get_all_courses()

@router.get("/course/{course_id}")
async def get_course(course_id: str, payload: dict = Depends(require_auth)):
    """Курс с вопросами (БЕЗ правильных ответов)."""
    course = _agent.get_course_with_questions(course_id)
    if not course:
        raise HTTPException(status_code=404, detail="Course not found")
    return course

@router.get("/my-progress")
async def get_my_progress(payload: dict = Depends(require_auth)):
    """Прогресс текущего пользователя."""
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Email not found in token")
    return _agent.get_user_completions(email)

@router.post("/course/{course_id}/submit")
async def submit_quiz(course_id: str, answers: Dict[str, int] = Body(...), payload: dict = Depends(require_auth)):
    """Сдать тест."""
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Email not found in token")
    
    result = _agent.submit_quiz(email, course_id, answers)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.get("/compliance-report")
async def get_compliance_report(payload: dict = Depends(require_auth)):
    """Полный отчёт по всем сотрудникам (Admin/Auditor)."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Admin or Auditor role required")
    
    report = _agent.get_compliance_report()
    if "error" in report:
        raise HTTPException(status_code=500, detail=report["error"])
    return report

@router.get("/completions")
async def get_completions(payload: dict = Depends(require_auth)):
    """Алиас для /compliance-report — список завершений курсов."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Admin or Auditor role required")
    report = _agent.get_compliance_report()
    if "error" in report:
        raise HTTPException(status_code=500, detail=report["error"])
    return report

@router.post("/send-reminders")
async def send_reminders(payload: dict = Depends(require_admin)):
    """Отправить Slack напоминания (только Admin)."""
    count = _agent.send_reminders()
    return {"reminders_sent": count}
