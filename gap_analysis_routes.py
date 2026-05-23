from fastapi import APIRouter, Depends, HTTPException, Cookie
from typing import Optional
from auth import decode_token, ROLES
from gap_analysis_agent import GapAnalysisAgent, load_cache, save_cache
from pathlib import Path

router = APIRouter(prefix="/api/gap-analysis", tags=["gap-analysis"])
CACHE_FILE = Path(__file__).parent / "gap_analysis_cache.json"


def _get_current_user(access_token: Optional[str] = Cookie(default=None)) -> dict:
    """Получить текущего пользователя из JWT cookie."""
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(access_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload


def _require_admin(user: dict = Depends(_get_current_user)) -> dict:
    """Только Admin."""
    if user.get("role") not in ("admin", "Admin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


@router.get("")
async def get_gap_analysis(user: dict = Depends(_get_current_user)):
    """Получить результаты Gap Analysis из кеша."""
    cache = load_cache()
    if not cache:
        return {"cached": False, "message": "Run POST /api/gap-analysis/refresh first"}
    return cache


@router.get("/{control_id}")
async def get_control_gap(control_id: str, user: dict = Depends(_get_current_user)):
    """Получить анализ конкретного контроля из кеша."""
    cache = load_cache()
    if not cache:
        raise HTTPException(status_code=404, detail="Cache not found. Run refresh first.")

    for gap in cache.get("gaps", []):
        if gap.get("control_id") == control_id or gap.get("control_code") == control_id:
            return gap

    raise HTTPException(status_code=404, detail=f"Gap analysis for {control_id} not found in cache")


@router.post("/refresh")
async def refresh_gap_analysis(user: dict = Depends(_require_admin)):
    """Запустить новый полный AI Gap Analysis (только для Admin)."""
    agent = GapAnalysisAgent()
    try:
        report = await agent.run_full_analysis()
        save_cache(report)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gap analysis failed: {str(e)}")
