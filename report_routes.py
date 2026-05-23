"""
report_routes.py — FastAPI эндпоинты для генерации и получения HTML отчётов SOC 2.
Подключается к ui_server.py через report_routes_wiring.txt.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException
from fastapi.responses import FileResponse

from auth import decode_token, ROLES
from html_report import HTMLReportGenerator, REPORTS_DIR
from log_config import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/reports", tags=["reports"])


# ── Зависимости авторизации ───────────────────────────────────────────────────

async def _require_auth(access_token: Optional[str] = Cookie(None)) -> Dict[str, Any]:
    """Требует любой валидный JWT-токен."""
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(access_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token invalid or expired")
    return payload


async def _require_admin_or_auditor(
    user: Dict[str, Any] = Depends(_require_auth),
) -> Dict[str, Any]:
    """
    Ограничивает доступ ролями admin и auditor.
    scanner/viewer не могут генерировать отчёты.
    """
    role = user.get("role", "")
    if role not in ("admin", "auditor"):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: role '{role}' cannot generate reports. Required: admin or auditor.",
        )
    return user


# ── Эндпоинты ─────────────────────────────────────────────────────────────────


@router.get(
    "/html",
    summary="Сгенерировать HTML отчёт",
    response_description="HTML файл отчёта для скачивания",
)
async def generate_html_report(
    user: Dict[str, Any] = Depends(_require_admin_or_auditor),
) -> FileResponse:
    """
    Генерирует полный HTML отчёт SOC 2 и отдаёт его как загрузку.

    Требует роль: admin или auditor.
    Отчёт сохраняется в reports/ и возвращается как attachment.
    """
    log.info(
        "Запрос генерации HTML отчёта",
        extra={"user": user.get("email"), "role": user.get("role")},
    )

    try:
        generator = HTMLReportGenerator()
        report_path = generator.generate_standalone()
    except Exception as exc:
        log.error("Ошибка генерации HTML отчёта", extra={"error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")

    # Формируем имя файла для заголовка Content-Disposition
    filename = report_path.name

    return FileResponse(
        path=str(report_path),
        media_type="text/html",
        filename=filename,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.get(
    "/list",
    summary="Список сгенерированных отчётов",
    response_description="Список HTML файлов из директории reports/",
)
async def list_reports(
    user: Dict[str, Any] = Depends(_require_auth),
) -> List[Dict[str, Any]]:
    """
    Возвращает список всех HTML отчётов в директории reports/.
    Доступно для любой авторизованной роли.

    Поля каждого элемента:
    - filename: имя файла
    - size_kb: размер в килобайтах
    - created_at: дата создания (ISO format)
    - download_url: относительный URL для скачивания
    """
    # Создаём директорию если не существует
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    reports: List[Dict[str, Any]] = []

    try:
        # Собираем только HTML файлы, сортируем по дате изменения (новые первые)
        html_files = sorted(
            REPORTS_DIR.glob("*.html"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

        for path in html_files:
            stat = path.stat()
            created_at = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()

            reports.append({
                "filename":     path.name,
                "size_kb":      round(stat.st_size / 1024, 1),
                "created_at":   created_at,
                "download_url": f"/api/reports/download/{path.name}",
            })

    except Exception as exc:
        log.error("Ошибка чтения директории reports/", extra={"error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Failed to list reports: {exc}")

    return reports


@router.get(
    "",
    summary="Список отчётов (корневой GET)",
    include_in_schema=False,
)
async def list_reports_root(
    user: Dict[str, Any] = Depends(_require_auth),
) -> List[Dict[str, Any]]:
    """Корневой GET — алиас для /api/reports/list."""
    return await list_reports(user)


@router.get(
    "/download/{filename}",
    summary="Скачать конкретный отчёт по имени файла",
    response_description="HTML файл отчёта",
)
async def download_report(
    filename: str,
    user: Dict[str, Any] = Depends(_require_auth),
) -> FileResponse:
    """
    Отдаёт существующий HTML отчёт по имени файла.
    Доступно для любой авторизованной роли.

    Защита от path traversal: только файлы внутри reports/.
    """
    # Защита от path traversal атак — только имя файла, без слешей
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Только .html файлы
    if not filename.endswith(".html"):
        raise HTTPException(status_code=400, detail="Only .html reports are available")

    report_path = REPORTS_DIR / filename

    if not report_path.exists():
        raise HTTPException(status_code=404, detail=f"Report '{filename}' not found")

    # Проверяем что файл действительно в папке reports/ (дополнительная защита)
    try:
        report_path.resolve().relative_to(REPORTS_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied")

    return FileResponse(
        path=str(report_path),
        media_type="text/html",
        filename=filename,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.delete(
    "/{filename}",
    summary="Удалить отчёт",
    response_description="Подтверждение удаления",
)
async def delete_report(
    filename: str,
    user: Dict[str, Any] = Depends(_require_admin_or_auditor),
) -> Dict[str, str]:
    """
    Удаляет HTML отчёт по имени файла.
    Требует роль: admin или auditor.
    """
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    if not filename.endswith(".html"):
        raise HTTPException(status_code=400, detail="Only .html reports can be deleted")

    report_path = REPORTS_DIR / filename

    if not report_path.exists():
        raise HTTPException(status_code=404, detail=f"Report '{filename}' not found")

    try:
        report_path.unlink()
        log.info("Отчёт удалён", extra={"filename": filename, "user": user.get("email")})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete report: {exc}")

    return {"detail": f"Report '{filename}' deleted successfully"}
