"""
Роутер: /api/frameworks

Endpoints:
  GET  /api/frameworks                           — список всех фреймворков в каталоге
  GET  /api/frameworks/cached                    — только загруженные локально
  GET  /api/frameworks/{id}                      — мета-информация фреймворка
  GET  /api/frameworks/{id}/controls             — контроли (assessable_only по умолчанию)
  GET  /api/frameworks/{id}/controls/{ref_id}    — конкретный контроль
  GET  /api/frameworks/{id}/search?q=...         — поиск внутри фреймворка
  POST /api/frameworks/{id}/download             — скачать/обновить YAML с GitHub
  POST /api/frameworks/download-all              — скачать все 12 фреймворков
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query

from auth import require_auth, require_admin
from framework_library import FRAMEWORK_CATALOG, FrameworkLibrary, get_library

router = APIRouter(prefix="/api/frameworks", tags=["framework-library"])


def _meta_to_dict(lib: FrameworkLibrary, framework_id: str) -> dict:
    meta = lib.get_meta(framework_id)
    if meta is None:
        return {
            "id": framework_id,
            "filename": FRAMEWORK_CATALOG.get(framework_id, ""),
            "cached": (lib.data_dir / f"{framework_id}.yaml").exists(),
            "loaded": False,
        }
    return {**asdict(meta), "cached": True, "loaded": True}


@router.get("")
async def list_frameworks(
    payload: dict = Depends(require_auth),
) -> list[dict]:
    """Все фреймворки из каталога с флагами cached/loaded."""
    lib = get_library()
    cached = set(lib.list_cached())
    result = []
    for fid in lib.list_available():
        if fid in cached:
            result.append(_meta_to_dict(lib, fid))
        else:
            result.append({
                "id": fid,
                "filename": FRAMEWORK_CATALOG[fid],
                "cached": False,
                "loaded": False,
            })
    return result


@router.get("/all")
async def list_all_frameworks(
    payload: dict = Depends(require_auth),
) -> list[dict]:
    """Все скачанные фреймворки (все YAML в data/frameworks/) с быстрыми метаданными.

    Возвращает до 264 фреймворков — все что есть на диске, включая не-каталожные.
    Не загружает requirement_nodes — только верхнеуровневые поля.
    """
    lib = get_library()
    return lib.list_all_meta()


@router.get("/cached")
async def list_cached_frameworks(
    payload: dict = Depends(require_auth),
) -> list[dict]:
    """Только фреймворки, загруженные в data/frameworks/."""
    lib = get_library()
    return [_meta_to_dict(lib, fid) for fid in lib.list_cached()]


@router.get("/{framework_id}/controls")
async def get_controls(
    framework_id: str,
    assessable_only: bool = Query(True, description="Только leaf-контроли (assessable=true)"),
    depth: Optional[int] = Query(None, description="Фильтр по уровню иерархии"),
    payload: dict = Depends(require_auth),
) -> dict:
    """Контроли фреймворка. Автоматически скачивает YAML если не кеширован."""
    lib = get_library()
    if framework_id not in FRAMEWORK_CATALOG:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown framework: {framework_id!r}. Available: {lib.list_available()}",
        )
    try:
        controls = lib.get_controls(framework_id, assessable_only=assessable_only)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    if depth is not None:
        controls = [c for c in controls if c.depth == depth]

    return {
        "framework_id": framework_id,
        "assessable_only": assessable_only,
        "total": len(controls),
        "controls": [asdict(c) for c in controls],
    }


@router.get("/{framework_id}/search")
async def search_controls(
    framework_id: str,
    q: str = Query(..., min_length=1, description="Поиск в ref_id, name, description"),
    assessable_only: bool = Query(True),
    payload: dict = Depends(require_auth),
) -> dict:
    """Поиск по контролям фреймворка."""
    lib = get_library()
    if framework_id not in FRAMEWORK_CATALOG:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework_id!r}")
    try:
        results = lib.search_controls(framework_id, q.strip(), assessable_only=assessable_only)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "framework_id": framework_id,
        "query": q.strip(),
        "total": len(results),
        "results": [asdict(c) for c in results],
    }


@router.get("/{framework_id}/controls/{ref_id:path}")
async def get_control(
    framework_id: str,
    ref_id: str,
    payload: dict = Depends(require_auth),
) -> dict:
    """Конкретный контроль по ref_id (например ID.AM-1, 8.3, Art.32)."""
    lib = get_library()
    if framework_id not in FRAMEWORK_CATALOG:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework_id!r}")
    try:
        controls = lib.get_controls(framework_id, assessable_only=False)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    ref_upper = ref_id.upper()
    match = next((c for c in controls if c.ref_id == ref_upper), None)
    if match is None:
        raise HTTPException(
            status_code=404,
            detail=f"Control '{ref_id}' not found in framework '{framework_id}'",
        )
    return asdict(match)


@router.get("/{framework_id}")
async def get_framework_meta(
    framework_id: str,
    payload: dict = Depends(require_auth),
) -> dict:
    """Мета-информация фреймворка (загружает YAML если не кеширован)."""
    lib = get_library()
    if framework_id not in FRAMEWORK_CATALOG:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown framework: {framework_id!r}. Available: {lib.list_available()}",
        )
    try:
        return _meta_to_dict(lib, framework_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/{framework_id}/download")
async def download_framework(
    framework_id: str,
    background_tasks: BackgroundTasks,
    payload: dict = Depends(require_admin),
) -> dict:
    """Скачать или обновить YAML фреймворка с GitHub (admin only)."""
    lib = get_library()
    if framework_id not in FRAMEWORK_CATALOG:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework_id!r}")

    cached_path = lib.data_dir / f"{framework_id}.yaml"
    # Удаляем кеш чтобы форсировать повторную загрузку
    if cached_path.exists():
        cached_path.unlink()
    if framework_id in lib._loaded:
        del lib._loaded[framework_id]

    def _do_download() -> None:
        lib.load(framework_id)

    background_tasks.add_task(_do_download)
    return {"status": "downloading", "framework_id": framework_id}


@router.get("/file/{filename:path}/controls")
async def get_controls_by_filename(
    filename: str,
    assessable_only: bool = Query(True),
    payload: dict = Depends(require_auth),
) -> dict:
    """Контроли любого скачанного фреймворка по имени файла (напр. gdpr.yaml)."""
    lib = get_library()
    try:
        controls = lib.get_controls_any(filename, assessable_only=assessable_only)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Framework file not found: {filename!r}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {
        "filename":       filename,
        "assessable_only": assessable_only,
        "total":          len(controls),
        "controls":       [asdict(c) for c in controls],
    }


@router.get("/file/{filename:path}/search")
async def search_controls_by_filename(
    filename: str,
    q: str = Query(..., min_length=1),
    assessable_only: bool = Query(True),
    payload: dict = Depends(require_auth),
) -> dict:
    """Поиск по контролям любого скачанного фреймворка по имени файла."""
    lib = get_library()
    try:
        results = lib.search_controls_any(filename, q.strip(), assessable_only=assessable_only)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Framework file not found: {filename!r}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {
        "filename": filename,
        "query":    q.strip(),
        "total":    len(results),
        "results":  [asdict(c) for c in results],
    }


@router.post("/download-all")
async def download_all_frameworks(
    background_tasks: BackgroundTasks,
    payload: dict = Depends(require_admin),
) -> dict:
    """Скачать все 12 фреймворков в фоне (admin only)."""
    lib = get_library()

    def _do_download_all() -> None:
        results = lib.download_all()
        success = sum(1 for ok in results.values() if ok)
        failed = [fid for fid, ok in results.items() if not ok]
        from log_config import get_logger
        log = get_logger(__name__)
        log.info("framework_library: download_all complete — %d ok, %d failed: %s", success, len(failed), failed)

    background_tasks.add_task(_do_download_all)
    return {
        "status": "downloading",
        "frameworks": list(FRAMEWORK_CATALOG.keys()),
        "total": len(FRAMEWORK_CATALOG),
    }
