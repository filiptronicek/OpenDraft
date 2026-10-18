"""Read-only navigation projections of collaboration document grants.

Forward the caller's identity; never read an owner's project directory under a
member's request. The collaboration service returns only authorized documents.
"""
from urllib.parse import quote

import httpx
from fastapi import HTTPException, Request
from app.config import COLLAB_SERVER_URL


async def _read(request: Request, path: str):
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            result = await client.get(
                f"{COLLAB_SERVER_URL}/api/sharing/{path}",
                headers={"Authorization": request.headers.get("authorization", "")},
            )
    except httpx.RequestError as exc:
        raise HTTPException(503, "Shared project access is unavailable") from exc
    if result.status_code in (401, 403, 404):
        raise HTTPException(result.status_code, "Shared project unavailable")
    if not result.is_success:
        raise HTTPException(503, "Shared project access is unavailable")
    return result.json()


def project_metadata(project: dict) -> dict:
    # No properties, total file counts, paths, assets, or other private metadata.
    return {
        "id": project["id"], "name": project["name"],
        "created_at": "", "updated_at": "",
        "access": "shared", "owner_id": project["owner_id"],
        "owner_name": project["owner_name"],
        "accessible_document_count": project["document_count"],
    }


async def list_projects(request: Request) -> list[dict]:
    return [project_metadata(p) for p in await _read(request, "projects")]


async def project(request: Request, owner_id: str, project_id: str) -> dict:
    return await _read(request, f"projects/{quote(owner_id, safe='')}/{quote(project_id, safe='')}")


def script_metadata(document: dict) -> dict:
    return {
        "id": document["script_id"], "title": document["script_title"],
        "author": "", "format": "json", "created_at": "", "updated_at": "",
        "shared_document_id": document["id"], "access_role": document["role"],
    }
