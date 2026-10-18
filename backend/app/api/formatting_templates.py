"""API router for formatting template CRUD."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.services import formatting_template_service
from app.dependencies import require_verified_user

router = APIRouter(dependencies=[Depends(require_verified_user)])


class TemplateCreate(BaseModel):
    id: str | None = None
    name: str = "Untitled Template"
    description: str = ""
    mode: str = "enforce"
    rules: dict = {}
    # Element ids that must start on a new page (e.g. ["newAct"]).
    forceBreakBefore: list[str] | None = None
    createdAt: str | None = None
    updatedAt: str | None = None


class TemplateUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    mode: str | None = None
    rules: dict | None = None
    forceBreakBefore: list[str] | None = None


@router.get("/")
async def list_templates():
    return formatting_template_service.list_templates()


@router.post("/")
async def create_template(body: TemplateCreate):
    try:
        return formatting_template_service.create_template(body.model_dump())
    except formatting_template_service.InvalidTemplateIdError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{template_id}")
async def get_template(template_id: str):
    try:
        return formatting_template_service.get_template(template_id)
    except formatting_template_service.InvalidTemplateIdError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/{template_id}")
async def update_template(template_id: str, body: TemplateUpdate):
    try:
        data = {k: v for k, v in body.model_dump().items() if v is not None}
        return formatting_template_service.update_template(template_id, data)
    except formatting_template_service.InvalidTemplateIdError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/{template_id}")
async def delete_template(template_id: str):
    try:
        formatting_template_service.delete_template(template_id)
    except formatting_template_service.InvalidTemplateIdError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"message": "Template deleted"}
