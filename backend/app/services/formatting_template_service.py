"""Service for CRUD operations on formatting templates (file-based, like scripts)."""

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_projects_dir


_SAFE_TEMPLATE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


class InvalidTemplateIdError(ValueError):
    """Raised when a template ID cannot safely be used as a file name."""


def _templates_dir() -> Path:
    """Return the active user's contained formatting-template directory."""
    base_dir = get_projects_dir().resolve()
    templates_dir = (base_dir / "_formatting_templates").resolve()
    try:
        templates_dir.relative_to(base_dir)
    except ValueError as exc:
        raise InvalidTemplateIdError(
            "Formatting templates directory resolves outside the user data directory"
        ) from exc
    if templates_dir.exists() and not templates_dir.is_dir():
        raise InvalidTemplateIdError("Formatting templates path is not a directory")
    templates_dir.mkdir(parents=True, exist_ok=True)
    return templates_dir


def _template_path(template_id: str) -> Path:
    """Return a contained template path for a strict, filesystem-safe ID."""
    if not isinstance(template_id, str) or not _SAFE_TEMPLATE_ID.fullmatch(template_id):
        raise InvalidTemplateIdError(
            "Template ID must be 1-128 letters, numbers, underscores, or hyphens"
        )

    templates_dir = _templates_dir().resolve()
    path = (templates_dir / f"{template_id}.json").resolve()
    try:
        path.relative_to(templates_dir)
    except ValueError as exc:
        # Keep this defense even with the strict allowlist so future changes to
        # the accepted ID syntax cannot silently reintroduce path traversal.
        raise InvalidTemplateIdError(
            "Template ID resolves outside the template directory"
        ) from exc
    return path


def list_templates() -> list[dict]:
    """List all formatting templates."""
    tpl_dir = _templates_dir()
    templates = []
    for f in sorted(tpl_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            templates.append(data)
        except (json.JSONDecodeError, KeyError):
            continue
    return templates


def get_template(template_id: str) -> dict:
    """Get a single formatting template by ID."""
    path = _template_path(template_id)
    if not path.exists():
        raise FileNotFoundError(f"Template '{template_id}' not found")
    return json.loads(path.read_text(encoding="utf-8"))


def create_template(data: dict) -> dict:
    """Create a new formatting template."""
    template_id = data.get("id") or str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    template = {
        "id": template_id,
        "name": data.get("name", "Untitled Template"),
        "description": data.get("description", ""),
        "mode": data.get("mode", "enforce"),
        "rules": data.get("rules", {}),
        "forceBreakBefore": data.get("forceBreakBefore") or [],
        "createdAt": data.get("createdAt", now),
        "updatedAt": data.get("updatedAt", now),
    }
    path = _template_path(template_id)
    path.write_text(json.dumps(template, indent=2), encoding="utf-8")
    return template


def update_template(template_id: str, data: dict) -> dict:
    """Update an existing formatting template."""
    path = _template_path(template_id)
    if not path.exists():
        raise FileNotFoundError(f"Template '{template_id}' not found")
    existing = json.loads(path.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc).isoformat()
    existing.update({
        k: v for k, v in data.items()
        if k in ("name", "description", "mode", "rules", "forceBreakBefore")
    })
    existing["updatedAt"] = now
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return existing


def delete_template(template_id: str) -> None:
    """Delete a formatting template."""
    path = _template_path(template_id)
    if path.exists():
        path.unlink()
