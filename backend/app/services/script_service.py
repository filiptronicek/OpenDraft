import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.services import project_service

logger = logging.getLogger(__name__)


class EmptyOverwriteError(Exception):
    """Raised when a save would blank a script that currently has content.

    The blank-document data-loss guard. Routes map this to HTTP 409.
    """


def _scripts_dir(project_id: str) -> Path:
    """Return the scripts directory for the active user's project."""
    project_dir = project_service.get_project_dir(project_id)
    scripts_path = project_service.resolve_contained_path(
        project_dir, "scripts", label="Scripts path"
    )
    if not scripts_path.exists() or not scripts_path.is_dir():
        raise FileNotFoundError(f"Project '{project_id}' not found")
    return scripts_path


def _script_paths(project_id: str, script_id: str) -> tuple[Path, Path]:
    """Return contained metadata/content paths for a validated script ID."""
    project_service.validate_resource_id(script_id, "Script")
    scripts_path = _scripts_dir(project_id)
    meta_file = project_service.resolve_contained_path(
        scripts_path, f"{script_id}.meta.json", label="Script metadata path"
    )
    content_file = project_service.resolve_contained_path(
        scripts_path, f"{script_id}.json", label="Script content path"
    )
    return meta_file, content_file


def create_script(
    project_id: str,
    title: str,
    content: dict | None = None,
    format: str = "json",
) -> dict:
    """Create a new script with a UUID, saving content and metadata files."""

    script_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    meta = {
        "id": script_id,
        "title": title,
        "author": "",
        "format": format,
        "created_at": now,
        "updated_at": now,
    }

    script_content = content if content is not None else {}
    meta_file, content_file = _script_paths(project_id, script_id)

    meta_file.write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    content_file.write_text(
        json.dumps(script_content, indent=2), encoding="utf-8"
    )

    return {"meta": meta, "content": script_content}


def _extract_preview(content: dict, max_chars: int = 200) -> str:
    """Extract plain text preview from TipTap JSON content."""
    if not content or "content" not in content:
        return ""
    texts: list[str] = []
    char_count = 0
    for node in content.get("content", []):
        if char_count >= max_chars:
            break
        line_parts: list[str] = []
        for child in node.get("content", []):
            if child.get("type") == "text":
                t = child.get("text", "")
                line_parts.append(t)
                char_count += len(t)
                if char_count >= max_chars:
                    break
        if line_parts:
            texts.append("".join(line_parts))
    result = "\n".join(texts)
    return result[:max_chars]


def list_scripts(project_id: str, include_preview: bool = False) -> list[dict]:
    """List metadata using canonical IDs derived from contained filenames."""
    scripts_path = _scripts_dir(project_id)

    metas = []
    suffix = ".meta.json"
    for candidate in sorted(scripts_path.glob(f"*{suffix}")):
        if candidate.is_symlink():
            logger.warning("Skipping symlinked script metadata: %s", candidate)
            continue
        script_id = candidate.name[:-len(suffix)]
        try:
            meta_file, content_file = _script_paths(project_id, script_id)
            data = json.loads(meta_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
        except (
            project_service.InvalidResourceIdError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            logger.warning("Skipping unsafe or invalid script metadata %s: %s", candidate, exc)
            continue
        data["id"] = script_id
        data["size_bytes"] = content_file.stat().st_size if content_file.exists() else 0
        data.setdefault("page_count", 0)
        data.setdefault("color", "")
        data.setdefault("pinned", False)
        data.setdefault("sort_order", 0)
        data.setdefault("preview", "")
        if include_preview and content_file.exists():
            try:
                content = json.loads(content_file.read_text(encoding="utf-8"))
                data["preview"] = _extract_preview(content)
            except Exception as exc:
                logger.warning(
                    "Failed to build preview for script %s in project %s: %s",
                    script_id,
                    project_id,
                    exc,
                )
                data["preview"] = ""
        metas.append(data)
    return metas


def get_script(project_id: str, script_id: str) -> dict:
    """Read a script's metadata and content."""
    meta_file, content_file = _script_paths(project_id, script_id)

    if not meta_file.exists():
        raise FileNotFoundError(f"Script '{script_id}' not found")

    meta = json.loads(meta_file.read_text(encoding="utf-8"))
    meta["id"] = script_id
    content = json.loads(content_file.read_text(encoding="utf-8")) if content_file.exists() else {}

    return {"meta": meta, "content": content}


def _has_body_text(content: dict | None) -> bool:
    """True when a TipTap/ProseMirror doc has any non-whitespace text in its body.

    Only ``content`` arrays are walked, so app-metadata keys (e.g. ``_notes``)
    don't count as body text. Mirrors ``docHasAnyText`` on the frontend.
    """
    if not isinstance(content, dict):
        return False
    if content.get("type") == "text":
        text = content.get("text")
        if isinstance(text, str) and text.strip():
            return True
    children = content.get("content")
    if isinstance(children, list):
        for child in children:
            if _has_body_text(child):
                return True
    return False


def update_script(
    project_id: str,
    script_id: str,
    title: str | None = None,
    content: dict | None = None,
    color: str | None = None,
    pinned: bool | None = None,
    sort_order: int | None = None,
    allow_empty_body: bool = False,
) -> dict:
    """Update a script's title and/or content."""
    meta_file, content_file = _script_paths(project_id, script_id)

    if not meta_file.exists():
        raise FileNotFoundError(f"Script '{script_id}' not found")

    # Data-loss guard: refuse to overwrite a script that has real content with an
    # empty/textless body (the blank-document bug). Callers that intentionally
    # clear a document must pass allow_empty_body=True. Checked before any write
    # so a rejected save leaves the script (and updated_at) untouched.
    if content is not None and not allow_empty_body and not _has_body_text(content):
        existing = (
            json.loads(content_file.read_text(encoding="utf-8"))
            if content_file.exists()
            else None
        )
        if _has_body_text(existing):
            raise EmptyOverwriteError(
                f"Refusing to overwrite script '{script_id}' with an empty document — "
                "the saved script has content but the incoming one has none. This "
                "guards against accidental data loss. If you really meant to clear it, "
                "delete the script instead."
            )

    meta = json.loads(meta_file.read_text(encoding="utf-8"))

    meta["id"] = script_id
    if title is not None:
        meta["title"] = title
    if color is not None:
        meta["color"] = color
    if pinned is not None:
        meta["pinned"] = pinned
    if sort_order is not None:
        meta["sort_order"] = sort_order

    meta["updated_at"] = datetime.now(timezone.utc).isoformat()

    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    if content is not None:
        content_file.write_text(json.dumps(content, indent=2), encoding="utf-8")

    current_content = json.loads(content_file.read_text(encoding="utf-8")) if content_file.exists() else {}

    meta.setdefault("color", "")
    meta.setdefault("pinned", False)
    meta.setdefault("sort_order", 0)

    return {"meta": meta, "content": current_content}


def duplicate_script(project_id: str, script_id: str) -> dict:
    """Duplicate a script with a new UUID and '(Copy)' title suffix."""
    original = get_script(project_id, script_id)

    new_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Determine next sort_order
    existing = list_scripts(project_id)
    max_order = max((s.get("sort_order", 0) for s in existing), default=0)

    meta = {
        "id": new_id,
        "title": f"{original['meta'].get('title', 'Untitled')} (Copy)",
        "author": original["meta"].get("author", ""),
        "format": original["meta"].get("format", "json"),
        "created_at": now,
        "updated_at": now,
        "color": original["meta"].get("color", ""),
        "pinned": False,
        "sort_order": max_order + 1,
    }

    content = original.get("content", {})

    meta_file, content_file = _script_paths(project_id, new_id)
    meta_file.write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
    content_file.write_text(
        json.dumps(content, indent=2), encoding="utf-8"
    )

    return {"meta": meta, "content": content}


def delete_script(project_id: str, script_id: str) -> None:
    """Delete a script's content and metadata files."""
    meta_file, content_file = _script_paths(project_id, script_id)

    if not meta_file.exists():
        raise FileNotFoundError(f"Script '{script_id}' not found")

    meta_file.unlink()
    if content_file.exists():
        content_file.unlink()
