import json
import logging
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from dulwich.repo import Repo as DulwichRepo

from app.config import get_projects_dir

logger = logging.getLogger(__name__)


class InvalidResourceIdError(ValueError):
    """Raised when a caller-controlled ID is unsafe for filesystem use."""


def validate_resource_id(resource_id: str, resource_name: str) -> str:
    """Validate a single safe path component while retaining Unicode names."""
    if (
        not isinstance(resource_id, str)
        or not 1 <= len(resource_id) <= 128
        or not resource_id[0].isalnum()
        or any(not (char.isalnum() or char in "_-") for char in resource_id)
    ):
        raise InvalidResourceIdError(
            f"{resource_name} ID must be 1-128 letters, numbers, underscores, or hyphens"
        )
    return resource_id


def resolve_contained_path(base: Path, *parts: str, label: str = "Path") -> Path:
    """Resolve a child path and fail closed if it escapes its resolved base."""
    resolved_base = base.resolve()
    resolved_path = resolved_base.joinpath(*parts).resolve()
    try:
        resolved_path.relative_to(resolved_base)
    except ValueError as exc:
        raise InvalidResourceIdError(
            f"{label} resolves outside its allowed directory"
        ) from exc
    return resolved_path


def get_project_dir(project_id: str, *, require_exists: bool = True) -> Path:
    """Return a validated project directory contained in the active user's root."""
    validate_resource_id(project_id, "Project")
    projects_root = get_projects_dir().resolve()
    unresolved = projects_root / project_id
    if unresolved.is_symlink():
        raise InvalidResourceIdError("Project paths may not be symbolic links")
    project_dir = resolve_contained_path(projects_root, project_id, label="Project path")
    if require_exists and (not project_dir.exists() or not project_dir.is_dir()):
        raise FileNotFoundError(f"Project '{project_id}' not found")
    return project_dir


def _project_file(project_id: str, *, require_project: bool = True) -> Path:
    project_dir = get_project_dir(project_id, require_exists=require_project)
    return resolve_contained_path(project_dir, "project.json", label="Project metadata path")


def _slugify(name: str) -> str:
    """Convert a project name to a filesystem-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    return slug.strip("-")


def _ensure_projects_dir() -> None:
    """Create the top-level projects directory if it doesn't exist."""
    get_projects_dir().mkdir(parents=True, exist_ok=True)


def create_project(name: str) -> dict:
    """Create a new project directory with subdirectories and git init."""
    _ensure_projects_dir()

    project_id = _slugify(name)
    if not project_id:
        raise ValueError("Project name produces an empty slug")

    project_dir = get_project_dir(project_id, require_exists=False)
    if project_dir.exists():
        raise FileExistsError(f"Project '{project_id}' already exists")

    # Create directory structure
    project_dir.mkdir(parents=True)
    (project_dir / "scripts").mkdir()
    (project_dir / "assets").mkdir()
    (project_dir / "notes").mkdir()

    now = datetime.now(timezone.utc).isoformat()
    project_data = {
        "id": project_id,
        "name": name,
        "created_at": now,
        "updated_at": now,
        "properties": {},
    }

    _project_file(project_id).write_text(
        json.dumps(project_data, indent=2), encoding="utf-8"
    )

    # Initialize git repository
    DulwichRepo.init(str(project_dir))

    return project_data


def list_projects() -> list[dict]:
    """List contained, non-symlink projects with canonical IDs."""
    _ensure_projects_dir()

    projects = []
    for entry in sorted(get_projects_dir().resolve().iterdir()):
        if entry.is_symlink() or not entry.is_dir():
            continue
        try:
            project_id = validate_resource_id(entry.name, "Project")
            project_file = _project_file(project_id)
            if not project_file.exists():
                continue
            data = json.loads(project_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
        except (InvalidResourceIdError, OSError, json.JSONDecodeError) as exc:
            logger.warning("Skipping unsafe or invalid project entry %s: %s", entry, exc)
            continue
        data["id"] = project_id
        data.setdefault("properties", {})
        data.setdefault("color", "")
        data.setdefault("pinned", False)
        data.setdefault("sort_order", 0)
        projects.append(data)
    return projects


def get_project(project_id: str) -> dict:
    """Read a single project's metadata."""
    project_file = _project_file(project_id)
    if not project_file.exists():
        raise FileNotFoundError(f"Project '{project_id}' not found")
    data = json.loads(project_file.read_text(encoding="utf-8"))
    data.setdefault("properties", {})
    data.setdefault("color", "")
    data.setdefault("pinned", False)
    data["id"] = project_id
    data.setdefault("sort_order", 0)
    return data


def update_project(
    project_id: str,
    name: str | None = None,
    properties: dict | None = None,
    color: str | None = None,
    pinned: bool | None = None,
    sort_order: int | None = None,
) -> dict:
    """Update a project's name, properties, and updated_at timestamp."""
    project_file = _project_file(project_id)
    if not project_file.exists():
        raise FileNotFoundError(f"Project '{project_id}' not found")

    data = json.loads(project_file.read_text(encoding="utf-8"))
    data["id"] = project_id
    if name is not None:
        data["name"] = name
    if properties is not None:
        data["properties"] = properties
    if color is not None:
        data["color"] = color
    if pinned is not None:
        data["pinned"] = pinned
    if sort_order is not None:
        data["sort_order"] = sort_order
    data["updated_at"] = datetime.now(timezone.utc).isoformat()

    project_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    data.setdefault("color", "")
    data.setdefault("pinned", False)
    data.setdefault("sort_order", 0)
    return data


def delete_project(project_id: str) -> None:
    """Delete an entire project directory."""
    project_dir = get_project_dir(project_id)
    shutil.rmtree(project_dir)


def ensure_default_project(default_name: str) -> dict:
    """Create the default project if it doesn't already exist, return its data."""
    project_id = _slugify(default_name)
    try:
        return get_project(project_id)
    except FileNotFoundError:
        pass
    return create_project(default_name)
