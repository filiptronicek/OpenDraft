import json
import mimetypes
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import aiofiles

from app.services import project_service

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


def _assets_dir(project_id: str) -> Path:
    """Return the assets directory for a project, ensuring the project exists."""
    project_dir = project_service.get_project_dir(project_id)
    assets_path = project_service.resolve_contained_path(
        project_dir, "assets", label="Assets path"
    )
    if assets_path.exists() and not assets_path.is_dir():
        raise project_service.InvalidResourceIdError("Assets path is not a directory")
    assets_path.mkdir(exist_ok=True)
    return assets_path


def _manifest_path(project_id: str) -> Path:
    """Return the path to the asset manifest file."""
    return project_service.resolve_contained_path(
        _assets_dir(project_id), "manifest.json", label="Asset manifest path"
    )


def _read_manifest(project_id: str) -> list[dict]:
    """Read the asset manifest, returning an empty list if it doesn't exist."""
    path = _manifest_path(project_id)
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def _write_manifest(project_id: str, manifest: list[dict]) -> None:
    """Write the asset manifest to disk."""
    path = _manifest_path(project_id)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _find_asset(project_id: str, asset_id: str) -> tuple[list[dict], dict]:
    """Find a validated manifest entry by a strict asset ID."""
    project_service.validate_resource_id(asset_id, "Asset")
    manifest = _read_manifest(project_id)
    for entry in manifest:
        if not isinstance(entry, dict):
            continue
        stored_id = entry.get("id")
        try:
            project_service.validate_resource_id(stored_id, "Asset")
        except project_service.InvalidResourceIdError:
            continue
        if stored_id == asset_id:
            return manifest, entry
    raise FileNotFoundError(f"Asset '{asset_id}' not found")


def _asset_file_path(project_id: str, entry: dict) -> Path:
    """Resolve only the file namespace belonging to this manifest asset ID."""
    asset_id = entry.get("id")
    project_service.validate_resource_id(asset_id, "Asset")
    filename = entry.get("filename")
    if not isinstance(filename, str) or not filename:
        raise project_service.InvalidResourceIdError("Asset filename is invalid")
    # Legacy uploads may have mixed-case or unusual extensions, but the stored
    # basename has always begun with the generated asset ID. Binding that
    # invariant prevents a tampered manifest from reading/deleting another
    # asset (or manifest.json) even when the target remains inside assets/.
    if (
        filename.casefold() == "manifest.json"
        or Path(filename).name != filename
        or (
            filename != asset_id and not filename.startswith(f"{asset_id}.")
        )
    ):
        raise project_service.InvalidResourceIdError(
            "Asset filename does not match its asset ID"
        )
    return project_service.resolve_contained_path(
        _assets_dir(project_id), filename, label="Asset file path"
    )


async def upload_asset(
    project_id: str,
    file_content: bytes,
    original_name: str,
    tags: list[str] | None = None,
) -> dict:
    """Save an uploaded file to the assets directory and add it to the manifest."""
    if len(file_content) > MAX_FILE_SIZE:
        raise ValueError(f"File size exceeds maximum of {MAX_FILE_SIZE // (1024 * 1024)} MB")

    assets_path = _assets_dir(project_id)
    asset_id = str(uuid.uuid4())

    # Detect MIME type from file extension
    mime_type, _ = mimetypes.guess_type(original_name)
    if mime_type is None:
        mime_type = "application/octet-stream"

    # Preserve a short, simple extension without retaining user-controlled paths.
    ext = Path(original_name).suffix.lower()
    if not re.fullmatch(r"\.[a-z0-9]{1,16}", ext):
        ext = ""
    filename = f"{asset_id}{ext}"

    file_path = project_service.resolve_contained_path(
        assets_path, filename, label="Asset upload path"
    )
    async with aiofiles.open(file_path, "wb") as f:
        await f.write(file_content)

    now = datetime.now(timezone.utc).isoformat()
    entry = {
        "id": asset_id,
        "filename": filename,
        "original_name": original_name,
        "mime_type": mime_type,
        "size_bytes": len(file_content),
        "tags": tags or [],
        "created_at": now,
    }

    manifest = _read_manifest(project_id)
    manifest.append(entry)
    _write_manifest(project_id, manifest)

    return entry


def list_assets(project_id: str) -> list[dict]:
    """List all assets in a project by reading the manifest."""
    return _read_manifest(project_id)


def get_asset_path(project_id: str, asset_id: str) -> Path:
    """Return the file path for a given asset, for download."""
    _manifest, entry = _find_asset(project_id, asset_id)
    file_path = _asset_file_path(project_id, entry)
    if not file_path.exists() or not file_path.is_file():
        raise FileNotFoundError(f"Asset file '{entry['filename']}' not found on disk")
    return file_path


def get_asset_entry(project_id: str, asset_id: str) -> dict:
    """Return the manifest entry for a given asset."""
    _manifest, entry = _find_asset(project_id, asset_id)
    return entry


def delete_asset(project_id: str, asset_id: str) -> None:
    """Remove an asset file and its manifest entry."""
    manifest, found = _find_asset(project_id, asset_id)

    # Remove file from disk
    file_path = _asset_file_path(project_id, found)
    if file_path.exists():
        file_path.unlink()

    # Remove from manifest
    manifest = [
        entry for entry in manifest
        if not isinstance(entry, dict) or entry.get("id") != asset_id
    ]
    _write_manifest(project_id, manifest)


def update_tags(project_id: str, asset_id: str, tags: list[str]) -> dict:
    """Update the tags for a given asset."""
    manifest, updated_entry = _find_asset(project_id, asset_id)
    updated_entry["tags"] = tags
    _write_manifest(project_id, manifest)
    return updated_entry


def search_by_tag(project_id: str, tag: str) -> list[dict]:
    """Filter assets by a specific tag."""
    manifest = _read_manifest(project_id)
    return [entry for entry in manifest if tag in entry.get("tags", [])]
