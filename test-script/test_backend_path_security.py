"""Focused regressions for backend filesystem and upload hardening."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
_tmp = Path(tempfile.mkdtemp(prefix="opendraft-path-security-"))
os.environ["OPENDRAFT_DATA_DIR"] = str(_tmp / "data")

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.api import versions as versions_api  # noqa: E402
from app.api import assets as assets_api  # noqa: E402
from app.api import formatting_templates as formatting_api  # noqa: E402
from app.api import projects as projects_api  # noqa: E402
from app.api import scripts as scripts_api  # noqa: E402
from app.config import PROJECTS_DIR_BASE, current_user_id, get_projects_dir  # noqa: E402
from app.dependencies import require_verified_user  # noqa: E402
from app.schemas.project import ProjectUpdate, ReorderItem, ReorderRequest  # noqa: E402
from app.services import (  # noqa: E402
    asset_service,
    formatting_template_service,
    location_service,
    project_service,
    script_service,
)


def expect_invalid(function, *args, **kwargs):
    try:
        function(*args, **kwargs)
    except (
        formatting_template_service.InvalidTemplateIdError,
        project_service.InvalidResourceIdError,
    ):
        return
    raise AssertionError("unsafe path was accepted")


def expect_http_400(awaitable):
    try:
        asyncio.run(awaitable)
    except HTTPException as exc:
        assert exc.status_code == 400, exc
        return
    raise AssertionError("unsafe route input did not return HTTP 400")


def test_formatting_templates():
    anonymous = FastAPI()
    anonymous.include_router(formatting_api.router, prefix="/templates")
    assert TestClient(anonymous).get("/templates/").status_code == 401

    verified = FastAPI()
    verified.include_router(formatting_api.router, prefix="/templates")
    verified.dependency_overrides[require_verified_user] = lambda: object()
    client = TestClient(verified)
    response = client.post(
        "/templates/", json={"id": "safe-template", "name": "Safe"}
    )
    assert response.status_code == 200, response.text
    for method in ("get", "put", "delete"):
        kwargs = {"json": {"name": "Nope"}} if method == "put" else {}
        response = getattr(client, method)("/templates/bad.id", **kwargs)
        assert response.status_code == 400, (method, response.text)

    outside = PROJECTS_DIR_BASE.parent / "outside.json"
    outside.parent.mkdir(parents=True, exist_ok=True)
    outside.write_text('{"sentinel": true}', encoding="utf-8")
    traversal = "../../outside"
    expect_invalid(formatting_template_service.get_template, traversal)
    expect_invalid(
        formatting_template_service.create_template,
        {"id": traversal, "name": "overwrite"},
    )
    expect_invalid(
        formatting_template_service.update_template,
        traversal,
        {"name": "overwrite"},
    )
    expect_invalid(formatting_template_service.delete_template, traversal)
    expect_http_400(formatting_api.get_template(traversal))
    expect_http_400(
        formatting_api.update_template(
            traversal, formatting_api.TemplateUpdate(name="overwrite")
        )
    )
    expect_http_400(formatting_api.delete_template(traversal))
    assert outside.read_text(encoding="utf-8") == '{"sentinel": true}'
    print("  ok: formatting auth, 400 mapping, and read/write/delete containment")


def create_cross_user_fixture():
    current_user_id.set("alice")
    project_service.create_project("Writer Room")
    script_service.create_script("writer-room", "Alice", {"type": "doc"})

    current_user_id.set("bob")
    project_service.create_project("Victim")
    result = script_service.create_script(
        "victim",
        "Bob Secret",
        {
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": "BOB SECRET"}],
                }
            ],
        },
    )
    victim_dir = get_projects_dir() / "victim"
    victim_id = result["meta"]["id"]
    victim_content = victim_dir / "scripts" / f"{victim_id}.json"
    return victim_id, victim_dir, victim_content


def test_project_script_containment():
    victim_id, victim_dir, victim_content = create_cross_user_fixture()
    project_before = (victim_dir / "project.json").read_text(encoding="utf-8")
    content_before = victim_content.read_text(encoding="utf-8")
    current_user_id.set("alice")
    traversal = "../bob/victim"

    expect_invalid(project_service.update_project, traversal, name="Owned")
    expect_invalid(project_service.delete_project, traversal)
    expect_invalid(script_service.update_script, traversal, victim_id, title="Owned")
    expect_invalid(script_service.delete_script, traversal, victim_id)
    expect_invalid(
        script_service.update_script,
        "writer-room",
        f"../../../bob/victim/scripts/{victim_id}",
        title="Owned",
    )
    reorder = ReorderRequest(items=[ReorderItem(id=traversal, sort_order=9)])
    expect_http_400(projects_api.reorder_projects(reorder))
    expect_http_400(
        projects_api.update_project(traversal, ProjectUpdate(name="Owned"))
    )
    expect_http_400(projects_api.delete_project(traversal))
    bad_scripts = ReorderRequest(
        items=[ReorderItem(id=f"../../{victim_id}", sort_order=9)]
    )
    expect_http_400(projects_api.reorder_scripts("writer-room", bad_scripts))

    assert (victim_dir / "project.json").read_text(encoding="utf-8") == project_before
    assert victim_content.read_text(encoding="utf-8") == content_before
    print("  ok: cross-user project/script reorder, update, and delete rejected")
    return victim_dir


def test_metadata_and_symlinks(victim_dir):
    current_user_id.set("alice")
    scripts_dir = get_projects_dir() / "writer-room" / "scripts"
    poison = {
        "id": "../../bob/victim/scripts/secret",
        "title": "Poison",
        "author": "",
        "format": "json",
        "created_at": "now",
        "updated_at": "now",
    }
    (scripts_dir / "poison.meta.json").write_text(
        json.dumps(poison), encoding="utf-8"
    )
    item = next(
        row
        for row in script_service.list_scripts("writer-room", include_preview=True)
        if row["title"] == "Poison"
    )
    assert item["id"] == "poison"
    assert item["size_bytes"] == 0
    assert "BOB SECRET" not in item["preview"]

    link = get_projects_dir() / "linked-victim"
    link.symlink_to(victim_dir, target_is_directory=True)
    assert "linked-victim" not in {
        row["id"] for row in project_service.list_projects()
    }
    expect_invalid(project_service.get_project, "linked-victim")
    print("  ok: stored script IDs are canonical and project symlinks are skipped")


def test_assets(victim_dir):
    current_user_id.set("alice")
    victim_project = victim_dir / "project.json"
    before = victim_project.read_text(encoding="utf-8")
    traversal_entry = {
        "id": "asset-traversal",
        "filename": "../../../bob/victim/project.json",
        "original_name": "project.json",
        "mime_type": "application/json",
        "size_bytes": len(before),
        "tags": [],
        "created_at": "now",
    }
    asset_service._write_manifest("writer-room", [traversal_entry])
    expect_invalid(asset_service.get_asset_path, "writer-room", "asset-traversal")
    expect_invalid(asset_service.delete_asset, "writer-room", "asset-traversal")
    expect_http_400(assets_api.delete_asset("writer-room", "asset-traversal"))
    assert victim_project.read_text(encoding="utf-8") == before

    asset_service._write_manifest("writer-room", [])
    first = asyncio.run(
        asset_service.upload_asset("writer-room", b"first", "first.png")
    )
    second = asyncio.run(
        asset_service.upload_asset("writer-room", b"second", "second.png")
    )
    assets_dir = get_projects_dir() / "writer-room" / "assets"
    second_path = assets_dir / second["filename"]
    second_before = second_path.read_bytes()
    swapped = dict(first, filename=second["filename"])
    asset_service._write_manifest("writer-room", [swapped, second])
    expect_invalid(asset_service.get_asset_path, "writer-room", first["id"])
    expect_invalid(asset_service.delete_asset, "writer-room", first["id"])
    expect_http_400(assets_api.download_asset("writer-room", first["id"]))
    expect_http_400(assets_api.delete_asset("writer-room", first["id"]))
    assert second_path.read_bytes() == second_before

    manifest_path = assets_dir / "manifest.json"
    asset_service._write_manifest(
        "writer-room",
        [
            {
                "id": "manifest",
                "filename": "manifest.json",
                "original_name": "manifest.json",
                "mime_type": "application/json",
                "size_bytes": 0,
                "tags": [],
                "created_at": "now",
            }
        ],
    )
    manifest_before = manifest_path.read_bytes()
    expect_invalid(asset_service.get_asset_path, "writer-room", "manifest")
    expect_invalid(asset_service.delete_asset, "writer-room", "manifest")
    expect_http_400(assets_api.download_asset("writer-room", "manifest"))
    expect_http_400(assets_api.delete_asset("writer-room", "manifest"))
    assert manifest_path.read_bytes() == manifest_before

    asset_service._write_manifest("writer-room", [])
    entry = asyncio.run(
        asset_service.upload_asset(
            "writer-room", b"image", 'shot"\r\nX-Evil: injected.png'
        )
    )
    response = asyncio.run(
        assets_api.download_asset("writer-room", entry["id"], "attachment")
    )
    header = response.headers["content-disposition"]
    assert "\r" not in header and "\n" not in header and "X-Evil:" not in header

    class OversizedUpload:
        filename = "large.bin"
        requested_size = None

        async def read(self, size=-1):
            self.requested_size = size
            return b"x" * size

    upload = OversizedUpload()
    old_limit = asset_service.MAX_FILE_SIZE
    asset_service.MAX_FILE_SIZE = 4
    try:
        expect_http_400(assets_api.upload_asset("writer-room", upload, ""))
        assert upload.requested_size == 5
    finally:
        asset_service.MAX_FILE_SIZE = old_limit
    print(
        "  ok: manifest containment and asset binding, safe filename header, "
        "and bounded upload read"
    )


def test_locations(victim_dir):
    current_user_id.set("alice")
    expect_invalid(location_service.list_locations, "../bob/victim")
    assert not (victim_dir / "locations.json").exists()
    print("  ok: locations cannot traverse to a sibling user")


def test_versions_use_shared_validation():
    current_user_id.set("alice")
    try:
        versions_api._project_path("../bob/victim")
    except HTTPException as exc:
        assert exc.status_code == 400, exc
    else:
        raise AssertionError("version project traversal was accepted")
    expect_http_400(
        versions_api.get_script_at_version(
            "writer-room", "deadbeef", "../victim-script"
        )
    )
    print("  ok: version routes use shared project/script ID validation")


def test_legacy_script_routes_reject_malformed_ids():
    current_user_id.set("alice")
    app = FastAPI()
    app.include_router(scripts_api.router, prefix="/scripts")
    client = TestClient(app)
    malformed = "bad.id"
    for method in ("get", "put", "delete"):
        kwargs = {"json": {"title": "Nope"}} if method == "put" else {}
        response = getattr(client, method)(f"/scripts/{malformed}", **kwargs)
        assert response.status_code == 400, (method, response.text)
    print("  ok: legacy get/update/delete script routes map malformed IDs to 400")


if __name__ == "__main__":
    print("Running backend path-security tests…")
    try:
        test_formatting_templates()
        victim_dir = test_project_script_containment()
        test_metadata_and_symlinks(victim_dir)
        test_assets(victim_dir)
        test_locations(victim_dir)
        test_versions_use_shared_validation()
        test_legacy_script_routes_reject_malformed_ids()
        print("All tests passed.")
    finally:
        shutil.rmtree(_tmp, ignore_errors=True)
