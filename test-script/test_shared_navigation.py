"""Read-only shared navigation through the existing project APIs."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from app.api import projects
from app.services import sharing_service


class SharedNavigationTests(unittest.TestCase):
    def test_existing_reads_filter_metadata_and_keep_write_destinations_owned(self):
        owned = {"id": "same-slug", "name": "My project", "created_at": "", "updated_at": ""}
        shared = {"id": "same-slug", "name": "Their project", "owner_id": "owner",
                  "owner_name": "Owner", "document_count": 1,
                  "documents": [{"id": "shared-id", "script_id": "allowed", "script_title": "Allowed", "role": "viewer"}],
                  "private_notes": "must not be returned", "total_count": 20}
        calls = []

        async def read(request, path):
            calls.append(path)
            if request.headers.get("authorization") != "Bearer recipient":
                raise HTTPException(403, "Unavailable")
            if path == "projects":
                return [shared]
            if path == "projects/owner/same-slug":
                return shared
            raise HTTPException(404, "Unavailable")

        app = FastAPI()
        app.include_router(projects.router, prefix="/api/projects")
        with patch.object(sharing_service, "_read", read), patch.object(projects.project_service, "list_projects", return_value=[owned.copy()]):
            client = TestClient(app)
            headers = {"Authorization": "Bearer recipient"}
            plain = client.get("/api/projects/", headers=headers).json()["projects"]
            self.assertEqual(len(plain), 1)
            self.assertEqual(calls, [])
            result = client.get("/api/projects/?include_shared=true", headers=headers)
            self.assertEqual(result.status_code, 200)
            rows = result.json()["projects"]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[1]["access"], "shared")
            self.assertEqual(rows[1]["accessible_document_count"], 1)
            self.assertNotIn("must not be returned", result.text)
            self.assertNotIn("total_count", result.text)
            p = client.get("/api/projects/same-slug?owner_id=owner", headers=headers)
            self.assertEqual(p.json()["name"], "Their project")
            scripts = client.get("/api/projects/same-slug/scripts/?owner_id=owner&include_preview=true", headers=headers).json()
            self.assertEqual([s["id"] for s in scripts], ["allowed"])
            self.assertEqual(scripts[0]["access_role"], "viewer")
            self.assertEqual(scripts[0]["shared_document_id"], "shared-id")
            self.assertEqual(scripts[0]["preview"], "")
            self.assertEqual(client.get("/api/projects/same-slug?owner_id=wrong", headers=headers).status_code, 404)
            self.assertEqual(client.get("/api/projects/?include_shared=true").status_code, 403)


if __name__ == "__main__":
    unittest.main()
