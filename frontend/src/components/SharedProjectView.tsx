import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { cloudApi } from "../services/cloudApi";
import type { ProjectInfo, ScriptMeta } from "../services/api";
import { useSettingsStore } from "../stores/settingsStore";

/** A read-only project navigation shell. All rows are authorized by the server. */
export default function SharedProjectView() {
  const { ownerId, projectId } = useParams();
  const userId = useSettingsStore((s) => s.collabAuth.user?.id);
  const navigate = useNavigate();
  const [project, setProject] = useState<ProjectInfo | null>(null);
  const [scripts, setScripts] = useState<ScriptMeta[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    let alive = true;
    setProject(null);
    setError("");
    setScripts([]);
    Promise.all([
      cloudApi.getProject(projectId!, ownerId),
      cloudApi.listScripts(projectId!, false, ownerId),
    ])
      .then(([p, docs]) => {
        if (alive) {
          setProject(p);
          setScripts(docs);
        }
      })
      .catch((e) => {
        if (alive) setError(e.message);
      });
    return () => {
      alive = false;
    };
  }, [ownerId, projectId, userId]);
  return (
    <div className="project-view">
      <div className="project-view-header">
        <button
          className="project-back-btn"
          onClick={() => navigate("/projects")}
        >
          ← Projects
        </button>
        <h1>{project?.name || "Shared project"}</h1>
      </div>
      <div className="shared-project-content">
      {error ? (
        <p role="alert">{error}</p>
      ) : !project ? (
        <p>Loading project…</p>
      ) : (
        <>
          <p>
            Shared · Owned by {project.owner_name} · {scripts.length} accessible
            screenplay{scripts.length === 1 ? "" : "s"}
          </p>
          <p>Only screenplays shared with you are shown.</p>
          <div className="project-list-grid">
            {scripts.map((d) => (
              <button
                key={d.id}
                className="project-card shared-project-card"
                onClick={() => navigate(`/shared/${d.shared_document_id}`)}
              >
                <h2>{d.title}</h2>
                <span>
                  {d.access_role === "editor" ? "Co-editor" : "Viewer"}
                </span>
              </button>
            ))}
          </div>
        </>
      )}
      </div>
    </div>
  );
}
