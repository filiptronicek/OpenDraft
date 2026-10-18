import { useEffect, useState } from "react";
import { Navigate, useParams } from "react-router-dom";
import ScreenplayEditor from "./ScreenplayEditor";
import { sharingApi } from "../services/sharing";
import { useSettingsStore } from "../stores/settingsStore";
import { useProjectStore } from "../stores/projectStore";
export default function OwnedEditorRoute() {
  const { projectId, scriptId } = useParams(),
    token = useSettingsStore((s) => s.collabAuth.accessToken);
  const [target, setTarget] = useState<string | null | undefined>(),
    [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    setTarget(undefined);
    setError("");
    if (
      !token ||
      ((window as any).__TAURI_INTERNALS__ &&
        !useProjectStore
          .getState()
          .isCloudScript(projectId || "", scriptId || ""))
    ) {
      setTarget(null);
      return;
    }
    sharingApi
      .documents()
      .then((ds) => {
        if (live)
          setTarget(
            ds.find(
              (d) =>
                d.role === "owner" &&
                d.project_id === projectId &&
                d.script_id === scriptId,
            )?.id || null,
          );
      })
      .catch((e) => {
        if (live) setError(e.message);
      });
    return () => {
      live = false;
    };
  }, [projectId, scriptId, token]);
  if (error)
    return (
      <div role="alert">
        Unable to check shared screenplay state: {error}. Please reload to
        retry.
      </div>
    );
  if (target === undefined) return <div>Opening screenplay…</div>;
  if (target) return <Navigate to={`/shared/${target}`} replace />;
  return <ScreenplayEditor />;
}
