import React, { useEffect, useState } from "react";
import { api, Project } from "../api";

export function Projects() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [newName, setNewName] = useState("");
  const [newPath, setNewPath] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api.projects.list().then(setProjects).catch((e) => setError(e.message));
  }, []);

  const createProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim()) return;
    try {
      const p = await api.projects.create(newName.trim(), newPath.trim() || "./");
      setProjects((prev) => [...prev, p]);
      setNewName("");
      setNewPath("");
    } catch (err: any) {
      setError(err.message);
    }
  };

  const startCheck = async (projectId: string) => {
    try {
      const check = await api.checks.start(projectId);
      window.location.href = `/checks/${check.id}`;
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div>
      <h1>Projects</h1>
      {error && <div className="error">{error}</div>}

      <form className="form" onSubmit={createProject}>
        <input
          type="text"
          placeholder="Project name"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          className="input"
        />
        <input
          type="text"
          placeholder="Path (optional)"
          value={newPath}
          onChange={(e) => setNewPath(e.target.value)}
          className="input"
        />
        <button type="submit" className="btn">+ Create</button>
      </form>

      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Path</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {projects.map((p) => (
            <tr key={p.id}>
              <td>
                <a href={`/projects/${p.id}`} className="link">{p.name}</a>
              </td>
              <td className="mono">{p.path}</td>
              <td>{new Date(p.created_at || "").toLocaleDateString()}</td>
              <td>
                <button className="btn btn-sm" onClick={() => startCheck(p.id)}>
                  Run Check
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {projects.length === 0 && <p className="empty">No projects yet. Create one above.</p>}
    </div>
  );
}