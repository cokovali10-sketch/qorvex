import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, CheckRun, Finding } from "../api";

export function ProjectDetail() {
  const { id } = useParams<{ id: string }>();
  const [checks, setChecks] = useState<CheckRun[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [projectName, setProjectName] = useState("Loading...");

  useEffect(() => {
    if (!id) return;
    api.projects.list().then((projects) => {
      const p = projects.find((pj) => pj.id === id);
      if (p) setProjectName(p.name);
    });
    api.projects.checks(id).then(setChecks);
    api.projects.findings(id).then(setFindings);
  }, [id]);

  const startCheck = async () => {
    if (!id) return;
    try {
      const check = await api.checks.start(id);
      window.location.href = `/checks/${check.id}`;
    } catch (e: any) { console.error(e); }
  };

  return (
    <div>
      <div className="header-row">
        <h1>{projectName}</h1>
        <button className="btn" onClick={startCheck}>Run Check</button>
      </div>

      <div className="panels">
        <div className="panel">
          <h2>Check Runs</h2>
          <table className="table">
            <thead>
              <tr><th>ID</th><th>Status</th><th>Score</th><th>Date</th></tr>
            </thead>
            <tbody>
              {checks.map((c) => (
                <tr key={c.id} className="clickable" onClick={() => window.location.href = `/checks/${c.id}`}>
                  <td className="mono">{c.id.slice(0, 12)}…</td>
                  <td><span className={`badge badge-${c.status}`}>{c.status}</span></td>
                  <td>{c.result?.score ?? "-"}</td>
                  <td>{new Date(c.start_time || "").toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {checks.length === 0 && <p className="empty">No checks run yet.</p>}
        </div>

        <div className="panel">
          <h2>Recent Findings</h2>
          <table className="table">
            <thead>
              <tr><th>Severity</th><th>Category</th><th>Description</th><th>File</th></tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <tr key={i}>
                  <td><span className={`badge badge-${f.severity}`}>{f.severity}</span></td>
                  <td>{f.category}</td>
                  <td>{f.description}</td>
                  <td className="mono">{f.file_path?.split("/").pop() || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {findings.length === 0 && <p className="empty">No findings yet.</p>}
        </div>
      </div>
    </div>
  );
}