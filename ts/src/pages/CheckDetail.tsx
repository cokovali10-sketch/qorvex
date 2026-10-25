import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, CheckRun } from "../api";

export function CheckDetail() {
  const { id } = useParams<{ id: string }>();
  const [check, setCheck] = useState<CheckRun | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) return;
    const poll = setInterval(async () => {
      try {
        const c = await api.checks.get(id);
        setCheck(c);
        if (c.status === "completed" || c.status === "failed") clearInterval(poll);
      } catch (e: any) {
        setError(e.message);
        clearInterval(poll);
      }
    }, 2000);
    return () => clearInterval(poll);
  }, [id]);

  if (error) return <div className="error">{error}</div>;
  if (!check) return <div>Loading...</div>;

  return (
    <div>
      <h1>Check Run</h1>
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Status</div>
          <div className={`stat-value badge-${check.status}`}>{check.status}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Score</div>
          <div className="stat-value">{check.result?.score ?? "pending..."}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Duration</div>
          <div className="stat-value">
            {check.start_time && check.end_time
              ? `${Math.round((new Date(check.end_time).getTime() - new Date(check.start_time).getTime()) / 1000)}s`
              : "running..."}
          </div>
        </div>
      </div>

      {check.error && <div className="error">{check.error}</div>}

      {check.result && (
        <>
          <div className="panel">
            <h2>Summary</h2>
            <p>{check.result.summary}</p>
          </div>

          <div className="panel">
            <h2>Findings ({check.result.findings?.length || 0})</h2>
            <table className="table">
              <thead>
                <tr><th>Severity</th><th>Category</th><th>Description</th><th>File</th><th>CWE</th></tr>
              </thead>
              <tbody>
                {check.result.findings?.map((f, i) => (
                  <tr key={i}>
                    <td><span className={`badge badge-${f.severity}`}>{f.severity}</span></td>
                    <td>{f.category}</td>
                    <td>{f.description}</td>
                    <td className="mono">{f.file_path?.split("/").pop() || "-"}</td>
                    <td>{f.cwe || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}