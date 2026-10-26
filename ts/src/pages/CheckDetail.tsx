import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, CheckRun } from "../api";

function duration(start: string, end: string): string {
  if (!start || !end) return "running...";
  const ms = new Date(end).getTime() - new Date(start).getTime();
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

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

  const counts = check.result?.severity_counts || {};
  const risk = check.result?.risk_level;

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
          <div className="stat-label">Risk</div>
          <div className={`stat-value badge-${risk || "pending"}`}>{risk ?? "pending..."}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Duration</div>
          <div className="stat-value">{duration(check.start_time, check.end_time)}</div>
        </div>
      </div>

      {check.error && <div className="error">{check.error}</div>}

      {check.stages && check.stages.length > 0 && (
        <div className="panel" style={{ marginBottom: 24 }}>
          <h2>Pipeline stages</h2>
          <table className="table">
            <thead>
              <tr><th>Stage</th><th>Status</th><th>Duration</th><th>Error</th></tr>
            </thead>
            <tbody>
              {check.stages.map((s) => (
                <tr key={s.name}>
                  <td className="mono">{s.name}</td>
                  <td><span className={`badge badge-${s.status}`}>{s.status}</span></td>
                  <td>{duration(s.start_time, s.end_time)}</td>
                  <td className="mono">{s.error || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {check.result && (
        <>
          <div className="panel" style={{ marginBottom: 24 }}>
            <h2>Summary</h2>
            <p>{check.result.summary}</p>
            <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
              {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
                <span key={sev} className={`badge badge-${sev}`}>
                  {sev}: {counts[sev] ?? 0}
                </span>
              ))}
            </div>
          </div>

          <div className="panel" style={{ marginBottom: 24 }}>
            <h2>Findings ({check.result.findings?.length || 0})</h2>
            <table className="table">
              <thead>
                <tr><th>Severity</th><th>Category</th><th>Description</th><th>File</th><th>CWE</th></tr>
              </thead>
              <tbody>
                {check.result.findings?.map((f, i) => (
                  <tr key={f.id || i}>
                    <td><span className={`badge badge-${f.severity}`}>{f.severity}</span></td>
                    <td>{f.category}</td>
                    <td>{f.description}</td>
                    <td className="mono">
                      {f.file_path ? `${f.file_path.split(/[\\/]/).pop()}${f.line_start ? `:${f.line_start}` : ""}` : "-"}
                    </td>
                    <td>{f.cwe || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {check.result.sbom && (
            <div className="panel">
              <h2>Dependency manifests (SBOM)</h2>
              <pre className="mono">{check.result.sbom}</pre>
            </div>
          )}
        </>
      )}
    </div>
  );
}
