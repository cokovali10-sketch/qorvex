import React, { useEffect, useState } from "react";
import { api, CheckRun, AuditEntry } from "../api";

export function Dashboard() {
  const [stats, setStats] = useState({
    projects: 0,
    checks: 0,
    findings: 0,
    health: "checking..." as string,
  });
  const [recentChecks, setRecentChecks] = useState<CheckRun[]>([]);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);

  useEffect(() => {
    api.health().then((h) => setStats((s) => ({ ...s, health: `v${h.version} ${h.status}` })));
    api.projects.list().then((ps) => {
      setStats((s) => ({ ...s, projects: ps.length }));
      ps.slice(0, 5).forEach((p) => {
        api.projects.checks(p.id).then((checks) => {
          setRecentChecks((prev) => [...prev, ...checks].slice(0, 10));
        });
      });
    });
    api.audit.list().then((entries) => setAuditEntries(entries.slice(0, 5)));
  }, []);

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>Qorvex Platform</h1>
        <p className="subtitle">Build. Test. Verify. — AI Code Verification Engine</p>
        <span className="badge">{stats.health}</span>
      </header>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-value">{stats.projects}</div>
          <div className="stat-label">Projects</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{recentChecks.length}</div>
          <div className="stat-label">Checks</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{auditEntries.length}</div>
          <div className="stat-label">Audit Entries</div>
        </div>
        <div className="stat-card">
          <div className="stat-value green">✓</div>
          <div className="stat-label">System Online</div>
        </div>
      </div>

      <div className="panels">
        <div className="panel">
          <h2>Recent Checks</h2>
          <table className="table">
            <thead>
              <tr><th>ID</th><th>Status</th><th>Score</th><th>Time</th></tr>
            </thead>
            <tbody>
              {recentChecks.slice(0, 5).map((c) => (
                <tr key={c.id} className="clickable" onClick={() => window.location.href = `/checks/${c.id}`}>
                  <td className="mono">{c.id.slice(0, 12)}…</td>
                  <td><span className={`badge badge-${c.status}`}>{c.status}</span></td>
                  <td>{c.result?.score ?? "-"}</td>
                  <td>{new Date(c.start_time).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <h2>Audit Log</h2>
          <table className="table">
            <thead>
              <tr><th>Actor</th><th>Action</th><th>Time</th></tr>
            </thead>
            <tbody>
              {auditEntries.slice(0, 5).map((e) => (
                <tr key={e.id}>
                  <td>{e.actor}</td>
                  <td className="mono">{e.action}</td>
                  <td>{new Date(e.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}