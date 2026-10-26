// Qorvex TypeScript Dashboard
// Main dashboard with authentication, pipeline stages, risk levels, and SBOM

import React, { useEffect, useState } from "react";
import { api, Project, Policy, CheckRun, Finding, AuditEntry, AuthState } from "../api";
import { useParams, useNavigate } from "react-router-dom";

function duration(start: string, end: string): string {
  if (!start || !end) return "running...";
  const ms = new Date(end).getTime() - new Date(start).getTime();
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

// Color mapping for risk levels
const riskColors: Record<string, string> = {
    critical: "red",
    high: "orange",
    medium: "yellow",
    low: "green",
    info: "blue",
    pending: "gray",
};

const riskLabels: Record<string, string> = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",
    pending: "Pending",
};

// Check if risk level means failure (fail-closed)
function isRiskFailed(risk: string | undefined): boolean {
    return risk === "critical";
}

export function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState({
    projects: 0,
    checks: 0,
    findings: 0,
    health: "checking..." as string,
  });
  const [recentChecks, setRecentChecks] = useState<CheckRun[]>([]);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    // Check auth state
    const checkAuth = async () => {
      try {
        const isAuth = await api.isAuthenticated();
        setIsLoggedIn(isAuth);
      } catch {
        setIsLoggedIn(false);
      }
    };

    async function fetchAll() {
      try {
        // Health check
        const h = await api.health();
        setStats((s) => ({ ...s, health: `v${h.version} ${h.status}` }));

        // Projects
        const ps = await api.projects.list();
        setStats((s) => ({ ...s, projects: ps.length }));

        // Recent checks for first 5 projects
        const checkPromises = ps.slice(0, 5).map((p) => api.projects.checks(p.id));
        const checkResults = await Promise.all(checkPromises);
        const flattened = checkResults.flat();
        setRecentChecks(flattened.slice(0, 10));

        // Policies
        const pols = await api.policies.list();
        setPolicies(pols);

        // Audit
        const entries = await api.audit.list();
        setAuditEntries(entries.slice(0, 20));

        setLoading(false);
      } catch (e) {
        setLoading(false);
      }
    }

    // Wait for auth check, then fetch
    checkAuth().then(fetchAll);
  }, []);

  if (loading) {
    return (
      <div className="dashboard">
        <div className="stat-card">
          <div className="stat-value">Loading...</div>
          <div className="stat-label">Initializing</div>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>Qorvex Platform</h1>
        <p className="subtitle">Build. Test. Verify. — AI Code Verification Engine</p>

        {/* Auth status display */}
        {isLoggedIn ? (
          <span className="badge green">🟢 Authenticated</span>
        ) : (
          <span className="badge red">🔴 Not authenticated</span>
        )}

        {/* Login/logout links */}
        {isLoggedIn ? (
          <button
            className="btn btn-sm btn-link"
            onClick={() => {
              api.logout().then(() => navigate("/login"));
            }}
          >
            Logout
          </button>
        ) : (
          <>
            <button
              className="btn btn-sm btn-link"
              onClick={() => navigate("/login")}
            >
              Login
            </button>
          </>
        )}
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
              <tr>
                <th>ID</th>
                <th>Status</th>
                <th>Score</th>
                <th>Risk</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {recentChecks.map((c) => (
                <tr key={c.id} className="clickable" onClick={() => navigate(`/checks/${c.id}`)}>
                  <td className="mono">{c.id.slice(0, 12)}…</td>
                  <td>
                    <span className={`badge badge-${c.status}`}>
                      {c.status}
                    </span>
                  </td>
                  <td>{c.result?.score ?? "-"}</td>
                  <td>
                    <span className={`badge badge-${c.result?.risk_level || "pending"}`}>
                      {riskLabels[c.result?.risk_level || "pending"]}
                    </span>
                  </td>
                  <td>{duration(c.start_time || "", c.end_time || "")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <h2>Policies</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Version</th>
                <th>Frozen</th>
                <th>Rules</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id}>
                  <td>
                    <a href={`/policies/${p.id}`} className="link">{p.name}</a>
                  </td>
                  <td>{p.version}</td>
                  <td>{p.frozen ? "🔒" : ""}</td>
                  <td>{(p.rules || []).length}</td>
                  <td>
                    <button className="btn btn-sm" onClick={() => navigate(`/policies/${p.id}`)}>
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="panel">
          <h2>Audit Log</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Actor</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Severity</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {auditEntries.slice(0, 10).map((e) => (
                <tr key={e.id}>
                  <td>{e.actor}</td>
                  <td className="mono">{e.action}</td>
                  <td className="mono">
                    {e.resource_id || "-"}
                  </td>
                  <td>
                    {e.detail && e.detail.match(/critical|high/i)
                      ? "high"
                      : "low"}
                  </td>
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

export function CheckPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [check, setCheck] = useState<CheckRun | null>(null);
  const [error, setError] = useState("");
  const [riskFailed, setRiskFailed] = useState(false);

  useEffect(() => {
    if (!id) return;
    const poll = setInterval(async () => {
      try {
        const c = await api.checks.get(id);
        setCheck(c);
        // Update risk failed state based on fail-closed policy
        if (c.result) {
          const risk = c.result.risk_level;
          setRiskFailed(isRiskFailed(risk));
        }
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

  // Fail-closed: if risk is critical, show as failed regardless of score
  const effectiveStatus = isRiskFailed(risk) ? "failed" : check.status;

  return (
    <div>
      <h1>Check Run #{check.id}</h1>

      {/* Status badge with risk awareness */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-label">Status</div>
          <div className={`stat-value badge-${effectiveStatus}`}>
            {effectiveStatus}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Risk</div>
          <div className={`stat-value badge-${risk || "pending"}`}>
            {riskLabels[risk] || risk}
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Score</div>
          <div className="stat-value">{check.result?.score ?? "pending"}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Duration</div>
          <div className="stat-value">
            {check.start_time && check.end_time
              ? `${Math.round(
                  (new Date(check.end_time).getTime() -
                    new Date(check.start_time).getTime()) /
                    1000,
                )}s`
              : "running..."}
          </div>
        </div>
      </div>

      {/* Risk warning if critical */}
      {isRiskFailed(risk) && (
        <div className="panel warning">
          <h3>⚠️ Fail-Closed Security</h3>
          <p>
            Check marked as <strong>failed</strong> due to critical risk level. This
            is fail-closed behavior — critical risks always result in failure
            regardless of other scores.
          </p>
        </div>
      )}

      {check.error && <div className="error">{check.error}</div>}

      {check.stages && check.stages.length > 0 && (
        <div className="panel" style={{ marginBottom: 24, borderTop: "1px solid var(--border)" }}>
          <h2>Pipeline stages</h2>
          <table className="table">
            <thead>
              <tr><th>Stage</th><th>Status</th><th>Start</th><th>End</th><th>Error</th></tr>
            </thead>
            <tbody>
              {check.stages.map((s: any) => (
                <tr key={s.name}>
                  <td className="mono">{s.name}</td>
                  <td>
                    <span className={`badge badge-${s.status}`}>
                      {s.status}
                    </span>
                  </td>
                  <td>{s.start_time ? new Date(s.start_time).toLocaleString() : "-"}</td>
                  <td>{s.end_time ? new Date(s.end_time).toLocaleString() : "-"}</td>
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
              {[...Array(5).keys()].map((i) => {
                const sev = ["critical", "high", "medium", "low", "info"][i];
                const count = counts[sev] || 0;
                return count > 0 && (
                  <span key={sev} className={`badge badge-${sev}`}>
                    {sev}: {count}
                  </span>
                );
              })}
            </div>
          </div>

          <div className="panel" style={{ marginBottom: 24 }}>
            <h2>Findings ({check.result.findings?.length || 0})</h2>
            <table className="table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Category</th>
                  <th>Description</th>
                  <th>File</th>
                  <th>CWE</th>
                </tr>
              </thead>
              <tbody>
                {check.result.findings?.map((f: any, i: any) => (
                  <tr key={f.id || i}>
                    <td>
                      <span className={`badge badge-${f.severity}`}>
                        {f.severity}
                      </span>
                    </td>
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
              <pre className="mono" style={{ overflowX: "auto" }}>
                {check.result.sbom}
              </pre>
            </div>
          )}

          {/* Risk level indicator */}
          {risk && (
            <div className="panel" style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--border)" }}>
              <h3>Risk level: {riskLabels[risk]}</h3>
              <p>
                {isRiskFailed(risk) ? (
                  "This check failed due to critical risk (fail-closed policy)."
                ) : (
                  "Check passed — no critical risks detected."
                )}
              </p>
            </div>
          )}
        </>
      )}
    </div>
  );
}