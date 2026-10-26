import React, { useEffect, useState } from "react";
import { api, Policy } from "../api";

export function Policies() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    api.policies.list().then(setPolicies);
  }, []);

  return (
    <div>
      <h1>Policies</h1>
      {policies.length === 0 && <p className="empty">No policies configured.</p>}
      {policies.map((p) => (
        <div key={p.id} className="policy-card" onClick={() => setExpanded(expanded === p.id ? null : p.id)}>
          <div className="policy-header">
            <strong>{p.name}</strong>
            <span className="badge">v{p.version}</span>
            {p.frozen && <span className="badge badge-frozen">frozen</span>}
          </div>
          {expanded === p.id && (
            <div className="policy-rules">
              {(p.rules || []).map((r) => (
                <div key={r.id} className="rule-row">
                  <span className={`badge badge-${r.severity}`}>{r.severity}</span>
                  <span>{r.category}</span>
                  <span className="mono">{r.pattern}</span>
                  <span>{r.description}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}