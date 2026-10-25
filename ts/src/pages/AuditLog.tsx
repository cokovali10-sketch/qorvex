import React, { useEffect, useState } from "react";
import { api, AuditEntry } from "../api";

export function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [integrity, setIntegrity] = useState<{ valid: boolean; invalid: string[] } | null>(null);

  useEffect(() => {
    api.audit.list().then(setEntries);
    api.audit.verify().then(setIntegrity);
  }, []);

  const severityClass = (action: string) => {
    if (action.includes("block") || action.includes("blocked")) return "badge-critical";
    if (action.includes("warn") || action.includes("warned")) return "badge-high";
    if (action.includes("policy")) return "badge-medium";
    return "";
  };

  return (
    <div>
      <h1>Audit Log</h1>
      {integrity && (
        <div className={`integrity-badge ${integrity.valid ? "valid" : "invalid"}`}>
          {integrity.valid ? "✓ Audit Log Integrity Verified" : `✗ Tampered entries: ${integrity.invalid.length}`}
        </div>
      )}

      <table className="table">
        <thead>
          <tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Detail</th><th>Signature</th></tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id}>
              <td>{new Date(e.timestamp).toLocaleString()}</td>
              <td><span className={`badge ${severityClass(e.action)}`}>{e.actor}</span></td>
              <td className="mono">{e.action}</td>
              <td className="mono">{e.resource_id?.slice(0, 12)}</td>
              <td>{e.detail}</td>
              <td className="mono" title={e.signature}>{e.signature.slice(0, 8)}…</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}