const API_BASE = "/api/v1";

async function request<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(error.error || res.statusText);
  }
  return res.json();
}

export interface Project {
  id: string;
  name: string;
  path: string;
  created_at: string;
  updated_at: string;
}

export interface Stage {
  name: string;
  status: "pending" | "running" | "completed" | "completed_with_errors" | "failed" | "skipped";
  start_time: string;
  end_time: string;
  error?: string;
}

export interface Report {
  id?: string;
  check_run_id?: string;
  score: number;
  risk_level?: "low" | "medium" | "high" | "critical";
  severity_counts?: Record<string, number>;
  findings: Finding[];
  summary: string;
  sbom?: string;
}

export interface CheckRun {
  id: string;
  project_id: string;
  status: string;
  start_time: string;
  end_time: string;
  result?: Report;
  error?: string;
  stages?: Stage[];
}

export interface Finding {
  id?: string;
  check_run_id?: string;
  project_id?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
  cwe?: string;
  remediation?: string;
  rule_id?: string;
}

export interface Policy {
  id: string;
  name: string;
  version: number;
  frozen: boolean;
  rules: { id: string; severity: string; category: string; pattern: string; description: string }[];
  created_at: string;
  updated_at: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  resource_id: string;
  detail: string;
  signature: string;
}

export const api = {
  health: () => request<{ status: string; version: string }>("/health"),

  projects: {
    list: () => request<Project[]>("/projects"),
    get: (id: string) => request<Project>(`/projects/${id}`),
    create: (name: string, path: string) =>
      request<Project>("/projects", {
        method: "POST",
        body: JSON.stringify({ name, path }),
      }),
    checks: (id: string) => request<CheckRun[]>(`/projects/${id}/checks`),
    findings: (id: string) => request<Finding[]>(`/projects/${id}/findings`),
  },

  checks: {
    get: (id: string) => request<CheckRun>(`/checks/${id}`),
    start: (projectId: string) =>
      request<CheckRun>(`/projects/${projectId}/checks`, {
        method: "POST",
      }),
  },

  policies: {
    list: () => request<Policy[]>("/policies"),
    get: (id: string) => request<Policy>(`/policies/${id}`),
    save: (policy: Partial<Policy>) =>
      request<Policy>("/policies", {
        method: "POST",
        body: JSON.stringify(policy),
      }),
  },

  audit: {
    list: () => request<AuditEntry[]>("/audit"),
    verify: () => request<{ valid: boolean; invalid: string[] }>("/audit/verify"),
    stats: () => request<Record<string, unknown>>("/audit/stats"),
  },
};