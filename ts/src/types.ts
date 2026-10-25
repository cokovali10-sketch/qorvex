/// <reference types="vite/client" />

interface Project {
  id: string;
  name: string;
  path: string;
  created_at: string;
  updated_at: string;
}

interface CheckRun {
  id: string;
  project_id: string;
  status: "pending" | "running" | "completed" | "failed";
  start_time: string;
  end_time: string;
  result?: Report;
  error?: string;
}

interface Report {
  id: string;
  check_run_id: string;
  score: number;
  findings: Finding[];
  summary: string;
  sbom?: string;
}

interface Finding {
  id: string;
  check_run_id: string;
  project_id: string;
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

interface Policy {
  id: string;
  name: string;
  version: number;
  rules: Rule[];
  frozen: boolean;
  created_at: string;
  updated_at: string;
}

interface Rule {
  id: string;
  severity: "block" | "warn" | "allow";
  category: string;
  pattern: string;
  description: string;
}

interface AuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  resource_id: string;
  detail: string;
  signature: string;
}

interface HealthResponse {
  status: string;
  version: string;
}