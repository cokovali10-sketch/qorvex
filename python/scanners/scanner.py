"""Core scanner framework for Qorvex code analysis.

Each scanner produces a standardized result format that can be consumed
by the Qorvex Go orchestrator and stored in PostgreSQL.
"""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
import tempfile
from typing import List, Optional, Protocol


@dataclasses.dataclass
class Finding:
    """A single code quality or security finding."""
    severity: str          # critical, high, medium, low, info
    category: str          # security, quality, dependency, secret, sast, license
    description: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    cwe: Optional[str] = None
    remediation: Optional[str] = None
    rule_id: Optional[str] = None

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclasses.dataclass
class ScanResult:
    """Aggregated result from a scanner run."""
    scanner_name: str
    findings: List[Finding]
    errors: List[str]
    elapsed_ms: int
    total_files_scanned: int = 0

    def to_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "elapsed_ms": self.elapsed_ms,
            "total_files_scanned": self.total_files_scanned,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class Scanner(Protocol):
    """Protocol for a Qorvex scanner plugin."""
    name: str

    def scan(self, project_path: str) -> ScanResult:
        """Run the scanner against a project directory."""
        ...


# ---------------------------------------------------------------------------
# Built-in Semantic Scanner (uses semgrep when available, else basic regex)
# ---------------------------------------------------------------------------

class SemgrepScanner:
    """Wrapper around semgrep SAST scanner."""

    name = "semgrep"

    def __init__(self, config: Optional[str] = None):
        self.config = config or "auto"

    def scan(self, project_path: str) -> ScanResult:
        import time
        start = time.time()

        if not os.path.isdir(project_path):
            return ScanResult(
                scanner_name=self.name,
                findings=[],
                errors=[f"path not found: {project_path}"],
                elapsed_ms=0,
            )

        # Try semgrep; fall back to basic regex analysis
        try:
            result = self._run_semgrep(project_path)
        except (FileNotFoundError, subprocess.CalledProcessError):
            result = self._run_basic(project_path)

        elapsed = int((time.time() - start) * 1000)
        result.elapsed_ms = elapsed
        return result

    def _run_semgrep(self, path: str) -> ScanResult:
        proc = subprocess.run(
            ["semgrep", "--json", "--config", self.config, path],
            capture_output=True, text=True, timeout=120,
        )
        data = json.loads(proc.stdout)
        findings = []
        for result in data.get("results", []):
            findings.append(Finding(
                severity=result.get("extra", {}).get("severity", "medium"),
                category="sast",
                description=result.get("extra", {}).get("message", "no message"),
                file_path=result.get("path"),
                line_start=result.get("start", {}).get("line"),
                line_end=result.get("end", {}).get("line"),
                cwe=result.get("extra", {}).get("metadata", {}).get("cwe", ""),
                remediation=result.get("extra", {}).get("fix", ""),
                rule_id=result.get("check_id"),
            ))
        return ScanResult(
            scanner_name=self.name,
            findings=findings,
            errors=[],
            elapsed_ms=0,
            total_files_scanned=len(data.get("paths", {}).get("scanned", [])),
        )

    def _run_basic(self, path: str) -> ScanResult:
        """Simple regex-based fallback scanner."""
        import re
        findings = []

        patterns = [
            (r"(?i)password\s*=\s*['\"][^'\"]+['\"]", "high", "secret", "Hardcoded password", "CWE-259", "Use env vars or secret manager"),
            (r"(?i)(api[_-]?key|secret[_-]?key)\s*=\s*['\"][^'\"]+['\"]", "high", "secret", "Hardcoded API key", "CWE-798", "Move to .env or vault"),
            (r"(?i)(SELECT|INSERT|UPDATE|DELETE).*FROM", "low", "quality", "Direct SQL query", "CWE-89", "Use parameterized queries"),
            (r"eval\s*\([^)]*\)", "high", "security", "Use of eval()", "CWE-95", "Avoid eval; use safer alternatives"),
            (r"exec\s*\([^)]*\)", "high", "security", "Use of exec()", "CWE-78", "Avoid exec; restrict inputs"),
        ]

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith((".", "__pycache__", "node_modules", "vendor"))]
            for fname in files:
                if fname.endswith((".py", ".js", ".ts", ".java", ".go", ".rs", ".cpp", ".c", ".php")):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            for lineno, line in enumerate(f, 1):
                                for pattern, severity, category, desc, cwe, remediation in patterns:
                                    if re.search(pattern, line):
                                        findings.append(Finding(
                                            severity=severity,
                                            category=category,
                                            description=desc,
                                            file_path=fpath,
                                            line_start=lineno,
                                            cwe=cwe,
                                            remediation=remediation,
                                            rule_id=f"regex-{category}-{severity}",
                                        ))
                    except (OSError, UnicodeDecodeError):
                        continue

        return ScanResult(
            scanner_name=f"{self.name}-fallback",
            findings=findings,
            errors=[],
            elapsed_ms=0,
            total_files_scanned=0,
        )


# ---------------------------------------------------------------------------
# Baseline scanner (location + size + structure)
# ---------------------------------------------------------------------------

class BaselineScanner:
    """Scans project structure and metrics."""

    name = "baseline"

    def scan(self, project_path: str) -> ScanResult:
        import time
        start = time.time()

        findings: List[Finding] = []
        total_files = 0
        total_lines = 0
        languages: dict = {}
        errors: List[str] = []

        if not os.path.isdir(project_path):
            return ScanResult(self.name, [], ["path not found"], 0)

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if not d.startswith((".", "__pycache__", "node_modules", "vendor"))]
            for fname in files:
                ext = os.path.splitext(fname)[1]
                if ext in {".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp", ".h", ".hpp", ".rb", ".php", ".cs", ".swift"}:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            lines = sum(1 for _ in f)
                        total_files += 1
                        total_lines += lines
                        languages[ext] = languages.get(ext, 0) + 1
                    except OSError:
                        errors.append(f"cannot read: {fpath}")

        if total_files > 1000:
            findings.append(Finding(
                severity="info",
                category="quality",
                description=f"Large project: {total_files} source files, {total_lines} lines",
            ))

        elapsed = int((time.time() - start) * 1000)
        return ScanResult(self.name, findings, errors, elapsed, total_files)


# ---------------------------------------------------------------------------
# Scanner registry and runner
# ---------------------------------------------------------------------------

_registry: dict = {
    "semgrep": SemgrepScanner,
    "baseline": BaselineScanner,
}


def register_scanner(name: str, scanner_cls):
    """Register a custom scanner."""
    _registry[name] = scanner_cls


def get_scanner(name: str) -> Scanner:
    """Get a scanner instance by name."""
    if name not in _registry:
        raise KeyError(f"unknown scanner: {name}. Available: {list(_registry.keys())}")
    cls = _registry[name]
    if isinstance(cls, type):
        return cls()
    return cls


def scan_all(project_path: str) -> List[ScanResult]:
    """Run all registered scanners against a project."""
    results = []
    for name in _registry:
        try:
            scanner = get_scanner(name)
            results.append(scanner.scan(project_path))
        except Exception as e:
            results.append(ScanResult(
                scanner_name=name,
                findings=[],
                errors=[str(e)],
                elapsed_ms=0,
            ))
    return results


def scan_with(name: str, project_path: str) -> ScanResult:
    """Run a single named scanner."""
    scanner = get_scanner(name)
    return scanner.scan(project_path)