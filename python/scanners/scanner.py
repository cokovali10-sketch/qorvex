"""Core scanner framework for Qorvex code analysis.

Each scanner produces a standardized result format that can be consumed
by the Qorvex Go orchestrator and stored in PostgreSQL.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional, Protocol


# ---------------------------------------------------------------------------
# Finding & Result types
# ---------------------------------------------------------------------------

import dataclasses

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
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            result = self._run_basic(project_path)
            result.errors.append(str(e))

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
            # Secrets
            (r"(?i)password\s*=\s*['\"][^'\"]+['\"]", "high", "secret", "Hardcoded password", "CWE-259", "Use env vars or secret manager"),
            (r"(?i)(api[_-]?key|secret[_-]?key)\s*=\s*['\"][^'\"]+['\"]", "high", "secret", "Hardcoded API key", "CWE-798", "Move to .env or vault"),
            (r"(?i)aws_[a-z_]+?(?:access|secret|session)_key\s*=\s*['\"][^'\"]+['\"]", "critical", "secret", "AWS credential detected", "CWE-798", "Use IAM roles or secret manager"),
            (r"\bAKIA[0-9A-Z]{16}\b", "critical", "secret", "AWS access key ID detected", "CWE-798", "Rotate the access key"),
            (r"(?i)-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "critical", "secret", "Private key material detected", "CWE-324", "Rotate the key and update configurations"),
            # Code quality / anti-patterns
            (r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+FROM\s+\w+", "low", "quality", "Direct SQL query", "CWE-89", "Use parameterized queries or ORM"),
            (r"eval\s*\([^)]*\)", "high", "security", "Use of eval()", "CWE-95", "Avoid eval; use safer alternatives"),
            (r"exec\s*\([^)]*\)", "high", "security", "Use of exec()", "CWE-78", "Restrict inputs or use safer APIs"),
            # License compliance
            (r"#\s*license\s*:\s*([^\n]+)", "info", "license", "License header detected", None, "Check license compliance"),
        ]

        # Walk files, skip noisy dirs
        skip_dirs = {".git", ".hg", ".svn", "node_modules", "target", "dist", "build",
                     ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", "vendor"}

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
            for fname in files:
                ext = os.path.splitext(fname)[1]
                if ext in {".py", ".js", ".ts", ".java", ".go", ".rs", ".cpp", ".c", ".php", ".rb", ".php"}:
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
        frameworks: Dict[str, int] = {}

        if not os.path.isdir(project_path):
            return ScanResult(self.name, [], ["path not found"], 0)

        skip_dirs = {".git", ".hg", ".svn", "node_modules", "target", "dist", "build",
                     ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", "vendor"}

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
            for fname in files:
                ext = os.path.splitext(fname)[1]
                if ext in {".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp", ".h", ".hpp", ".rb", ".php", ".cs", ".swift", ".css", ".html"}:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            lines = sum(1 for _ in f)
                        total_files += 1
                        total_lines += lines
                        languages[ext] = languages.get(ext, 0) + 1
                        # Detect simple framework signs
                        self._detect_frameworks(fname, ext, frameworks)
                    except OSError:
                        errors.append(f"cannot read: {fpath}")

        if total_files > 1000:
            findings.append(Finding(
                severity="info",
                category="quality",
                description=f"Large project: {total_files} source files, {total_lines} lines",
            ))

        # Add framework info as findings
        for fw, count in sorted(frameworks.items(), key=lambda x: -x[1]):
            if count >= 3:  # only report frameworks detected in 3+ files
                findings.append(Finding(
                    severity="info",
                    category="quality",
                    description=f"Detected {fw} framework ({count} files)",
                ))

        elapsed = int((time.time() - start) * 1000)
        return ScanResult(self.name, findings, errors, elapsed, total_files)

    @staticmethod
    def _detect_frameworks(filename: str, ext: str, frameworks: Dict[str, int]) -> None:
        name = filename.lower()
        if ext == ".py":
            if "django" in name or "manage.py" in name:
                frameworks["Django"] = frameworks.get("Django", 0) + 1
            if "flask" in name:
                frameworks["Flask"] = frameworks.get("Flask", 0) + 1
            if "fastapi" in name:
                frameworks["FastAPI"] = frameworks.get("FastAPI", 0) + 1
            if "celery" in name:
                frameworks["Celery"] = frameworks.get("Celery", 0) + 1
        elif ext in {".js", ".ts"}:
            if "react" in name.lower():
                frameworks["React"] = frameworks.get("React", 0) + 1
            if "vue" in name.lower():
                frameworks["Vue"] = frameworks.get("Vue", 0) + 1
            if "angular" in name.lower():
                frameworks["Angular"] = frameworks.get("Angular", 0) + 1


class DependencyScanner:
    """Scans dependency manifest files for known vulnerable / unmaintained packages."""

    name = "dependency"

    MANIFESTS = {
        "requirements.txt": "python",
        "package.json": "node",
        "go.mod": "go",
        "Cargo.toml": "rust",
        "pom.xml": "java",
        "build.gradle": "java",
    }

    # Minimal heuristic: packages that look suspicious or unpinned.
    SUSPICIOUS = {
        "pickle", "pyyaml", "requests", "urllib3", "django", "flask",
        "lodash", "moment", "react", "express",
    }

    def scan(self, project_path: str) -> ScanResult:
        import time
        start = time.time()
        findings: List[Finding] = []
        errors: List[str] = []
        total_files = 0

        if not os.path.isdir(project_path):
            return ScanResult(self.name, [], ["path not found"], 0)

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv", "venv", "target", "dist", "build"} and not d.startswith(".")]
            for fname in files:
                if fname not in self.MANIFESTS:
                    continue
                fpath = os.path.join(root, fname)
                total_files += 1
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except OSError as exc:
                    errors.append(f"cannot read {fpath}: {exc}")
                    continue

                lang = self.MANIFESTS[fname]
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("//") or line.startswith("<!--"):
                        continue
                    pkg = self._extract_package(line, lang)
                    if not pkg:
                        continue
                    if pkg.lower() in self.SUSPICIOUS:
                        findings.append(Finding(
                            severity="medium",
                            category="dependency",
                            description=f"Potentially risky dependency: {pkg}",
                            file_path=fpath,
                            rule_id="dep-risky-pkg",
                        ))
                    if self._is_unpinned(line):
                        findings.append(Finding(
                            severity="low",
                            category="dependency",
                            description=f"Unpinned dependency: {pkg}",
                            file_path=fpath,
                            rule_id="dep-unpinned",
                        ))

        elapsed = int((time.time() - start) * 1000)
        return ScanResult(self.name, findings, errors, elapsed, total_files)

    @staticmethod
    def _extract_package(line: str, lang: str) -> Optional[str]:
        if lang == "python":
            m = re.match(r"([A-Za-z0-9_\-\.]+)", line)
            return m.group(1) if m else None
        if lang == "node":
            m = re.match(r'"([^"]+)"\s*:', line)
            return m.group(1) if m else None
        if lang == "go":
            m = re.match(r"([a-z0-9./\-_]+)\s+v?[0-9]", line)
            return m.group(1) if m else None
        if lang == "rust":
            m = re.match(r'([a-z0-9_\-]+)\s*=\s*"', line)
            return m.group(1) if m else None
        if lang == "java":
            m = re.match(r'<artifactId>([^<]+)</artifactId>', line)
            return m.group(1) if m else None
        return None

    @staticmethod
    def _is_unpinned(line: str) -> bool:
        return not any(ch in line for ch in {"=", ">", "<", "~", "^"})


class LicenseScanner:
    """Detects license files and common license headers in source files."""

    name = "license"

    LICENSE_FILES = {"LICENSE", "LICENCE", "LICENSE.txt", "LICENCE.txt", "LICENSE.md", "COPYING"}

    HEADER_PATTERNS = [
        (re.compile(r"MIT License", re.I), "MIT"),
        (re.compile(r"Apache License", re.I), "Apache-2.0"),
        (re.compile(r"GNU General Public License", re.I), "GPL"),
        (re.compile(r"BSD", re.I), "BSD"),
        (re.compile(r"ISC License", re.I), "ISC"),
    ]

    def scan(self, project_path: str) -> ScanResult:
        import time
        start = time.time()
        findings: List[Finding] = []
        errors: List[str] = []
        total_files = 0

        if not os.path.isdir(project_path):
            return ScanResult(self.name, [], ["path not found"], 0)

        # Check for top-level license file.
        for lf in self.LICENSE_FILES:
            fpath = os.path.join(project_path, lf)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        head = f.read(2048)
                    detected = self._detect(head)
                    findings.append(Finding(
                        severity="info",
                        category="license",
                        description=f"License file detected: {lf} ({detected})",
                        file_path=fpath,
                        rule_id="license-file",
                    ))
                    total_files += 1
                except OSError as exc:
                    errors.append(f"cannot read {fpath}: {exc}")
                break

        # Scan source files for SPDX / license headers.
        skip_dirs = {".git", "node_modules", ".venv", "venv", "target", "dist", "build",
                     "__pycache__", ".mypy_cache", ".pytest_cache", "vendor"}
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
            for fname in files:
                if not fname.endswith((".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp", ".h")):
                    continue
                fpath = os.path.join(root, fname)
                total_files += 1
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        head = "".join(f.readlines()[:15])
                except OSError as exc:
                    errors.append(f"cannot read {fpath}: {exc}")
                    continue
                detected = self._detect(head)
                if detected:
                    findings.append(Finding(
                        severity="info",
                        category="license",
                        description=f"License header in {fname}: {detected}",
                        file_path=fpath,
                        rule_id="license-header",
                    ))
                    break  # one header finding per project is enough

        elapsed = int((time.time() - start) * 1000)
        return ScanResult(self.name, findings, errors, elapsed, total_files)

    @staticmethod
    def _detect(text: str) -> str:
        for pattern, lic in LicenseScanner.HEADER_PATTERNS:
            if pattern.search(text):
                return lic
        return "unknown"


# ---------------------------------------------------------------------------
# Scanner registry (used by CLI and package init)
# ---------------------------------------------------------------------------

_registry: dict[str, type] = {}


def register_scanner(name: str, cls: type):
    """Register a scanner by name."""
    _registry[name] = cls


def get_scanner(name: str) -> type:
    """Get scanner class by name."""
    if name not in _registry:
        raise KeyError(f"Scanner '{name}' not registered")
    return _registry[name]


def scan_all(project_path: str) -> list[ScanResult]:
    """Run all registered scanners against a project."""
    results: list[ScanResult] = []
    for name, cls in _registry.items():
        try:
            scanner = cls()
            results.append(scanner.scan(project_path))
        except Exception as exc:
            results.append(ScanResult(
                scanner_name=name,
                findings=[],
                errors=[str(exc)],
                elapsed_ms=0,
            ))
    return results


def scan_with(project_path: str, scanner_name: str) -> ScanResult:
    """Run a specific scanner."""

register_scanner('semgrep', SemgrepScanner)
register_scanner('baseline', BaselineScanner)



def run_bandit(project_path: str, timeout: int = 120) -> List[Finding]:
    """Run bandit security scanner and return findings.

    Returns an empty list if bandit is not installed or errors occur.
    """
    try:
        cmd = ["bandit", "-r", project_path, "--format", "json", "--quiet"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode not in (0, 1):  # bandit exits 1 when findings are found
            return []

        data = json.loads(proc.stdout)
        findings = []
        for item in data:
            severity_map = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
            sev = severity_map.get(item.get("issue_severity", "LOW"), "low")
            findings.append(Finding(
                severity=sev,
                category="security",
                description=item.get("issue_text", "bandit finding"),
                file_path=item.get("filename"),
                line_start=item.get("line_number"),
                cwe=item.get("cwe"),
                remediation=item.get("mitigation", ""),
                rule_id=item.get("test_id"),
            ))
        return findings
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []

register_scanner('dependency', DependencyScanner)
register_scanner('license', LicenseScanner)

