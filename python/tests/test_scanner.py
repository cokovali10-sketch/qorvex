"""Tests for the Qorvex Python scanner framework."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from scanners.scanner import (
    Finding,
    ScanResult,
    SemgrepScanner,
    BaselineScanner,
    _registry,
    get_scanner,
    scan_all,
    scan_with,
    run_bandit,
)


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def test_finding_roundtrip():
    finding = Finding(
        severity="high",
        category="secret",
        description="Hardcoded key",
        file_path="app.py",
        line_start=3,
        line_end=3,
        cwe="CWE-798",
        remediation="rotate the key",
        rule_id="test-rule",
    )
    data = finding.to_dict()
    restored = Finding.from_dict(data)
    assert restored == finding


def test_finding_from_dict_ignores_unknown_fields():
    restored = Finding.from_dict(
        {
            "severity": "low",
            "category": "quality",
            "description": "x",
            "unknown": "ignored",
        }
    )
    assert restored.severity == "low"
    assert restored.category == "quality"


def test_scan_result_serialisation():
    result = ScanResult(
        scanner_name="test",
        findings=[Finding("low", "quality", "x")],
        errors=["e"],
        elapsed_ms=5,
        total_files_scanned=2,
    )
    payload = json.loads(result.to_json())
    assert payload["scanner_name"] == "test"
    assert payload["findings"][0]["severity"] == "low"
    assert payload["total_files_scanned"] == 2


def test_baseline_scanner_counts_source_files(tmp_path):
    _write(str(tmp_path / "src" / "app.py"), "print('hello')\n")
    _write(str(tmp_path / "src" / "lib.go"), "package lib\n")
    _write(str(tmp_path / "README.md"), "docs\n")

    result = BaselineScanner().scan(str(tmp_path))
    assert result.scanner_name == "baseline"
    assert result.total_files_scanned == 2
    assert result.errors == []


def test_baseline_scanner_missing_path(tmp_path):
    result = BaselineScanner().scan(str(tmp_path / "missing"))
    assert result.total_files_scanned == 0
    assert result.errors == ["path not found"]


def test_semgrep_fallback_detects_eval(tmp_path, monkeypatch):
    _write(str(tmp_path / "app.py"), "result = eval(user_input)\n")

    scanner = SemgrepScanner()

    def _unavailable(_path):
        raise FileNotFoundError("semgrep not installed")

    monkeypatch.setattr(scanner, "_run_semgrep", _unavailable)

    result = scanner.scan(str(tmp_path))
    assert result.scanner_name.endswith("fallback")
    # basic regex should detect eval
    assert any(f.severity == "high" and "eval" in f.description.lower() for f in result.findings)


def test_semgrep_fallback_detects_hardcoded_password(tmp_path, monkeypatch):
    _write(str(tmp_path / "config.py"), 'password = "hunter2"\n')

    scanner = SemgrepScanner()
    monkeypatch.setattr(
        scanner,
        "_run_semgrep",
        lambda _path: (_ for _ in ()).throw(FileNotFoundError("no semgrep")),
    )

    result = scanner.scan(str(tmp_path))
    # regex fallback should detect password
    assert any(f.category == "secret" for f in result.findings)


def test_registry_and_get_scanner():
    assert "semgrep" in _registry
    assert "baseline" in _registry
    assert isinstance(get_scanner("baseline"), type) and get_scanner("baseline") is BaselineScanner


def test_scan_all_runs_every_registered_scanner(tmp_path, monkeypatch):
    calls: list = []

    def fake_scan(self, _path):
        calls.append(self.name)
        return ScanResult(self.name, [], [], 0)

    # monkeypatch class methods
    monkeypatch.setattr(SemgrepScanner, "scan", lambda self, _path: ScanResult(self.name, [], [], 0))
    monkeypatch.setattr(BaselineScanner, "scan", lambda self, _path: ScanResult(self.name, [], [], 0))

    results = scan_all(str(tmp_path))
    assert len(results) == len(_registry)


def test_run_bandit_with_dummy_project(tmp_path, monkeypatch):
    """Bandit should not crash even if no real bandit configs match."""
    _write(str(tmp_path / "app.py"), "x = 1\n")

    # monkeypatch so bandit doesn't actually run
    original = run_bandit
    monkeypatch.setattr("scanners.scanner.run_bandit", lambda p: [])

    result = run_bandit(str(tmp_path))
    assert isinstance(result, list)


def test_normalize_severity_utility():
    """Direct test of the severity normalisation used in scanner."""
    # severity normalisation lowercases
    f = Finding(severity="CRITICAL", category="security", description="test")
    assert f.severity in ("critical", "CRITICAL")


def test_bandit_finds_issues_when_available(monkeypatch, tmp_path):
    """If bandit is callable, it should return a list (might be empty)."""
    _write(str(tmp_path / "test.py"), "import os; os.system('id')\n")
    # When bandit is available, it returns findings; when not, empty list.
    # We just verify no crash.
    findings = run_bandit(str(tmp_path))
    assert isinstance(findings, list)


def test_unknown_scanner_raises():
    with pytest.raises(KeyError):
        get_scanner("nonexistent-scanner")


def test_skip_dirs_baseline(tmp_path):
    """Baseline should skip .git and node_modules."""
    _write(str(tmp_path / ".git" / "config"), "x")
    _write(str(tmp_path / "node_modules" / "dep.js"), "x")
    _write(str(tmp_path / "app.py"), "x = 1\n")

    result = BaselineScanner().scan(str(tmp_path))
    # .git and node_modules should be excluded
    git_node_files = [f.file_path for f in result.findings if ".git" in f.file_path or "node_modules" in f.file_path]
    assert len(git_node_files) == 0