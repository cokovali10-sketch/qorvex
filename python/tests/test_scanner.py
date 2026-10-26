"""Tests for the Qorvex Python scanner framework."""

from __future__ import annotations

import json
import os

from scanners.scanner import (
    BaselineScanner,
    Finding,
    ScanResult,
    SemgrepScanner,
    _registry,
    get_scanner,
    scan_all,
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
    assert any(f.rule_id and "security" in f.rule_id for f in result.findings)
    assert any(f.severity == "high" for f in result.findings)


def test_semgrep_fallback_detects_hardcoded_password(tmp_path, monkeypatch):
    _write(str(tmp_path / "config.py"), 'password = "hunter2"\n')

    scanner = SemgrepScanner()

    def _unavailable(_path):
        raise FileNotFoundError("no semgrep")

    monkeypatch.setattr(scanner, "_run_semgrep", _unavailable)

    result = scanner.scan(str(tmp_path))
    assert any(f.category == "secret" for f in result.findings)


def test_registry_and_get_scanner():
    assert "semgrep" in _registry
    assert "baseline" in _registry
    assert isinstance(get_scanner("baseline"), BaselineScanner)


def test_scan_all_runs_every_registered_scanner(tmp_path, monkeypatch):
    calls = []

    def fake_scan(self, _path):
        calls.append(self.name)
        return ScanResult(self.name, [], [], 0)

    monkeypatch.setattr(SemgrepScanner, "scan", fake_scan)
    monkeypatch.setattr(BaselineScanner, "scan", fake_scan)

    results = scan_all(str(tmp_path))
    assert len(results) == len(_registry)
    assert set(calls) == set(_registry)
