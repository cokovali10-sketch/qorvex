# Qorvex Python Analyzers

Lightweight scanner runners that integrate with Qorvex's Go orchestrator.
Each scanner produces findings in a standardized JSON format.

## Usage

```bash
# Run from the python/ directory
python -m scanners.cli scan /path/to/project --format json
python -m scanners.cli list
python -m scanners.cli run semgrep /path/to/project
```

Exit code is `1` when high/critical findings are present, so the CLI can be
used as a CI gate.

## Tests

```bash
python -m pytest tests -q
```
