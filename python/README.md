# Qorvex Python Analyzers

Lightweight scanner runners that integrate with Qorvex's Go orchestrator.
Each scanner produces findings in a standardized JSON format.

## Usage

```bash
python -m qorvex_scanners scan /path/to/project --format json
python -m qorvex_scanners list
python -m qorvex_scanners run semgrep /path/to/project
```