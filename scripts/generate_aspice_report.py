#!/usr/bin/env python3

"""
ASPICE CI Dashboard Generator

Reads:
- JUnit XML test reports
- JaCoCo XML coverage report
- Trivy filesystem and image scan JSON reports
- SonarCloud measures JSON
- SonarCloud quality gate JSON

Generates:
- aspice-report/aspice-report.html
- aspice-report/aspice-report.json
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter


ROOT = Path(".")
EVIDENCE_DIR = ROOT / "evidence"
OUTPUT_DIR = ROOT / "aspice-report"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def safe_int(value, default=0):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def find_files(pattern):
    if not EVIDENCE_DIR.exists():
        return []

    return list(EVIDENCE_DIR.rglob(pattern))


def parse_junit():
    totals = {
        "tests": 0,
        "passed": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0
    }

    report_files = []

    for file in find_files("*.xml"):
        if not (
            file.name.startswith("TEST-")
            or "junit" in file.name.lower