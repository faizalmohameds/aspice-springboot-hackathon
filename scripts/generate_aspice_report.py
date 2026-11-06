
#!/usr/bin/env python3

"""
ASPICE CI Dashboard Generator

Reads:
- JUnit XML reports
- JaCoCo XML coverage
- Trivy filesystem JSON
- Trivy image JSON
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
from html import escape
import os


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
            or "junit" in file.name.lower()
        ):
            continue

        try:
            root = ET.parse(file).getroot()

            suites = (
                [root]
                if root.tag == "testsuite"
                else root.findall(".//testsuite")
            )

            if root.tag == "testsuites":
                suites = root.findall("testsuite")

            for suite in suites:
                tests = safe_int(suite.get("tests"))
                failures = safe_int(suite.get("failures"))
                errors = safe_int(suite.get("errors"))
                skipped = safe_int(suite.get("skipped"))

                totals["tests"] += tests
                totals["failures"] += failures
                totals["errors"] += errors
                totals["skipped"] += skipped

                totals["passed"] += max(
                    0,
                    tests - failures - errors - skipped
                )

            report_files.append(str(file))

        except (ET.ParseError, OSError) as exc:
            print(f"Unable to parse JUnit report {file}: {exc}")

    return {
        **totals,
        "reports_found": len(report_files),
        "report_files": report_files
    }


def parse_jacoco():
    result = {
        "found": False,
        "line_coverage": 0.0,
        "branch_coverage": 0.0,
        "covered_lines": 0,
        "missed_lines": 0,
        "covered_branches": 0,
        "missed_branches": 0
    }

    files = find_files("jacoco.xml")

    if not files:
        print("JaCoCo report not found.")
        return result

    try:
        root = ET.parse(files[0]).getroot()

        for counter in root.findall("counter"):
            counter_type = counter.get("type")
            covered = safe_int(counter.get("covered"))
            missed = safe_int(counter.get("missed"))
            total = covered + missed

            if counter_type == "LINE":
                result["covered_lines"] = covered
                result["missed_lines"] = missed
                result["line_coverage"] = (
                    covered / total * 100 if total else 0
                )

            elif counter_type == "BRANCH":
                result["covered_branches"] = covered
                result["missed_branches"] = missed
                result["branch_coverage"] = (
                    covered / total * 100 if total else 0
                )

        result["found"] = True

    except (ET.ParseError, OSError) as exc:
        print(f"Unable to parse JaCoCo report: {exc}")

    return result


def parse_trivy_file(file):
    result = Counter({
        "UNKNOWN": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    })

    categories = Counter({
        "Vulnerabilities": 0,
        "Misconfigurations": 0,
        "Secrets": 0
    })

    try:
        data = json.loads(file.read_text(encoding="utf-8"))

        for item in data.get("Results", []):
            for vulnerability in item.get("Vulnerabilities") or []:
                severity = vulnerability.get(
                    "Severity", "UNKNOWN"
                ).upper()
                result[severity] += 1
                categories["Vulnerabilities"] += 1

            for config in item.get("Misconfigurations") or []:
                severity = config.get(
                    "Severity", "UNKNOWN"
                ).upper()
                result[severity] += 1
                categories["Misconfigurations"] += 1

            for secret in item.get("Secrets") or []:
                severity = secret.get(
                    "Severity", "UNKNOWN"
                ).upper()
                result[severity] += 1
                categories["Secrets"] += 1

        return {
            "found": True,
            "severity": dict(result),
            "categories": dict(categories),
            "total": sum(result.values())
        }

    except (json.JSONDecodeError, OSError, AttributeError) as exc:
        print(f"Unable to parse Trivy report {file}: {exc}")

    return {
        "found": False,
        "severity": dict(result),
        "categories": dict(categories),
        "total": 0
    }


def parse_trivy_reports():
    filesystem_files = [
        file for file in find_files("*.json")
        if "ASPICE-Trivy-Filesystem" in str(file)
        or "trivy-fs" in file.name.lower()
    ]

    image_files = [
        file for file in find_files("*.json")
        if "ASPICE-Trivy-Image" in str(file)
        or "trivy-image" in file.name.lower()
    ]

    def combine(files):
        combined = {
            "found": False,
            "severity": Counter(),
            "categories": Counter(),
            "total": 0
        }

        for file in files:
            report = parse_trivy_file(file)
            if report["found"]:
                combined["found"] = True
                combined["severity"].update(report["severity"])
                combined["categories"].update(report["categories"])
                combined["total"] += report["total"]

        return {
            "found": combined["found"],
            "severity": dict(combined["severity"]),
            "categories": dict(combined["categories"]),
            "total": combined["total"]
        }

    return {
        "filesystem": combine(filesystem_files),
        "image": combine(image_files)
    }


def parse_sonar():
    result = {
        "found": False,
        "quality_gate": "NOT AVAILABLE",
        "metrics": {}
    }

    metric_files = find_files("sonar-measures.json")
    quality_files = find_files("sonar-quality-gate.json")

    if metric_files:
        try:
            data = json.loads(
                metric_files[0].read_text(encoding="utf-8")
            )

            measures = (
                data.get("component", {}).get("measures", [])
            )

            for measure in measures:
                key = measure.get("metric")
                value = measure.get("value")

                if key and value is not None:
                    result["metrics"][key] = value

            result["found"] = True

        except (json.JSONDecodeError, OSError) as exc:
            print(f"Unable to parse Sonar measures: {exc}")

    if quality_files:
        try:
            data = json.loads(
                quality_files[0].read_text(encoding="utf-8")
            )

            status = (
                data.get("projectStatus", {}).get("status")
            )

            if status:
                result["quality_gate"] = status
                result["found"] = True

        except (json.JSONDecodeError, OSError) as exc:
            print(f"Unable to parse Sonar quality gate: {exc}")

    return result


def build_report():
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pipeline": {
            "build": os.getenv("BUILD_RESULT", "UNKNOWN"),
            "tests": os.getenv("TEST_RESULT", "UNKNOWN"),
            "sonar": os.getenv("SONAR_RESULT", "UNKNOWN"),
            "trivy_filesystem": os.getenv(
                "TRIVY_FS_RESULT", "UNKNOWN"
            ),
            "docker_build": os.getenv(
                "DOCKER_BUILD_RESULT", "UNKNOWN"
            ),
            "trivy_image": os.getenv(
                "TRIVY_IMAGE_RESULT", "UNKNOWN"
            ),
            "docker_push": os.getenv(
                "DOCKER_PUSH_RESULT", "UNKNOWN"
            )
        },
        "junit": parse_junit(),
        "jacoco": parse_jacoco(),
        "trivy": parse_trivy_reports(),
        "sonar": parse_sonar()
    }


def status_class(value):
    value = str(value).upper()

    if value in ("SUCCESS", "PASSED", "OK"):
        return "success"

    if value in ("FAILURE", "FAILED", "ERROR"):
        return "danger"

    return "warning"


def metric_card(label, value, detail=""):
    return f"""
    <div class="card">
        <div class="label">{escape(str(label))}</div>
        <div class="value">{escape(str(value))}</div>
        <div class="detail">{escape(str(detail))}</div>
    </div>
    """


def trivy_table(report):
    severity = report.get("severity", {})

    rows = ""

    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        rows += f"""
        <tr>
            <td>{level}</td>
            <td>{severity.get(level, 0)}</td>
        </tr>
        """

    return f"""
    <p>Total findings: <strong>{report.get('total', 0)}</strong></p>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        {rows}
    </table>
    """


def generate_html(data):
    junit = data["junit"]
    jacoco = data["jacoco"]
    sonar = data["sonar"]
    trivy = data["trivy"]
    pipeline = data["pipeline"]

    sonar_metrics = sonar["metrics"]

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ASPICE CI Dashboard</title>

<style>
body {{
    font-family: Arial, sans-serif;
    margin: 0;
    background: #f4f6f9;
    color: #253044;
}}

header {{
    background: #172b4d;
    color: white;
    padding: 28px 5%;
}}

header h1 {{
    margin: 0 0 8px;
}}

.container {{
    max-width: 1200px;
    margin: auto;
    padding: 24px;
}}

.section {{
    margin-bottom: 30px;
}}

.cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
}}

.card {{
    background: white;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 2px 7px rgba(0,0,0,.06);
}}

.label {{
    color: #667085;
    font-size: 14px;
}}

.value {{
    font-size: 27px;
    font-weight: bold;
    margin-top: 10px;
}}

.detail {{
    color: #667085;
    margin-top: 8px;
    font-size: 12px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
}}

th, td {{
    padding: 12px;
    border-bottom: 1px solid #e5e7eb;
    text-align: left;
}}

th {{
    background: #eef2f7;
}}

.success {{ color: #15803d; }}
.danger {{ color: #dc2626; }}
.warning {{ color: #b45309; }}

.panel {{
    background: white;
    border-radius: 8px;
    padding: 20px;
    margin-top: 15px;
}}

footer {{
    text-align: center;
    padding: 25px;
    color: #667085;
}}

@media(max-width:600px) {{
    .container {{ padding: 12px; }}
}}
</style>
</head>

<body>

<header>
    <h1>ASPICE CI Dashboard</h1>
    <p>Spring Boot Continuous Integration and Quality Report</p>
    <small>Generated: {escape(data['generated_at'])}</small>
</header>

<div class="container">

<section class="section">
    <h2>1. Pipeline Execution Status</h2>
    <div class="cards">
"""

    for name, status in pipeline.items():
        html += metric_card(
            name.replace("_", " ").title(),
            status,
            "Pipeline job status"
        )

    html += """
    </div>
</section>

<section class="section">
    <h2>2. Unit Test Results</h2>
    <div class="cards">
"""

    html += metric_card("Total Tests", junit["tests"])
    html += metric_card("Passed", junit["passed"])
    html += metric_card("Failures", junit["failures"])
    html += metric_card("Errors", junit["errors"])
    html += metric_card("Skipped", junit["skipped"])

    html += """
    </div>
</section>

<section class="section">
    <h2>3. JaCoCo Code Coverage</h2>
    <div class="cards">
"""

    html += metric_card(
        "Line Coverage",
        f"{jacoco['line_coverage']:.2f}%",
        f"Covered: {jacoco['covered_lines']} / "
        f"{jacoco['covered_lines'] + jacoco['missed_lines']}"
    )

    html += metric_card(
        "Branch Coverage",
        f"{jacoco['branch_coverage']:.2f}%",
        f"Covered: {jacoco['covered_branches']} / "
        f"{jacoco['covered_branches'] + jacoco['missed_branches']}"
    )

    html += """
    </div>
</section>

<section class="section">
    <h2>4. SonarCloud Quality Analysis</h2>

    <div class="cards">
"""

    html += metric_card(
        "Quality Gate",
        sonar["quality_gate"]
    )

    metric_labels = {
        "coverage": "Coverage",
        "bugs": "Bugs",
        "vulnerabilities": "Vulnerabilities",
        "code_smells": "Code Smells",
        "security_hotspots": "Security Hotspots",
        "duplicated_lines_density": "Duplicated Lines"
    }

    for key, label in metric_labels.items():
        if key in sonar_metrics:
            value = sonar_metrics[key]

            if key in ("coverage", "duplicated_lines_density"):
                value = f"{safe_float(value):.2f}%"

            html += metric_card(label, value)

    html += """
    </div>
</section>

<section class="section">
    <h2>5. Trivy Filesystem Scan</h2>
    <div class="panel">
"""

    html += trivy_table(trivy["filesystem"])

    html += """
    </div>
</section>

<section class="section">
    <h2>6. Trivy Docker Image Scan</h2>
    <div class="panel">
"""

    html += trivy_table(trivy["image"])

    html += """
    </div>
</section>

<section class="section">
    <h2>7. Report Information</h2>
    <div class="panel">
        <p>JUnit XML reports found:
"""

    html += str(junit["reports_found"])

    html += """
        </p>
        <p>JaCoCo report available:
"""

    html += str(jacoco["found"])

    html += """
        </p>
        <p>SonarCloud data available:
"""

    html += str(sonar["found"])

    html += """
        </p>
    </div>
</section>

</div>

<footer>
    Generated automatically by GitHub Actions ASPICE CI Pipeline
</footer>

</body>
</html>
"""

    return html


def main():
    print("Starting ASPICE report generation...")

    report = build_report()

    json_file = OUTPUT_DIR / "aspice-report.json"
    html_file = OUTPUT_DIR / "aspice-report.html"

    json_file.write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    html_file.write_text(
        generate_html(report),
        encoding="utf-8"
    )

    print("ASPICE report generation completed.")
    print(f"HTML report: {html_file}")
    print(f"JSON report: {json_file}")

    print("\n=== Summary ===")
    print(f"Total tests: {report['junit']['tests']}")
    print(f"Passed: {report['junit']['passed']}")
    print(f"Failures: {report['junit']['failures']}")
    print(
        f"JaCoCo line coverage: "
        f"{report['jacoco']['line_coverage']:.2f}%"
    )
    print(
        f"Trivy filesystem findings: "
        f"{report['trivy']['filesystem']['total']}"
    )
    print(
        f"Trivy image findings: "
        f"{report['trivy']['image']['total']}"
    )
    print(
        f"Sonar quality gate: "
        f"{report['sonar']['quality_gate']}"
    )


if __name__ == "__main__":
    main()
