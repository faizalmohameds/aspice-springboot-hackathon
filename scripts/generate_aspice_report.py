
#!/usr/bin/env python3

import os
import json
import html
import sys
import xml.etree.ElementTree as ET

from pathlib import Path
from datetime import datetime, timezone
from collections import Counter


ROOT = Path.cwd()
EVIDENCE = ROOT / "evidence"
OUTPUT = ROOT / "aspice-report"


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def esc(value):
    return html.escape(str(value if value is not None else ""))


def env(name):
    return os.getenv(name, "Not available")


def relative(path):
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def find_files(base, pattern):
    if not base.exists():
        return []
    return sorted(base.rglob(pattern))


def parse_pipeline():

    repository = env("GITHUB_REPOSITORY")
    sha = env("GITHUB_SHA")
    run_id = env("GITHUB_RUN_ID")

    server = os.getenv(
        "GITHUB_SERVER_URL",
        "https://github.com"
    ).rstrip("/")

    return {
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "repository": repository,
        "workflow": env("GITHUB_WORKFLOW"),
        "branch": env("GITHUB_REF_NAME"),
        "commit": sha,
        "run_id": run_id,
        "actor": env("GITHUB_ACTOR"),
        "event": env("GITHUB_EVENT_NAME"),

        "run_url": (
            f"{server}/{repository}/actions/runs/{run_id}"
            if repository != "Not available"
            and run_id != "Not available"
            else None
        ),

        "commit_url": (
            f"{server}/{repository}/commit/{sha}"
            if repository != "Not available"
            and sha != "Not available"
            else None
        ),

        "jobs": {
            "Requirement Traceability": env("REQUIREMENT_TRACE_RESULT"),
            "Maven Build": env("BUILD_RESULT"),
            "Unit Test": env("TEST_RESULT"),
            "SonarCloud": env("SONAR_RESULT"),
            "Software Bill of Materials": env("SBOM_RESULT"),
            "Trivy Filesystem": env("TRIVY_FS_RESULT"),
            "Docker Build": env("DOCKER_BUILD_RESULT"),
            "Trivy Image": env("TRIVY_IMAGE_RESULT"),
            "Docker Push": env("DOCKER_PUSH_RESULT")
        },

        "requirements": {
            "traceability_status": env("REQUIREMENT_TRACE_RESULT"),
            "ids": [
                item.strip()
                for item in os.getenv("REQUIREMENT_IDS", "").split(",")
                if item.strip()
            ],
            "check_description": (
                "For pull requests, confirms at least one REQ-<AREA>-<NUMBER> "
                "identifier appears in the title or description and that each "
                "identifier has a non-empty docs/requirements/<ID>.md record."
            )
        }
    }


def parse_junit():

    cases = []
    totals = Counter()
    duration = 0.0

    files = [
        p for p in find_files(
            EVIDENCE / "tests",
            "*.xml"
        )
        if p.name.startswith("TEST-")
        or "junit" in p.name.lower()
    ]

    for file in files:

        try:
            root = ET.parse(file).getroot()
        except (ET.ParseError, OSError):
            continue

        for case in root.iter("testcase"):

            failure = case.find("failure")
            error = case.find("error")
            skipped = case.find("skipped")

            problem = failure if failure is not None else error

            if problem is not None:
                status = "FAILED"
                message = (
                    problem.attrib.get("message")
                    or (problem.text or "").strip()
                )
            elif skipped is not None:
                status = "SKIPPED"
                message = ""
            else:
                status = "PASSED"
                message = ""

            try:
                seconds = float(case.attrib.get("time", 0))
            except (ValueError, TypeError):
                seconds = 0.0

            duration += seconds
            totals[status] += 1

            cases.append({
                "class": case.attrib.get("classname", ""),
                "name": case.attrib.get("name", ""),
                "status": status,
                "duration": round(seconds, 3),
                "message": message,
                "file": relative(file)
            })

    total = len(cases)
    passed = totals["PASSED"]

    return {
        "available": bool(files),
        "total": total,
        "passed": passed,
        "failed": totals["FAILED"],
        "skipped": totals["SKIPPED"],
        "pass_rate": (
            round(passed / total * 100, 2)
            if total else None
        ),
        "duration_seconds": round(duration, 3),
        "cases": cases
    }


def jacoco_counter(element, kind):

    for counter in element.findall("counter"):

        if counter.attrib.get("type") == kind:

            covered = int(counter.attrib.get("covered", 0))
            missed = int(counter.attrib.get("missed", 0))
            total = covered + missed

            return {
                "covered": covered,
                "missed": missed,
                "total": total,
                "percentage": (
                    round(covered / total * 100, 2)
                    if total else None
                )
            }

    return {
        "covered": 0,
        "missed": 0,
        "total": 0,
        "percentage": None
    }


def parse_jacoco():

    files = find_files(
        EVIDENCE / "tests",
        "jacoco.xml"
    )

    if not files:
        return {"available": False}

    try:
        root = ET.parse(files[0]).getroot()
    except (ET.ParseError, OSError):
        return {"available": False}

    metrics = {}

    for kind in (
        "INSTRUCTION",
        "BRANCH",
        "LINE",
        "COMPLEXITY",
        "METHOD",
        "CLASS"
    ):
        metrics[kind.lower()] = jacoco_counter(
            root,
            kind
        )

    classes = []
    packages = []

    for package in root.findall("package"):

        package_name = package.attrib.get(
            "name", ""
        ).replace("/", ".")

        packages.append({
            "name": package_name,
            "line": jacoco_counter(package, "LINE")
        })

        for cls in package.findall("class"):

            classes.append({
                "name": cls.attrib.get(
                    "name", ""
                ).replace("/", "."),
                "line": jacoco_counter(cls, "LINE")
            })

    classes.sort(
        key=lambda x: (
            x["line"]["percentage"] is None,
            x["line"]["percentage"]
            if x["line"]["percentage"] is not None
            else 101
        )
    )

    packages.sort(
        key=lambda x: (
            x["line"]["percentage"] is None,
            x["line"]["percentage"]
            if x["line"]["percentage"] is not None
            else 101
        )
    )

    return {
        "available": True,
        "source": relative(files[0]),
        "metrics": metrics,
        "classes": classes[:20],
        "packages": packages
    }


def parse_sonar():

    base = EVIDENCE / "sonar"

    measures_data = read_json(
        base / "sonar-measures.json"
    )

    gate_data = read_json(
        base / "sonar-quality-gate.json"
    )

    issues_data = read_json(
        base / "sonar-issues.json"
    )

    measures = {}

    component = measures_data.get("component", {})

    for item in component.get("measures", []):

        measures[item["metric"]] = item.get(
            "value",
            "Not available"
        )

    gate = gate_data.get("projectStatus", {})

    issues = []

    for issue in issues_data.get("issues", []):

        component_key = issue.get("component", "")
        text_range = issue.get("textRange") or {}

        issues.append({
            "severity": issue.get("severity", "UNKNOWN"),
            "type": issue.get("type", ""),
            "rule": issue.get("rule", ""),
            "file": component_key.split(":")[-1],
            "line": text_range.get("startLine"),
            "message": issue.get("message", "")
        })

    return {
        "available": bool(
            measures_data or gate_data or issues_data
        ),
        "measures": measures,
        "quality_gate": {
            "status": gate.get(
                "status",
                "Not available"
            ),
            "conditions": gate.get("conditions", [])
        },
        "issues": issues,
        "issue_count": len(issues),
        "issue_total": issues_data.get(
            "total",
            len(issues)
        ),
        "project_url": (
            "https://sonarcloud.io/project/overview?id="
            + os.getenv("SONAR_PROJECT_KEY", "")
            if os.getenv("SONAR_PROJECT_KEY")
            else None
        )
    }


def parse_sbom():

    files = find_files(EVIDENCE / "sbom", "*.json")

    if not files:
        return {"available": False, "component_count": 0, "components": []}

    data = read_json(files[0])

    if not data:
        return {"available": False, "component_count": 0, "components": []}

    metadata = data.get("metadata") or {}
    product = metadata.get("component") or {}
    components = data.get("components") or []

    parsed_components = []

    for component in components[:100]:
        licenses = []

        for entry in component.get("licenses") or []:
            license_data = entry.get("license") or {}
            license_name = (
                license_data.get("name")
                or license_data.get("id")
                or entry.get("expression")
            )
            if license_name:
                licenses.append(license_name)

        parsed_components.append({
            "name": component.get("name", ""),
            "version": component.get("version", ""),
            "type": component.get("type", ""),
            "purl": component.get("purl", ""),
            "licenses": ", ".join(licenses)
        })

    return {
        "available": True,
        "source": relative(files[0]),
        "format": data.get("bomFormat", "Not available"),
        "spec_version": data.get("specVersion", "Not available"),
        "serial_number": data.get("serialNumber", "Not available"),
        "bom_version": data.get("version", "Not available"),
        "generated_at": metadata.get("timestamp", "Not available"),
        "root_component": product.get("name", "Not available"),
        "root_version": product.get("version", "Not available"),
        "component_count": len(components),
        "components": parsed_components,
        "display_limit": min(len(components), 100)
    }


def parse_trivy_file(path, scan_type):

    data = read_json(path)

    findings = []
    severities = Counter()
    categories = Counter()

    for result in data.get("Results", []):

        target = result.get("Target", "")
        result_type = result.get("Type", "")

        for item in result.get("Vulnerabilities", []):

            severity = item.get(
                "Severity",
                "UNKNOWN"
            ).upper()

            severities[severity] += 1
            categories["vulnerability"] += 1

            findings.append({
                "category": "Vulnerability",
                "severity": severity,
                "id": item.get("VulnerabilityID", ""),
                "package": item.get("PkgName", ""),
                "installed": item.get("InstalledVersion", ""),
                "fixed": item.get("FixedVersion", ""),
                "title": item.get("Title", ""),
                "description": item.get("Description", ""),
                "target": target,
                "type": result_type,
                "url": item.get("PrimaryURL", "")
            })

        for item in result.get("Misconfigurations", []):

            severity = item.get(
                "Severity",
                "UNKNOWN"
            ).upper()

            severities[severity] += 1
            categories["misconfiguration"] += 1

            findings.append({
                "category": "Misconfiguration",
                "severity": severity,
                "id": item.get("ID", ""),
                "package": "",
                "installed": "",
                "fixed": "",
                "title": item.get("Title", ""),
                "description": item.get("Message", ""),
                "target": target,
                "type": result_type,
                "url": item.get("PrimaryURL", "")
            })

        for item in result.get("Secrets", []):

            severity = item.get(
                "Severity",
                "UNKNOWN"
            ).upper()

            severities[severity] += 1
            categories["secret"] += 1

            findings.append({
                "category": "Secret",
                "severity": severity,
                "id": item.get("RuleID", ""),
                "package": "",
                "installed": "",
                "fixed": "",
                "title": item.get("Title", ""),
                "description": item.get("Match", ""),
                "target": target,
                "type": result_type,
                "url": ""
            })

    return {
        "available": bool(data),
        "scan_type": scan_type,
        "source": relative(path),
        "findings": findings,
        "total": len(findings),
        "severities": dict(severities),
        "categories": dict(categories),
        "scan_scope": (
            "Workflow filters HIGH and CRITICAL severities "
            "and ignores unfixed vulnerabilities."
        )
    }


def parse_trivy():

    files = find_files(
        EVIDENCE / "trivy",
        "*.json"
    )

    fs_file = next(
        (
            p for p in files
            if "trivy-fs" in p.name.lower()
            or "filesystem" in str(p).lower()
        ),
        None
    )

    image_file = next(
        (
            p for p in files
            if "trivy-image" in p.name.lower()
            or "aspice-trivy-image" in str(p).lower()
        ),
        None
    )

    return {
        "filesystem": (
            parse_trivy_file(fs_file, "filesystem")
            if fs_file else {"available": False}
        ),
        "image": (
            parse_trivy_file(image_file, "image")
            if image_file else {"available": False}
        )
    }


def build_data():

    return {
        "pipeline": parse_pipeline(),
        "tests": parse_junit(),
        "jacoco": parse_jacoco(),
        "sonar": parse_sonar(),
        "sbom": parse_sbom(),
        "trivy": parse_trivy(),

        "docker": {
            "image": env("DOCKER_IMAGE"),
            "tag": env("DOCKER_TAG"),
            "digest": env("DOCKER_DIGEST"),
            "base_image": env("DOCKER_BASE_IMAGE")
        },

        "evidence_files": [
            relative(p)
            for p in find_files(EVIDENCE, "*")
            if p.is_file()
        ]
    }


def status_class(value):

    value = str(value).lower()

    if value in ("success", "passed", "ok"):
        return "good"

    if value in ("failure", "failed", "error"):
        return "bad"

    if value in ("skipped", "cancelled"):
        return "warn"

    return "neutral"


def render_findings(findings):

    if not findings:
        return (
            "<p class='muted'>No findings returned, "
            "or scan evidence is unavailable.</p>"
        )

    rows = []

    for item in findings:

        rows.append(
            "<tr>"
            f"<td>{esc(item['severity'])}</td>"
            f"<td>{esc(item['category'])}</td>"
            f"<td>{esc(item['id'])}</td>"
            f"<td>{esc(item['package'] or item['title'])}</td>"
            f"<td>{esc(item['installed'])}</td>"
            f"<td>{esc(item['fixed'])}</td>"
            f"<td>{esc(item['target'])}</td>"
            "</tr>"
        )

    return (
        "<div class='table-wrap'><table>"
        "<thead><tr>"
        "<th>Severity</th><th>Category</th><th>ID</th>"
        "<th>Package / title</th><th>Installed</th>"
        "<th>Fixed</th><th>Target</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def render_html(data):

    pipeline = data["pipeline"]
    tests = data["tests"]
    jacoco = data["jacoco"]
    sonar = data["sonar"]
    sbom = data["sbom"]
    trivy = data["trivy"]
    docker = data["docker"]

    job_rows = "".join(
        "<tr>"
        f"<td>{esc(name)}</td>"
        f"<td><span class='pill {status_class(result)}'>"
        f"{esc(result)}</span></td>"
        "</tr>"
        for name, result in pipeline["jobs"].items()
    )

    test_rows = "".join(
        "<tr>"
        f"<td>{esc(case['class'])}</td>"
        f"<td>{esc(case['name'])}</td>"
        f"<td>{esc(case['status'])}</td>"
        f"<td>{esc(case['duration'])}</td>"
        f"<td>{esc(case['message'])}</td>"
        "</tr>"
        for case in tests["cases"]
    )

    coverage_cards = ""

    for name, metric in jacoco.get("metrics", {}).items():

        percentage = metric["percentage"]

        value = (
            f"{percentage}%"
            if percentage is not None
            else "Not available"
        )

        coverage_cards += (
            "<div class='metric'>"
            f"<span>{esc(name.title())} coverage</span>"
            f"<strong>{esc(value)}</strong>"
            f"<small>{metric['covered']} / {metric['total']}</small>"
            "</div>"
        )

    sonar_cards = ""

    sonar_labels = {
        "coverage": ("Coverage", "%"),
        "bugs": ("Bugs", ""),
        "vulnerabilities": ("Vulnerabilities", ""),
        "code_smells": ("Code smells", ""),
        "security_hotspots": ("Security hotspots", ""),
        "duplicated_lines_density": ("Duplicated lines", "%"),
        "sqale_index": ("Technical debt (minutes)", ""),
        "ncloc": ("Lines of code", ""),
        "reliability_rating": ("Reliability rating", ""),
        "security_rating": ("Security rating", ""),
        "sqale_rating": ("Maintainability rating", "")
    }

    for key, (label, suffix) in sonar_labels.items():

        value = sonar["measures"].get(
            key,
            "Not available"
        )

        sonar_cards += (
            "<div class='metric'>"
            f"<span>{esc(label)}</span>"
            f"<strong>{esc(str(value) + suffix if value != 'Not available' else value)}</strong>"
            "</div>"
        )

    issue_rows = "".join(
        "<tr>"
        f"<td>{esc(issue['severity'])}</td>"
        f"<td>{esc(issue['type'])}</td>"
        f"<td>{esc(issue['rule'])}</td>"
        f"<td>{esc(issue['file'])}</td>"
        f"<td>{esc(issue['line'])}</td>"
        f"<td>{esc(issue['message'])}</td>"
        "</tr>"
        for issue in sonar["issues"]
    )

    sbom_rows = "".join(
        "<tr>"
        f"<td>{esc(component['name'])}</td>"
        f"<td>{esc(component['version'])}</td>"
        f"<td>{esc(component['type'])}</td>"
        f"<td>{esc(component['licenses'])}</td>"
        f"<td>{esc(component['purl'])}</td>"
        "</tr>"
        for component in sbom.get("components", [])
    )

    sbom_table = (
        "<div class='table-wrap'><table><thead><tr>"
        "<th>Component</th><th>Version</th><th>Type</th>"
        "<th>License</th><th>Package URL</th>"
        "</tr></thead><tbody>"
        + sbom_rows
        + "</tbody></table></div>"
        if sbom_rows
        else "<p class='muted'>SBOM contains no component entries.</p>"
    )

    if sbom.get("available"):
        sbom_summary = (
            "<div class='meta'>"
            f"<div><b>Format:</b> {esc(sbom.get('format', 'Not available'))}</div>"
            f"<div><b>Spec version:</b> {esc(sbom.get('spec_version', 'Not available'))}</div>"
            f"<div><b>Root component:</b> {esc(sbom.get('root_component', 'Not available'))}</div>"
            f"<div><b>Root version:</b> {esc(sbom.get('root_version', 'Not available'))}</div>"
            f"<div><b>Components:</b> {esc(sbom.get('component_count', 0))}</div>"
            f"<div><b>Generated:</b> {esc(sbom.get('generated_at', 'Not available'))}</div>"
            f"<div><b>Evidence file:</b> {esc(sbom.get('source', 'Unavailable'))}</div>"
            "</div>"
        )

        if sbom.get("component_count", 0) > 100:
            sbom_summary += (
                "<p class='muted'>Showing the first 100 components; "
                "the complete CycloneDX file is included in the report artifact.</p>"
            )

        sbom_summary += sbom_table
    else:
        sbom_summary = (
            "<p class='muted'>SBOM artifact is unavailable for this run.</p>"
        )

    fs = trivy["filesystem"]
    image = trivy["image"]

    fs_severity = fs.get("severities", {})
    image_severity = image.get("severities", {})

    def severity_summary(counts):

        return " | ".join(
            f"{level}: {counts.get(level, 0)}"
            for level in (
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNKNOWN"
            )
        )

    class_rows = ""

    for item in jacoco.get("classes", []):

        percentage = item["line"]["percentage"]

        class_rows += (
            "<tr>"
            f"<td>{esc(item['name'])}</td>"
            f"<td>{esc(str(percentage) + '%' if percentage is not None else 'N/A')}</td>"
            f"<td>{item['line']['covered']}</td>"
            f"<td>{item['line']['missed']}</td>"
            "</tr>"
        )

    package_rows = ""

    for item in jacoco.get("packages", []):

        percentage = item["line"]["percentage"]

        package_rows += (
            "<tr>"
            f"<td>{esc(item['name'])}</td>"
            f"<td>{esc(str(percentage) + '%' if percentage is not None else 'N/A')}</td>"
            f"<td>{item['line']['covered']}</td>"
            f"<td>{item['line']['missed']}</td>"
            "</tr>"
        )

    evidence_rows = "".join(
        f"<li>{esc(item)}</li>"
        for item in data["evidence_files"]
    ) or "<li>No evidence files downloaded</li>"

    run_link = (
        f"<a href='{esc(pipeline['run_url'])}'>GitHub Actions run</a>"
        if pipeline.get("run_url")
        else "Not available"
    )

    commit_link = (
        f"<a href='{esc(pipeline['commit_url'])}'>"
        f"{esc(pipeline['commit'])}</a>"
        if pipeline.get("commit_url")
        else esc(pipeline["commit"])
    )

    sonar_link = (
        f"<a href='{esc(sonar['project_url'])}'>"
        "Open SonarCloud project</a>"
        if sonar.get("project_url")
        else "Not available"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ASPICE CI Evidence Report</title>
<style>
body {{
    margin: 0;
    background: #f4f6fa;
    color: #172033;
    font-family: Arial, sans-serif;
    font-size: 14px;
    line-height: 1.5;
}}
header {{
    background: #172b4d;
    color: white;
    padding: 28px 5%;
}}
header h1 {{ margin: 0 0 5px; }}
main {{ max-width: 1400px; margin: 24px auto; padding: 0 20px; }}
section {{
    background: white;
    border: 1px solid #dbe2ea;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 18px;
}}
h2 {{ font-size: 19px; margin-top: 0; }}
h3 {{ font-size: 15px; margin-top: 20px; }}
.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(155px, 1fr));
    gap: 12px;
}}
.metric {{
    border: 1px solid #dbe2ea;
    border-radius: 8px;
    padding: 13px;
}}
.metric span, .metric small {{
    display: block;
    color: #64748b;
}}
.metric strong {{
    display: block;
    font-size: 22px;
    margin: 5px 0;
    overflow-wrap: anywhere;
}}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{
    text-align: left;
    padding: 9px;
    border-bottom: 1px solid #dbe2ea;
    vertical-align: top;
}}
th {{ background: #f8fafc; }}
.table-wrap {{ overflow-x: auto; }}
.pill {{
    display: inline-block;
    padding: 2px 9px;
    border-radius: 20px;
    background: #e2e8f0;
}}
.good {{ background: #dcfce7; color: #166534; }}
.bad {{ background: #fee2e2; color: #991b1b; }}
.warn {{ background: #fef3c7; color: #92400e; }}
.meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 8px;
}}
.meta div {{
    background: #f8fafc;
    border-radius: 6px;
    padding: 8px;
    overflow-wrap: anywhere;
}}
.note {{
    background: #fff7ed;
    border-left: 4px solid #f59e0b;
    padding: 12px;
    margin: 12px 0;
}}
.muted {{ color: #64748b; }}
footer {{ text-align: center; padding: 20px; color: #64748b; }}
@media print {{
    body {{ background: white; }}
    section {{ break-inside: avoid; }}
}}
</style>
</head>
<body>
<header>
<h1>ASPICE CI Evidence Report</h1>
<p>Automated build, test, quality, security and container evidence</p>
</header>

<main>

<section>
<h2>Pipeline metadata</h2>
<div class="meta">
<div><b>Repository:</b> {esc(pipeline['repository'])}</div>
<div><b>Workflow:</b> {esc(pipeline['workflow'])}</div>
<div><b>Branch:</b> {esc(pipeline['branch'])}</div>
<div><b>Commit:</b> {commit_link}</div>
<div><b>Run:</b> {run_link}</div>
<div><b>Run ID:</b> {esc(pipeline['run_id'])}</div>
<div><b>Actor:</b> {esc(pipeline['actor'])}</div>
<div><b>Event:</b> {esc(pipeline['event'])}</div>
<div><b>Generated:</b> {esc(pipeline['generated_at'])}</div>
</div>
</section>

<section>
<h2>Pipeline execution status</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Stage</th><th>Result</th></tr></thead>
<tbody>{job_rows}</tbody>
</table>
</div>
</section>

<section>
<h2>Requirement traceability</h2>
<p>{esc(pipeline['requirements']['check_description'])}</p>
<p><b>Job result:</b> <span class="pill {status_class(pipeline['requirements']['traceability_status'])}">{esc(pipeline['requirements']['traceability_status'])}</span></p>
<p><b>Requirements verified:</b> {esc(', '.join(pipeline['requirements']['ids']) if pipeline['requirements']['ids'] else 'Not available (the check only runs on pull requests)')}</p>
<p class="muted">This is a lightweight ID-to-document presence check. It does not assess requirement completeness, implementation correctness, or test coverage.</p>
</section>

<section>
<h2>JUnit test evidence</h2>
<div class="grid">
<div class="metric"><span>Total</span><strong>{tests['total']}</strong></div>
<div class="metric"><span>Passed</span><strong>{tests['passed']}</strong></div>
<div class="metric"><span>Failed</span><strong>{tests['failed']}</strong></div>
<div class="metric"><span>Skipped</span><strong>{tests['skipped']}</strong></div>
<div class="metric"><span>Pass rate</span><strong>{esc(str(tests['pass_rate']) + '%' if tests['pass_rate'] is not None else 'Not available')}</strong></div>
<div class="metric"><span>Duration</span><strong>{tests['duration_seconds']} s</strong></div>
</div>
<h3>Test case details</h3>
{('<div class="table-wrap"><table><thead><tr><th>Class</th><th>Test</th><th>Status</th><th>Seconds</th><th>Failure / error</th></tr></thead><tbody>' + test_rows + '</tbody></table></div>') if test_rows else '<p class="muted">JUnit XML evidence not available.</p>'}
</section>

<section>
<h2>JaCoCo coverage</h2>
{('<div class="grid">' + coverage_cards + '</div>') if jacoco.get('available') else '<p class="muted">JaCoCo XML evidence not available.</p>'}
<h3>Lowest line-coverage classes</h3>
{('<div class="table-wrap"><table><thead><tr><th>Class</th><th>Coverage</th><th>Covered</th><th>Missed</th></tr></thead><tbody>' + class_rows + '</tbody></table></div>') if class_rows else '<p class="muted">Class coverage details not available.</p>'}
<h3>Package line coverage</h3>
{('<div class="table-wrap"><table><thead><tr><th>Package</th><th>Coverage</th><th>Covered</th><th>Missed</th></tr></thead><tbody>' + package_rows + '</tbody></table></div>') if package_rows else '<p class="muted">Package coverage details not available.</p>'}
</section>

<section>
<h2>SonarCloud quality evidence</h2>
<p><b>Quality Gate:</b>
<span class="pill {status_class(sonar['quality_gate']['status'])}">{esc(sonar['quality_gate']['status'])}</span>
&nbsp; {sonar_link}</p>
<div class="grid">{sonar_cards}</div>
<h3>Quality Gate conditions</h3>
{('<div class="table-wrap"><table><thead><tr><th>Metric</th><th>Operator</th><th>Actual</th><th>Threshold</th><th>Status</th></tr></thead><tbody>' + ''.join(f"<tr><td>{esc(c.get('metricKey'))}</td><td>{esc(c.get('comparator'))}</td><td>{esc(c.get('actualValue'))}</td><td>{esc(c.get('errorThreshold'))}</td><td>{esc(c.get('status'))}</td></tr>" for c in sonar['quality_gate'].get('conditions', [])) + '</tbody></table></div>') if sonar['quality_gate'].get('conditions') else '<p class="muted">Quality Gate conditions not available.</p>'}
<h3>Unresolved issue details</h3>
<p class="muted">Returned {sonar['issue_count']} issues; API total: {sonar['issue_total']}. The workflow request currently retrieves up to 500 issues.</p>
{('<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Type</th><th>Rule</th><th>File</th><th>Line</th><th>Message</th></tr></thead><tbody>' + issue_rows + '</tbody></table></div>') if issue_rows else '<p class="muted">No issue records returned, or issue evidence is unavailable.</p>'}
</section>

<section>
<h2>Software Bill of Materials</h2>
{sbom_summary}
<p class="note">The SBOM inventories software components and versions for review and supply-chain traceability. It is an inventory; vulnerability findings are reported separately in the Trivy section.</p>
</section>

<section>
<h2>Trivy security evidence</h2>
<div class="grid">
<div class="metric">
<span>Filesystem findings</span>
<strong>{fs.get('total', 'Not available')}</strong>
<small>{esc(severity_summary(fs_severity) if fs.get('available') else 'Report unavailable')}</small>
</div>
<div class="metric">
<span>Container image findings</span>
<strong>{image.get('total', 'Not available')}</strong>
<small>{esc(severity_summary(image_severity) if image.get('available') else 'Report unavailable')}</small>
</div>
</div>
<div class="note">
Scan scope: workflow filters HIGH and CRITICAL severities and ignores unfixed vulnerabilities. The results do not represent all severity levels or all unfixed findings.
</div>
<h3>Filesystem scan findings</h3>
{render_findings(fs.get('findings', []))}
<h3>Container image scan findings</h3>
{render_findings(image.get('findings', []))}
</section>

<section>
<h2>Docker image evidence</h2>
<div class="meta">
<div><b>Image:</b> {esc(docker['image'])}</div>
<div><b>Tag:</b> {esc(docker['tag'])}</div>
<div><b>Digest:</b> {esc(docker['digest'])}</div>
<div><b>Base image:</b> {esc(docker['base_image'])}</div>
</div>
</section>

<section>
<h2>ASPICE-oriented evidence mapping</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Evidence area</th><th>Evidence generated</th><th>Purpose</th></tr></thead>
<tbody>
<tr><td>Build verification</td><td>Maven build status and JAR artifact</td><td>Evidence of application build</td></tr>
<tr><td>Software verification</td><td>JUnit reports and test outcomes</td><td>Evidence of automated test execution</td></tr>
<tr><td>Structural coverage</td><td>JaCoCo counters and coverage</td><td>Evidence of measured code coverage</td></tr>
<tr><td>Static analysis</td><td>SonarCloud measures and Quality Gate</td><td>Evidence of code quality analysis</td></tr>
<tr><td>Security analysis</td><td>Trivy filesystem and image findings</td><td>Evidence of configured security scans</td></tr>
<tr><td>Software component inventory</td><td>CycloneDX SBOM with component names and versions</td><td>Identifies third-party and software components included in the build</td></tr>
<tr><td>Deployment package</td><td>Docker image tag and digest</td><td>Identifies the produced container image</td></tr>
<tr><td>Requirement traceability</td><td>Pull request check result and verified requirement IDs</td><td>Links the change to a registered requirement record</td></tr>
<tr><td>CI execution traceability</td><td>Repository, commit and workflow run</td><td>Links evidence to source revision and CI execution</td></tr>
</tbody>
</table>
</div>
<p class="muted">This is an engineering evidence summary aligned to selected ASPICE-related activities. It is not an ASPICE compliance certificate or assessment result.</p>
</section>

<section>
<h2>Collected evidence files</h2>
<ul>{''.join(f'<li>{esc(item)}</li>' for item in data['evidence_files']) or '<li>No evidence files downloaded</li>'}</ul>
</section>

</main>
<footer>Generated by scripts/generate_aspice_report.py</footer>
</body>
</html>"""


def main():

    OUTPUT.mkdir(
        parents=True,
        exist_ok=True
    )

    data = build_data()

    json_file = OUTPUT / "aspice-report.json"
    html_file = OUTPUT / "aspice-report.html"

    json_file.write_text(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    html_file.write_text(
        render_html(data),
        encoding="utf-8"
    )

    print(f"Generated: {relative(html_file)}")
    print(f"Generated: {relative(json_file)}")

    print(
        "JUnit tests:",
        data["tests"]["total"]
    )

    print(
        "Sonar issues:",
        data["sonar"]["issue_count"]
    )

    print(
        "Trivy filesystem findings:",
        data["trivy"]["filesystem"].get("total", "N/A")
    )

    print(
        "Trivy image findings:",
        data["trivy"]["image"].get("total", "N/A")
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
