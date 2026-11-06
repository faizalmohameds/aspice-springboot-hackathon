from pathlib import Path
from datetime import datetime, timezone
import html
import json

EVIDENCE_DIR = Path("evidence")
OUTPUT_DIR = Path("aspice-report")


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    artifacts = []
    if EVIDENCE_DIR.exists():
        for path in sorted(EVIDENCE_DIR.rglob("*")):
            if path.is_file():
                artifacts.append({
                    "name": str(path.relative_to(EVIDENCE_DIR)),
                    "size_bytes": path.stat().st_size,
                })

    report = {
        "project": "ASPICE Spring Boot Hackathon",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_count": len(artifacts),
        "evidence": artifacts,
    }

    (OUTPUT_DIR / "aspice-report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )

    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(item['name'])}</td>"
        f"<td>{item['size_bytes']}</td>"
        "</tr>"
        for item in artifacts
    )

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ASPICE CI Evidence Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #222; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
    th {{ background: #f2f2f2; }}
    .muted {{ color: #666; }}
  </style>
</head>
<body>
  <h1>ASPICE CI Evidence Report</h1>
  <p><strong>Project:</strong> {html.escape(report["project"])}</p>
  <p><strong>Generated (UTC):</strong> {html.escape(report["generated_at"])}</p>
  <p><strong>Evidence files:</strong> {len(artifacts)}</p>
  <h2>Collected evidence</h2>
  <table>
    <thead><tr><th>Evidence file</th><th>Size (bytes)</th></tr></thead>
    <tbody>{rows if rows else '<tr><td colspan="2" class="muted">No evidence files were found.</td></tr>'}</tbody>
  </table>
  <p class="muted">This report inventories collected CI artifacts; it does not certify ASPICE process compliance.</p>
</body>
</html>
'''
    (OUTPUT_DIR / "aspice-report.html").write_text(
        html_content, encoding="utf-8"
    )

    print(f"ASPICE report generated. Evidence files: {len(artifacts)}")
    print(f"Output directory: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
