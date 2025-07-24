import json
import os

with open("semgrep_report/semgrep.json") as f:
    data = json.load(f)

results = data.get("results", [])
count = len(results)

html = f"""
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>Semgrep Security Report</title>
    <link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>
    <style>
        body {{ padding: 2rem; }}
        .high {{ background-color: #f8d7da; }}
        .medium {{ background-color: #fff3cd; }}
        .low {{ background-color: #d1ecf1; }}
        .info {{ background-color: #e2e3e5; }}
        .card {{ margin-bottom: 1rem; }}
        pre {{ background: #f8f9fa; padding: 0.5rem; }}
    </style>
</head>
<body>
    <h1 class='mb-4'>🔍 Semgrep Security Report</h1>
    <p><strong>Total Findings:</strong> {count}</p>
    <div class='accordion' id='resultsAccordion'>
"""

for i, result in enumerate(results):
    severity = result.get("extra", {}).get("severity", "info").lower()
    check_id = result.get("check_id", "N/A")
    message = result.get("extra", {}).get("message", "N/A")
    path = result.get("path", "N/A")
    start_line = result.get("start", {}).get("line", "N/A")

    html += f"""
    <div class='card {severity}'>
        <div class='card-header' id='heading{i}'>
            <h2 class='mb-0'>
                <button class='btn btn-link text-dark' type='button' data-bs-toggle='collapse' data-bs-target='#collapse{i}' aria-expanded='true' aria-controls='collapse{i}'>
                    [{severity.upper()}] {check_id} - {os.path.basename(path)}:{start_line}
                </button>
            </h2>
        </div>
        <div id='collapse{i}' class='collapse' aria-labelledby='heading{i}' data-bs-parent='#resultsAccordion'>
            <div class='card-body'>
                <p><strong>Message:</strong> {message}</p>
                <p><strong>File:</strong> {path}</p>
                <p><strong>Line:</strong> {start_line}</p>
            </div>
        </div>
    </div>
    """

html += """
    </div>
    <script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'></script>
</body>
</html>
"""

os.makedirs("semgrep_report", exist_ok=True)
with open("semgrep_report/semgrep-report.html", "w") as f:
    f.write(html)
