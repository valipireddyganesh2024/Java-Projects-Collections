import json
from pathlib import Path

# Load Semgrep JSON result
with open("semgrep_report/semgrep.json", "r") as f:
    data = json.load(f)

output_file = "semgrep_report/semgrep-report.html"
Path("semgrep_report").mkdir(parents=True, exist_ok=True)

# Counters for severity
high_count = 0
medium_count = 0
low_count = 0

with open(output_file, "w") as html:
    html.write("<html><head><title>🔍 Semgrep Security Report</title></head><body>")
    html.write("<h1>🔍 Semgrep Security Report</h1>")

    findings = data.get("results", [])
    html.write(f"<h2>Total Findings: {len(findings)}</h2>")

    # Count severities
    for result in findings:
        severity = result.get("extra", {}).get("severity", "").upper()
        if severity == "ERROR":
            high_count += 1
        elif severity == "WARNING":
            medium_count += 1
        else:
            low_count += 1

    # Summary table
    html.write("<h3>Severity Summary</h3>")
    html.write("<table border='1' style='border-collapse: collapse;'>")
    html.write("<tr><th>Severity</th><th>Count</th><th>Visual</th></tr>")
    html.write(f"<tr><td style='color:red;'>High</td><td>{high_count}</td><td>🔴</td></tr>")
    html.write(f"<tr><td style='color:orange;'>Medium</td><td>{medium_count}</td><td>🟠</td></tr>")
    html.write(f"<tr><td style='color:green;'>Low</td><td>{low_count}</td><td>🟢</td></tr>")
    html.write("</table><hr>")

    for result in findings:
        check_id = result.get("check_id", "N/A")
        message = result.get("extra", {}).get("message", "No message")
        severity = result.get("extra", {}).get("severity", "").upper()
        path = result.get("path", "N/A")
        line = result.get("start", {}).get("line", "N/A")
        recommendation = result.get("extra", {}).get("metadata", {}).get("cwe", "N/A")

        # Color & Emoji
        if severity == "ERROR":
            color = "red"
            emoji = "🔴"
        elif severity == "WARNING":
            color = "orange"
            emoji = "🟠"
        else:
            color = "green"
            emoji = "🟢"

        html.write("<div style='margin-bottom:20px;'>")
        html.write(f"<p><strong>[{emoji}] <span style='color:{color};'>{severity}</span></strong></p>")
        html.write(f"<code>{check_id} - {path}:{line}</code><br>")
        html.write(f"<p><strong>Message:</strong> {message}</p>")
        html.write(f"<p><strong>File:</strong> {path}</p>")
        html.write(f"<p><strong>Line:</strong> {line}</p>")
        if recommendation != "N/A":
            html.write(f"<p><strong>Recommendation (CWE):</strong> {recommendation}</p>")
        html.write("</div><hr>")

    html.write("</body></html>")
