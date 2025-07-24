import json
from pathlib import Path

# Load Semgrep JSON result
with open("semgrep_report/semgrep.json", "r") as f:
    data = json.load(f)

output_file = "semgrep_report/semgrep-report.html"
Path("semgrep_report").mkdir(parents=True, exist_ok=True)

# Severity mapping (customize if needed)
SEVERITY_MAP = {
    "CRITICAL": ("darkred", "🔥"),
    "HIGH": ("red", "🔴"),
    "MEDIUM": ("orange", "🟠"),
    "LOW": ("green", "🟢"),
    "INFO": ("blue", "ℹ️"),
    "WARNING": ("orange", "🟠"),  # fallback
    "ERROR": ("red", "🔴"),       # fallback
}

# Initialize counters
severity_counts = {key: 0 for key in SEVERITY_MAP.keys()}

with open(output_file, "w") as html:
    html.write("<html><head><title>🔍 Semgrep Security Report</title></head><body>")
    html.write("<h1>🔍 Semgrep Security Report</h1>")

    findings = data.get("results", [])
    html.write(f"<h2>Total Findings: {len(findings)}</h2>")

    # Count severities
    for result in findings:
        raw_sev = result.get("extra", {}).get("severity", "").upper()
        severity = raw_sev if raw_sev in SEVERITY_MAP else "INFO"
        severity_counts[severity] += 1

    # Summary table
    html.write("<h3>Severity Summary</h3>")
    html.write("<table border='1' style='border-collapse: collapse;'>")
    html.write("<tr><th>Severity</th><th>Count</th><th>Visual</th></tr>")
    for sev, count in severity_counts.items():
        color, emoji = SEVERITY_MAP[sev]
        html.write(f"<tr><td style='color:{color};'>{sev}</td><td>{count}</td><td>{emoji}</td></tr>")
    html.write("</table><hr>")

    # Detailed findings
    for result in findings:
        check_id = result.get("check_id", "N/A")
        message = result.get("extra", {}).get("message", "No message")
        raw_severity = result.get("extra", {}).get("severity", "").upper()
        severity = raw_severity if raw_severity in SEVERITY_MAP else "INFO"
        color, emoji = SEVERITY_MAP[severity]

        path = result.get("path", "N/A")
        line = result.get("start", {}).get("line", "N/A")
        recommendation = result.get("extra", {}).get("metadata", {}).get("cwe", "N/A")

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
