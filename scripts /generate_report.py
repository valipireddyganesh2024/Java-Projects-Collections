import json
import os
from datetime import datetime

INPUT_JSON = 'semgrep_report/semgrep.json'
OUTPUT_HTML = 'semgrep_report/semgrep-report.html'

SEVERITY_MAP = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low"
}

COLOR_MAP = {
    "High": "#f8d7da",   # Red background
    "Medium": "#fff3cd", # Orange background
    "Low": "#d1ecf1"     # Blue background
}

EMOJI_MAP = {
    "High": "🔴",
    "Medium": "🟠",
    "Low": "🔵"
}

def load_findings():
    if not os.path.exists(INPUT_JSON):
        print(f"[!] File not found: {INPUT_JSON}")
        return []
    with open(INPUT_JSON, 'r') as f:
        data = json.load(f)
        return data.get("results", [])

def generate_html(findings):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    counts = {"High": 0, "Medium": 0, "Low": 0}
    rows = ""

    for finding in findings:
        severity_raw = finding.get("extra", {}).get("severity", "INFO")
        severity = SEVERITY_MAP.get(severity_raw, "Low")
        counts[severity] += 1

        color = COLOR_MAP.get(severity, "#ffffff")
        emoji = EMOJI_MAP.get(severity, "")
        rule_id = finding.get("check_id", "")
        message = finding.get("extra", {}).get("message", "")
        file_path = finding.get("path", "")
        line_number = finding.get("start", {}).get("line", "?")

        rows += f"""
        <tr style="background-color: {color};">
            <td><strong>{emoji} {severity}</strong></td>
            <td>{file_path}:{line_number}</td>
            <td>{rule_id}</td>
            <td>{message}</td>
        </tr>
        """

    summary = f"""
    <h2>Summary by Severity</h2>
    <table style="width: 50%; border-collapse: collapse; margin-bottom: 20px;">
        <tr>
            <th style="background-color:#eee; padding: 8px; border: 1px solid #ccc;">Severity</th>
            <th style="background-color:#eee; padding: 8px; border: 1px solid #ccc;">Count</th>
            <th style="background-color:#eee; padding: 8px; border: 1px solid #ccc;">Visual</th>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ccc;">High</td>
            <td style="padding: 8px; border: 1px solid #ccc;">{counts['High']}</td>
            <td style="padding: 8px; border: 1px solid #ccc;">🔴</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ccc;">Medium</td>
            <td style="padding: 8px; border: 1px solid #ccc;">{counts['Medium']}</td>
            <td style="padding: 8px; border: 1px solid #ccc;">🟠</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ccc;">Low</td>
            <td style="padding: 8px; border: 1px solid #ccc;">{counts['Low']}</td>
            <td style="padding: 8px; border: 1px solid #ccc;">🔵</td>
        </tr>
    </table>
    <p><strong>Total Findings:</strong> {len(findings)}</p>
    <p><strong>Generated On:</strong> {now}</p>
    """

    html = f"""
    <html>
    <head>
        <title>Semgrep Security Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                padding: 20px;
                background-color: #f9f9f9;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                border: 1px solid #ccc;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
        </style>
    </head>
    <body>
        <h1>🔍 Semgrep Security Report</h1>
        {summary}
        <table>
            <tr>
                <th>Severity</th>
                <th>Location</th>
                <th>Rule ID</th>
                <th>Recommendation</th>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """
    return html

def save_report(html):
    os.makedirs(os.path.dirname(OUTPUT_HTML), exist_ok=True)
    with open(OUTPUT_HTML, 'w') as f:
        f.write(html)
    print(f"[+] Report generated: {OUTPUT_HTML}")

def main():
    findings = load_findings()
    if findings:
        html = generate_html(findings)
        save_report(html)
    else:
        print("[!] No findings to report.")

if __name__ == "__main__":
    main()
