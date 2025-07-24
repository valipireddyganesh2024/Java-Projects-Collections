import json
import os
from datetime import datetime

INPUT_JSON = 'semgrep_report/semgrep.json'
OUTPUT_HTML = 'semgrep_report/semgrep-report.html'

SEVERITY_MAPPING = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low"
}

def load_findings():
    if not os.path.exists(INPUT_JSON):
        print(f"[!] Input file not found: {INPUT_JSON}")
        return []
    with open(INPUT_JSON, 'r') as f:
        data = json.load(f)
        return data.get("results", [])

def generate_html(findings):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    counts = {"High": 0, "Medium": 0, "Low": 0}
    rows = ""

    for finding in findings:
        rule_id = finding.get("check_id", "")
        path = finding.get("path", "")
        start_line = finding.get("start", {}).get("line", "?")
        message = finding.get("extra", {}).get("message", "")
        severity_raw = finding.get("extra", {}).get("severity", "INFO")
        severity = SEVERITY_MAPPING.get(severity_raw, "Low")

        counts[severity] += 1

        rows += f"""
        <tr>
            <td>{severity}</td>
            <td>{path}:{start_line}</td>
            <td>{rule_id}</td>
            <td>{message}</td>
        </tr>
        """

    summary = f"""
    <h2>Semgrep Report Summary</h2>
    <ul>
        <li><strong>High:</strong> {counts['High']}</li>
        <li><strong>Medium:</strong> {counts['Medium']}</li>
        <li><strong>Low:</strong> {counts['Low']}</li>
        <li><strong>Total Findings:</strong> {len(findings)}</li>
        <li><strong>Generated On:</strong> {now}</li>
    </ul>
    """

    html = f"""
    <html>
    <head>
        <title>Semgrep Security Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f9f9f9; color: #333; padding: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; }}
            th {{ background-color: #f2f2f2; }}
            tr:hover {{ background-color: #f1f1f1; }}
            .High {{ background-color: #f8d7da; }}
            .Medium {{ background-color: #fff3cd; }}
            .Low {{ background-color: #d1ecf1; }}
        </style>
    </head>
    <body>
        <h1>🔍 Semgrep Scan Results</h1>
        {summary}
        <h2>Detailed Findings</h2>
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
