import json
import os
import datetime
import html

def generate_report(results):
    """
    Generates a comprehensive report of vulnerability scan results.

    Args:
        results (dict): Scan results from the scanner

    Returns:
        None: Outputs reports to files
    """
    # Create reports directory if it doesn't exist
    if not os.path.exists('reports'):
        os.makedirs('reports')

    # Create timestamp for unique report filenames
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    url_safe = results["url"].replace("://", "_").replace("/", "_").replace(":", "_")

    # Generate JSON report4
    json_filename = f"reports/scan_{url_safe}_{timestamp}.json"
    with open(json_filename, 'w') as json_file:
        json.dump(results, json_file, indent=4)

    # Generate HTML report
    html_filename = f"reports/scan_{url_safe}_{timestamp}.html"
    with open(html_filename, 'w') as html_file:
        html_content = generate_html_report(results)
        html_file.write(html_content)

    # Generate text report
    text_filename = f"reports/scan_{url_safe}_{timestamp}.txt"
    with open(text_filename, 'w') as text_file:
        text_content = generate_text_report(results)
        text_file.write(text_content)

    print(f"\nReports generated:")
    print(f"- JSON Report: {json_filename}")
    print(f"- HTML Report: {html_filename}")
    print(f"- Text Report: {text_filename}")

def generate_html_report(results):
    """
    Generates an HTML report from scan results.
    """
    # Get vulnerability counts
    vuln_count = sum(1 for key, value in results.items()
                     if key != "url" and isinstance(value, dict) and value.get("vulnerable", False))

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {html.escape(results["url"])}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background-color: #f4f4f4;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        h1 {{
            color: #333;
            margin-top: 0;
        }}
        h2 {{
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
            margin-top: 30px;
        }}
        .summary {{
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }}
        .summary-box {{
            background-color: #f9f9f9;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 10px;
            flex: 1;
            min-width: 200px;
            margin-right: 10px;
        }}
        .summary-box.vulnerable {{
            background-color: #ffe6e6;
            border-left: 5px solid #ff4d4d;
        }}
        .summary-box.safe {{
            background-color: #e6ffe6;
            border-left: 5px solid #4dff4d;
        }}
        .vulnerability {{
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .vulnerability.detected {{
            border-left: 5px solid #ff4d4d;
        }}
        .vulnerability.safe {{
            border-left: 5px solid #4dff4d;
        }}
        .vulnerability h3 {{
            margin-top: 0;
        }}
        pre {{
            background-color: #f4f4f4;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f4f4f4;
        }}
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #777;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Web Vulnerability Scan Report</h1>
            <p><strong>Target URL:</strong> {html.escape(results["url"])}</p>
            <p><strong>Scan Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </header>

        <section class="summary">
            <div class="summary-box {("vulnerable" if vuln_count > 0 else "safe")}">
                <h2>Summary</h2>
                <p><strong>Vulnerabilities Detected:</strong> {vuln_count}</p>
                <p><strong>Status:</strong> {("VULNERABLE" if vuln_count > 0 else "SECURE")}</p>
            </div>
        </section>

        <h2>Detailed Results</h2>
"""

    # Add vulnerability details
    vuln_types = {
        "xss": "Cross-Site Scripting (XSS)",
        "sql_injection": "SQL Injection",
        "csrf": "Cross-Site Request Forgery (CSRF)",
        "idor": "Insecure Direct Object References (IDOR)",
        "open_redirect": "Open Redirect",
        "directory_traversal": "Directory Traversal",
        "command_injection": "Command Injection"
    }

    for vuln_key, vuln_name in vuln_types.items():
        if vuln_key in results:
            vuln_data = results[vuln_key]
            is_vulnerable = vuln_data.get("vulnerable", False)

            html_content += f"""
        <div class="vulnerability {"detected" if is_vulnerable else "safe"}">
            <h3>{vuln_name}</h3>
            <p><strong>Status:</strong> {"Vulnerable" if is_vulnerable else "Not Vulnerable"}</p>
"""

            if is_vulnerable:
                # Add specific vulnerability details based on the type
                if vuln_key == "xss":
                    html_content += f"""
            <p><strong>Type:</strong> {vuln_data.get("type", "Unknown")}</p>
            <p><strong>Parameter:</strong> {vuln_data.get("parameter", "N/A")}</p>
            <p><strong>Payload:</strong> <code>{html.escape(vuln_data.get("payload", ""))}</code></p>
            <p><strong>URL:</strong> <a href="{html.escape(vuln_data.get("url", ""))}" target="_blank">{html.escape(vuln_data.get("url", ""))}</a></p>
"""
                elif vuln_key == "sql_injection":
                    html_content += f"""
            <p><strong>Type:</strong> {vuln_data.get("type", "Unknown")}</p>
            <p><strong>Parameter:</strong> {vuln_data.get("parameter", "N/A")}</p>
            <p><strong>Payload:</strong> <code>{html.escape(vuln_data.get("payload", ""))}</code></p>
            <p><strong>URL:</strong> <a href="{html.escape(vuln_data.get("url", ""))}" target="_blank">{html.escape(vuln_data.get("url", ""))}</a></p>
"""
                elif vuln_key == "csrf":
                    html_content += f"""
            <p><strong>Message:</strong> {vuln_data.get("message", "N/A")}</p>
            <p><strong>Vulnerable Forms:</strong></p>
            <ul>
"""
                    for form in vuln_data.get("vulnerable_forms", []):
                        html_content += f"""
                <li>Form #{form.get("index", "Unknown")} - Action: {html.escape(form.get("action", ""))}, Method: {form.get("method", "")}</li>
"""
                    html_content += f"""
            </ul>
"""
                elif vuln_key == "idor" or vuln_key == "open_redirect" or vuln_key == "directory_traversal" or vuln_key == "command_injection":
                    html_content += f"""
            <p><strong>Vulnerable Parameters:</strong></p>
            <ul>
"""
                    for param in vuln_data.get("vulnerable_parameters", []):
                        html_content += f"""
                <li>Parameter: {param.get("parameter", "Unknown")}, Payload: <code>{html.escape(param.get("payload", ""))}</code></li>
"""
                    html_content += f"""
            </ul>
"""

            html_content += """
        </div>
"""

    html_content += """
        <div class="footer">
            <p>Generated by Python Vulnerability Scanner</p>
        </div>
    </div>
</body>
</html>
"""

    return html_content

def generate_text_report(results):
    """
    Generates a plain text report from scan results.
    """
    # Get vulnerability counts
    vuln_count = sum(1 for key, value in results.items()
                     if key != "url" and isinstance(value, dict) and value.get("vulnerable", False))

    text_content = f"""WEB VULNERABILITY SCAN REPORT
===========================

Target URL: {results["url"]}
Scan Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

SUMMARY
-------
Vulnerabilities Detected: {vuln_count}
Status: {("VULNERABLE" if vuln_count > 0 else "SECURE")}

DETAILED RESULTS
---------------
"""

    # Add vulnerability details
    vuln_types = {
        "xss": "Cross-Site Scripting (XSS)",
        "sql_injection": "SQL Injection",
        "csrf": "Cross-Site Request Forgery (CSRF)",
        "idor": "Insecure Direct Object References (IDOR)",
        "open_redirect": "Open Redirect",
        "directory_traversal": "Directory Traversal",
        "command_injection": "Command Injection"
    }

    for vuln_key, vuln_name in vuln_types.items():
        if vuln_key in results:
            vuln_data = results[vuln_key]
            is_vulnerable = vuln_data.get("vulnerable", False)

            text_content += f"""
{vuln_name}:
  Status: {"Vulnerable" if is_vulnerable else "Not Vulnerable"}
"""

            if is_vulnerable:
                # Add specific vulnerability details based on the type
                if vuln_key == "xss":
                    text_content += f"""
  Type: {vuln_data.get("type", "Unknown")}
  Parameter: {vuln_data.get("parameter", "N/A")}
  Payload: {vuln_data.get("payload", "")}
  URL: {vuln_data.get("url", "")}
"""
                elif vuln_key == "sql_injection":
                    text_content += f"""
  Type: {vuln_data.get("type", "Unknown")}
  Parameter: {vuln_data.get("parameter", "N/A")}
  Payload: {vuln_data.get("payload", "")}
  URL: {vuln_data.get("url", "")}
"""
                elif vuln_key == "csrf":
                    text_content += f"""
  Message: {vuln_data.get("message", "N/A")}
  Vulnerable Forms:
"""
                    for form in vuln_data.get("vulnerable_forms", []):
                        text_content += f"""    - Form #{form.get("index", "Unknown")} - Action: {form.get("action", "")}, Method: {form.get("method", "")}\n"""

                elif vuln_key == "idor" or vuln_key == "open_redirect" or vuln_key == "directory_traversal" or vuln_key == "command_injection":
                    text_content += f"""
  Vulnerable Parameters:
"""
                    for param in vuln_data.get("vulnerable_parameters", []):
                        text_content += f"""    - Parameter: {param.get("parameter", "Unknown")}, Payload: {param.get("payload", "")}\n"""

    text_content += """
RECOMMENDATIONS
--------------
If vulnerabilities were detected, please consider the following recommendations:

1. XSS: Implement proper input validation and output encoding.
2. SQL Injection: Use parameterized queries or prepared statements.
3. CSRF: Implement anti-CSRF tokens in all forms.
4. IDOR: Implement proper access controls and use indirect references.
5. Open Redirect: Validate and sanitize all redirect URLs.
6. Directory Traversal: Use file inclusion functions securely, validate paths.
7. Command Injection: Avoid using shell commands with user input. If necessary, use strict input validation.

For more detailed remediation advice, consult with a security professional.

Generated by Python Vulnerability Scanner
"""

    return text_content

if __name__ == '__main__':
    # Test with dummy data
    test_results = {
        "url": "http://example.com",
        "xss": {"vulnerable": True, "type": "Reflected XSS", "parameter": "search", "payload": "<script>alert('XSS')</script>", "url": "http://example.com/?search=<script>alert('XSS')</script>"},
        "sql_injection": {"vulnerable": False},
        "csrf": {"vulnerable": False},
        "idor": {"vulnerable": False},
        "open_redirect": {"vulnerable": False},
        "directory_traversal": {"vulnerable": False},
        "command_injection": {"vulnerable": False}
    }

    generate_report(test_results)
