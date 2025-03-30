import sys
import urllib.parse
from vulnerabilities import xss_scanner, sql_injection_scanner, csrf_scanner, idor_scanner, open_redirect_scanner, directory_traversal_scanner, command_injection_scanner
from reporter import generate_report

def scan_url(url):
    """
    Scans the given URL for multiple vulnerabilities.
    """
    print(f"Scanning: {url}")
    results = {
        "url": url,
        "xss": xss_scanner.scan_xss(url),
        "sql_injection": sql_injection_scanner.scan_sql_injection(url),
        "csrf": csrf_scanner.scan_csrf(url),
        "idor": idor_scanner.scan_idor(url),
        "open_redirect": open_redirect_scanner.scan_open_redirect(url),
        "directory_traversal": directory_traversal_scanner.scan_directory_traversal(url),
        "command_injection": command_injection_scanner.scan_command_injection(url),
    }
    return results

def main():
    """
    Main function to run the scanner.
    """
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]

    # Validate the URL
    try:
        urllib.parse.urlparse(target_url)
    except:
        print("Invalid URL")
        sys.exit(1)

    results = scan_url(target_url)
    generate_report(results)  # Generate a report

if __name__ == "__main__":
    main()
