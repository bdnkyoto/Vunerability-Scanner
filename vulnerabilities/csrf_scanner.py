import requests
from bs4 import BeautifulSoup
import re

def scan_csrf(url):
    """
    Scans a web application for CSRF vulnerabilities.
    Basic detection focuses on forms lacking anti-CSRF tokens.
    """
    try:
        # Get the page content
        response = requests.get(url)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            return {"vulnerable": False, "message": "No forms found on the page"}

        # Check each form for CSRF protection
        vulnerable_forms = []

        for i, form in enumerate(forms):
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()

            # Skip GET forms as they're less relevant for CSRF
            if form_method == 'get':
                continue

            # Look for common CSRF token field names
            csrf_fields = form.find_all('input', {
                'name': re.compile(r'csrf|xsrf|token', re.I)
            })

            # Also check for hidden fields that might be tokens
            hidden_fields = form.find_all('input', {'type': 'hidden'})

            if not csrf_fields and not any(is_likely_csrf_token(field.get('name', ''), field.get('value', '')) for field in hidden_fields):
                vulnerable_forms.append({
                    'index': i,
                    'action': form_action,
                    'method': form_method
                })

        if vulnerable_forms:
            return {
                "vulnerable": True,
                "type": "Cross-Site Request Forgery (CSRF)",
                "url": url,
                "vulnerable_forms": vulnerable_forms,
                "message": f"Found {len(vulnerable_forms)} form(s) without CSRF protection"
            }
        else:
            return {"vulnerable": False}

    except requests.exceptions.RequestException as e:
        print(f"Error scanning {url} for CSRF: {e}")
        return {"vulnerable": False, "error": str(e)}

def is_likely_csrf_token(name, value):
    """
    Heuristically determines if a field might be a CSRF token.
    """
    # Check if the name suggests it's a token
    if re.search(r'csrf|xsrf|token|nonce', name, re.I):
        return True

    # Check if the value looks like a random token
    if len(value) > 10 and re.search(r'[a-zA-Z0-9\-_]{10,}', value):
        return True

    return False

if __name__ == '__main__':
    test_url = "http://localhost:3000/#/contact"  # Replace with a test URL
    result = scan_csrf(test_url)
    print(result)
