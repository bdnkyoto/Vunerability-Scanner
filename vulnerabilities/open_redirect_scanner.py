import requests
import urllib.parse
from bs4 import BeautifulSoup

def scan_open_redirect(url):
    """
    Scans for Open Redirect vulnerabilities in a web application.
    """
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    # Common parameter names that might be used for redirects
    redirect_param_names = [
        'redirect', 'redirect_to', 'redirecturl', 'redirect_uri', 'returnto', 'returnurl',
        'return', 'return_url', 'return_to', 'goto', 'next', 'url', 'target', 'rurl',
        'dest', 'destination', 'redir', 'redirect_url', 'link', 'linkto', 'to'
    ]

    # Test payloads (malicious URLs)
    test_payloads = [
        'https://evil-site.com',
        'https://attacker.com',
        '//evil-site.com',
        'http:////evil-site.com',
        'https:////evil-site.com',
        'javascript:alert(document.domain)'
    ]

    found_params = {}

    # Check if URL already contains potential redirect parameters
    for param_name in query_params:
        if param_name.lower() in redirect_param_names:
            found_params[param_name] = query_params[param_name][0]

    # If no redirect parameters found in URL, scan the page for forms
    if not found_params:
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Check for links with redirect parameters
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                parsed_href = urllib.parse.urlparse(href)
                href_params = urllib.parse.parse_qs(parsed_href.query)

                for param_name in href_params:
                    if param_name.lower() in redirect_param_names:
                        # Get the base URL for this link
                        if href.startswith('/'):
                            # Relative URL
                            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{href}"
                        else:
                            base_url = href

                        found_params[param_name] = href_params[param_name][0]

            # Check forms for potential redirect fields
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    if input_tag.get('name') and input_tag.get('name').lower() in redirect_param_names:
                        found_params[input_tag.get('name')] = input_tag.get('value', '')

        except requests.exceptions.RequestException as e:
            print(f"Error scanning {url} for open redirect parameters: {e}")

    if not found_params:
        return {"vulnerable": False, "message": "No potential redirect parameters found"}

    # Test each parameter with malicious payloads
    vulnerable_params = []

    for param_name, original_value in found_params.items():
        for payload in test_payloads:
            encoded_payload = urllib.parse.quote_plus(payload)

            # Create a test URL with the payload
            test_url_parts = list(parsed_url)
            query_dict = urllib.parse.parse_qs(parsed_url.query)
            query_dict[param_name] = [encoded_payload]
            test_url_parts[4] = urllib.parse.urlencode(query_dict, doseq=True)
            test_url = urllib.parse.urlunparse(test_url_parts)

            try:
                # Make request with allow_redirects=False to catch the redirect without following it
                response = requests.get(test_url, allow_redirects=False, timeout=10)

                # Check if the response is a redirect
                if 300 <= response.status_code < 400:
                    location = response.headers.get('Location', '')

                    # Check if our payload is in the redirect URL
                    if payload in location or encoded_payload in location:
                        vulnerable_params.append({
                            "parameter": param_name,
                            "payload": payload,
                            "redirect_url": location,
                            "test_url": test_url
                        })
                        break  # Found a vulnerability with this parameter, no need to test more payloads

            except requests.exceptions.RequestException as e:
                print(f"Error testing {test_url} for open redirect: {e}")
                continue

    if vulnerable_params:
        return {
            "vulnerable": True,
            "type": "Open Redirect",
            "url": url,
            "vulnerable_parameters": vulnerable_params
        }
    else:
        return {"vulnerable": False}

if __name__ == '__main__':
    test_url = "http://localhost:3000"  # Replace with a test URL
    result = scan_open_redirect(test_url)
    print(result)
