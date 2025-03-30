import requests
import urllib.parse
from bs4 import BeautifulSoup

def check_reflected_xss(url, params):
    """
    Checks for reflected XSS in the given URL and parameters.
    """
    payloads = [
        "<script>alert('XSS')</script>",
        "\"'><script>alert(1)</script>",
        "<img src=x onerror=alert('XSS')>",
    ]  # Simplified payloads

    for param in params:
        for payload in payloads:
            # URL encode the payload
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?{param}={encoded_payload}"

            try:
                response = requests.get(test_url)
                response.raise_for_status()  # Raise exception for bad status

                if payload in response.text:
                    return {
                        "vulnerable": True,
                        "type": "Reflected XSS",
                        "url": test_url,
                        "parameter": param,
                        "payload": payload,
                    }
            except requests.exceptions.RequestException as e:
                print(f"Error checking {test_url}: {e}")
                continue  # Go to the next payload

    return {"vulnerable": False}

def check_stored_xss(url, form_data=None):
    """
    Checks for stored XSS by submitting a payload and then checking
    if it's rendered on another page.
    """
    session = requests.Session()
    payloads = [
        "<script>alert('StoredXSS')</script>",
        "\"'><script>alert('StoredXSS')</script>",
        "<img src=x onerror=alert('StoredXSS')>",
    ]

    # Step 1: Find forms if form_data is not provided
    if not form_data:
        try:
            response = session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                return {
                    "vulnerable": False,
                    "type": "Stored XSS",
                    "url": url,
                    "message": "No forms found to test for stored XSS"
                }

            # Process the first form found
            form = forms[0]
            action = form.get('action', '')
            method = form.get('method', 'post').lower()

            # Build form data from input fields
            form_data = {}
            for input_field in form.find_all(['input', 'textarea']):
                name = input_field.get('name')
                if name:
                    input_type = input_field.get('type', 'text')
                    if input_type not in ['submit', 'button', 'file', 'image']:
                        form_data[name] = payloads[0]  # Use the first payload
                    else:
                        form_data[name] = input_field.get('value', '')

            # Construct the submission URL
            if action and action.startswith('http'):
                submit_url = action
            elif action:
                submit_url = urllib.parse.urljoin(url, action)
            else:
                submit_url = url

        except Exception as e:
            return {
                "vulnerable": False,
                "type": "Stored XSS",
                "url": url,
                "message": f"Error finding forms: {str(e)}"
            }
    else:
        # Use provided URL for submission
        submit_url = url
        method = "post"  # Default method

    # Step 2: Submit payloads and check for stored XSS
    for payload in payloads:
        try:
            # Update form data with current payload
            payload_form_data = form_data.copy()
            for key in payload_form_data:
                if isinstance(payload_form_data[key], str) and '<script>' in payload_form_data[key]:
                    payload_form_data[key] = payload

            # Submit the form
            if method == "post":
                submit_response = session.post(submit_url, data=payload_form_data)
            else:
                submit_response = session.get(submit_url, params=payload_form_data)

            # Step 3: Check if payload appears in the response or other pages
            if payload in submit_response.text:
                # This might be reflected XSS, but check linked pages too
                soup = BeautifulSoup(submit_response.text, 'html.parser')
                links = soup.find_all('a', href=True)

                # Track visited URLs to avoid loops
                visited = set([url, submit_url])

                # Check up to 5 linked pages for the stored payload
                for i, link in enumerate(links[:5]):
                    href = link['href']
                    check_url = urllib.parse.urljoin(url, href)

                    # Skip external links or already visited pages
                    parsed_url = urllib.parse.urlparse(check_url)
                    if parsed_url.netloc != urllib.parse.urlparse(url).netloc or check_url in visited:
                        continue

                    visited.add(check_url)

                    try:
                        check_response = session.get(check_url, timeout=5)
                        if payload in check_response.text:
                            return {
                                "vulnerable": True,
                                "type": "Stored XSS",
                                "url": submit_url,
                                "found_on": check_url,
                                "payload": payload,
                                "form_data": payload_form_data
                            }
                    except Exception:
                        continue

        except Exception as e:
            continue

    # No stored XSS found
    return {
        "vulnerable": False,
        "type": "Stored XSS",
        "url": url,
        "message": "No stored XSS vulnerabilities detected"
    }

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

def scan_xss(url):
    """
    Main function to scan for both reflected and stored XSS.
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

    reflected_xss_result = check_reflected_xss(url, params)
    stored_xss_result = check_stored_xss(url)

    if reflected_xss_result["vulnerable"]:
        return reflected_xss_result
    elif stored_xss_result["vulnerable"]:
        return stored_xss_result
    else:
        return {"vulnerable": False}

if __name__ == '__main__':
    test_url = "http://localhost:3000/#/contact"  # Example vulnerable site
    result = scan_xss(test_url)
    print(result)
