import requests
import urllib.parse
import re
from bs4 import BeautifulSoup

def scan_idor(url):
    """
    Scans for Insecure Direct Object Reference (IDOR) vulnerabilities.
    This is a simplified scanner that looks for potential numeric IDs in URLs.
    """
    # Parse the URL to find potential ID parameters
    parsed_url = urllib.parse.urlparse(url)
    path_segments = parsed_url.path.split('/')
    query_params = urllib.parse.parse_qs(parsed_url.query)

    potential_id_params = {}

    # Check path segments for numeric values (potential IDs)
    for i, segment in enumerate(path_segments):
        if segment.isdigit():
            potential_id_params[f"path_segment_{i}"] = segment

    # Check query parameters for numeric values
    for param, values in query_params.items():
        if len(values) == 1 and values[0].isdigit():
            potential_id_params[param] = values[0]

    if not potential_id_params:
        return {"vulnerable": False, "message": "No potential ID parameters found in URL"}

    results = []

    for param_name, value in potential_id_params.items():
        # Try incrementing and decrementing the ID to see if we can access different resources
        for test_value in [str(int(value) + 1), str(int(value) - 1)]:
            test_url = modify_url(url, param_name, test_value, path_segments)

            try:
                # Send request with original ID
                original_response = requests.get(url, timeout=10)

                # Send request with modified ID
                modified_response = requests.get(test_url, timeout=10)

                # Check if both requests were successful and returned different content
                if (original_response.status_code == 200 and
                    modified_response.status_code == 200 and
                    len(modified_response.text) > 0 and
                    similar_but_different(original_response.text, modified_response.text)):

                    results.append({
                        "parameter": param_name,
                        "original_value": value,
                        "test_value": test_value,
                        "test_url": test_url
                    })

            except requests.exceptions.RequestException as e:
                print(f"Error testing {test_url} for IDOR: {e}")
                continue

    if results:
        return {
            "vulnerable": True,
            "type": "Insecure Direct Object Reference (IDOR)",
            "url": url,
            "potential_vulnerabilities": results
        }
    else:
        return {"vulnerable": False}

def modify_url(url, param_name, new_value, path_segments):
    """
    Modifies either a path segment or query parameter in a URL.
    """
    parsed_url = urllib.parse.urlparse(url)

    if param_name.startswith('path_segment_'):
        # Modify path segment
        segment_index = int(param_name.split('_')[-1])
        new_path_segments = path_segments.copy()
        if segment_index < len(new_path_segments):
            new_path_segments[segment_index] = new_value

        new_path = '/'.join(new_path_segments)
        modified_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            new_path,
            parsed_url.params,
            parsed_url.query,
            parsed_url.fragment
        ))
    else:
        # Modify query parameter
        query_dict = urllib.parse.parse_qs(parsed_url.query)
        query_dict[param_name] = [new_value]
        new_query = urllib.parse.urlencode(query_dict, doseq=True)

        modified_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))

    return modified_url

def similar_but_different(text1, text2, similarity_threshold=0.7):
    """
    Checks if two HTML responses are similar but different.
    This helps identify when we're seeing different records of the same type.
    """
    # Remove all whitespace for comparison
    text1_clean = re.sub(r'\s+', '', text1)
    text2_clean = re.sub(r'\s+', '', text2)

    # Calculate similarity
    shorter_length = min(len(text1_clean), len(text2_clean))
    longer_length = max(len(text1_clean), len(text2_clean))

    if shorter_length == 0:
        return False

    # Simple character-by-character comparison
    common_chars = sum(a == b for a, b in zip(text1_clean, text2_clean))
    similarity = common_chars / longer_length

    # We want texts that are similar (same template) but not identical
    return similarity > similarity_threshold and similarity < 1.0

if __name__ == '__main__':
    test_url = "http://localhost:3000"  # Replace with a test URL
    result = scan_idor(test_url)
    print(result)
