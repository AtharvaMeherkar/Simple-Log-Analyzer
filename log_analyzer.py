# log_analyzer.py
import re # Import the regular expression module
from collections import defaultdict # Used for easy counting (e.g., failed login attempts)

def analyze_log(log_file_path, output_report_path="security_report.txt"):
    """
    Reads a log file line by line, parses entries, and identifies suspicious activities.
    Generates a security report to the console and a file.
    """
    print(f"Starting analysis of: {log_file_path}\n")

    # Define a regular expression pattern to parse common Apache/Nginx log formats.
    # This pattern captures:
    # 1. IP Address: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - Matches standard IPv4 addresses
    # 2. Timestamp: \[(.*?)\] - Captures content inside square brackets (e.g., [01/Jul/2025:10:00:01 +0530])
    # 3. Request: "(.*?)" - Captures content inside double quotes (e.g., "GET /index.html HTTP/1.1")
    # 4. Status Code: (\d{3}) - Captures a 3-digit HTTP status code (e.g., 200, 404, 401)
    # 5. Size: (\d+|-)? - Captures the response size or a hyphen if not available
    log_pattern = re.compile(
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+|-)'
    )

    # Data structures to store findings
    failed_login_attempts = defaultdict(int) # Stores IP -> count of failed login attempts
    suspicious_url_patterns = [] # Stores details of URLs that match suspicious patterns
    forbidden_access_attempts = [] # Stores details of attempts to access restricted areas
    unusual_http_status_codes = [] # Stores details of other non-2xx/3xx status codes

    # List to collect all output messages for the final report file
    report_lines = []

    def add_to_report(message):
        """Helper function to print a message and add it to the report_lines list."""
        print(message)
        report_lines.append(message)

    add_to_report("--- Log Analysis Report ---")
    add_to_report(f"Analysis started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    add_to_report(f"Analyzing file: {log_file_path}\n")

    total_lines_processed = 0

    try:
        with open(log_file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                total_lines_processed += 1
                match = log_pattern.match(line) # Attempt to match the regex pattern to the line

                if match:
                    # Extract captured groups from the regex match
                    ip_address, timestamp, request_string, status_code_str, size = match.groups()

                    # Further parse the request string (e.g., "GET /path HTTP/1.1")
                    try:
                        method, url, http_version = request_string.split(' ', 2)
                    except ValueError:
                        add_to_report(f"[ERROR] Could not parse request string on line {line_num}: '{request_string}'")
                        continue # Skip this line if request string is malformed

                    try:
                        status_code = int(status_code_str) # Convert status code to integer for numerical comparison
                    except ValueError:
                        add_to_report(f"[ERROR] Invalid status code '{status_code_str}' on line {line_num}: {line.strip()}")
                        continue # Skip this line if status code is not a valid number

                    # --- SECURITY ANALYSIS LOGIC ---

                    # 1. Detect Failed Login Attempts (HTTP 401 Unauthorized)
                    # Check if the status code is 401 and the URL contains '/login'
                    if status_code == 401 and '/login' in url.lower():
                        failed_login_attempts[ip_address] += 1
                        add_to_report(f"[ALERT] Failed login from {ip_address} for '{url}' (Status: {status_code}) - Line {line_num}")

                    # 2. Detect Suspicious URL Patterns (e.g., SQL Injection, Cross-Site Scripting (XSS), Path Traversal)
                    # Using re.search for more flexible pattern matching within the URL
                    if re.search(r'(union\s+select|sleep\(|benchmark\(|/etc/passwd|/proc/self/environ|<script>|%3Cscript%3E)', url.lower()):
                        suspicious_url_patterns.append(f"IP: {ip_address}, URL: '{url}', Status: {status_code} - Line {line_num}")
                        add_to_report(f"[WARNING] Possible Malicious URL pattern detected from {ip_address} on '{url}'")

                    # 3. Detect Forbidden Access Attempts (HTTP 403 Forbidden)
                    # Check if the status code is 403 and the URL contains sensitive paths
                    if status_code == 403 and ('/admin/' in url.lower() or '/private/' in url.lower() or '/config/' in url.lower()):
                        forbidden_access_attempts.append(f"IP: {ip_address}, URL: '{url}', Status: {status_code} - Line {line_num}")
                        add_to_report(f"[WARNING] Forbidden access attempt to restricted area from {ip_address} on '{url}'")

                    # 4. Detect Other Unusual HTTP Status Codes (Client or Server Errors)
                    # Flag any 4xx (Client Error) or 5xx (Server Error) codes that haven't been specifically handled above
                    if 400 <= status_code < 600 and status_code not in [401, 403]:
                        unusual_http_status_codes.append(f"IP: {ip_address}, URL: '{url}', Status: {status_code} - Line {line_num}")
                        add_to_report(f"[INFO] Unusual HTTP Status Code: {status_code} for '{url}' from {ip_address} - Line {line_num}")

                else:
                    # If a line doesn't match our expected log pattern, report it
                    add_to_report(f"[ERROR] Could not parse line {line_num}: {line.strip()}")

    except FileNotFoundError:
        add_to_report(f"Error: The log file '{log_file_path}' was not found. Please ensure it exists.")
    except Exception as e:
        add_to_report(f"An unexpected error occurred during analysis: {e}")

    # --- ANALYSIS SUMMARY ---
    add_to_report(f"\n--- Analysis Summary ({total_lines_processed} lines processed) ---")

    if failed_login_attempts:
        add_to_report("\nSummary of Failed Login Attempts (IP: Count):")
        for ip, count in failed_login_attempts.items():
            if count >= 3: # A common threshold for brute-force attempts
                add_to_report(f"  [CRITICAL] {ip}: {count} (Multiple failed attempts - potential brute-force!)")
            else:
                add_to_report(f"  {ip}: {count}")
    else:
        add_to_report("\nNo significant failed login attempts detected.")

    if suspicious_url_patterns:
        add_to_report("\nSummary of Suspicious URL Access Attempts:")
        for entry in suspicious_url_patterns:
            add_to_report(f"  {entry}")
    else:
        add_to_report("\nNo suspicious URL access attempts detected.")

    if forbidden_access_attempts:
        add_to_report("\nSummary of Forbidden Access Attempts (403 Status):")
        for entry in forbidden_access_attempts:
            add_to_report(f"  {entry}")
    else:
        add_to_report("\nNo forbidden access attempts detected.")

    if unusual_http_status_codes:
        add_to_report("\nSummary of Other Unusual HTTP Status Codes (4xx/5xx):")
        for entry in unusual_http_status_codes:
            add_to_report(f"  {entry}")
    else:
        add_to_report("\nNo other unusual HTTP status codes detected.")

    add_to_report(f"\nAnalysis complete. Detailed report saved to '{output_report_path}'")

    # Save the accumulated report content to a file
    try:
        with open(output_report_path, 'w') as report_file:
            for line in report_lines:
                report_file.write(line + '\n')
    except Exception as e:
        print(f"Error: Could not save report to '{output_report_path}': {e}")


# This block ensures that analyze_log() is called only when
# the script is executed directly.
if __name__ == "__main__":
    import datetime # Import datetime here as it's used in the main function call

    log_file_name = "access.log"
    report_file_name = "security_report.txt"
    analyze_log(log_file_name, report_file_name)