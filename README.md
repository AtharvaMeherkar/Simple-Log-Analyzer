Simple Log Analyzer for Cybersecurity


Project Overview

This project is a Python command-line tool designed for basic web server log analysis and threat detection. 
It processes common log formats (like Apache/Nginx access logs) to identify suspicious activities, potential attack attempts, and generate a structured security report along with insightful visual graphs. 
It serves as a foundational example of programmatic security monitoring.



Features

Log Parsing: Efficiently reads and parses log entries using regular expressions (re module) to extract key information such as IP addresses, timestamps, requested URLs, and HTTP status codes.
Threat Detection: Identifies brute-force login attempts by detecting multiple 401 Unauthorized responses from a single source IP on login-related endpoints.
Detects SQL Injection and Cross-Site Scripting (XSS) attempts by scanning for known malicious patterns and payloads within URLs.
Flag unauthorized access attempts to sensitive or restricted directories (e.g., /admin/, /private/).
Monitors for other unusual HTTP status codes (e.g., 4xx client errors, 5xx server errors) that might indicate anomalies or misconfigurations.
Data Aggregation: Summarizes detected anomalies by source IP, event type, and severity.
Visual Reporting: Automatically generates and saves informative graphs (e.g., protocol distribution pie chart, traffic volume over time line plot) using matplotlib to provide a clear and attractive visual overview of network activity patterns.
Textual Reports: Outputs a detailed, human-readable security analysis report to a text file, summarizing all findings.



Technologies Used

Python 3.x:                 Core programming language for scripting and logic.
re module:                  Standard library for regular expression-based log parsing.
collections (defaultdict):  For efficient counting and aggregation of log data.
pandas:                     Powerful library for data structuring, manipulation, and aggregation of log events.
matplotlib:                 Used for creating static, high-quality visual charts and saving them as image files within the report.



How to Download and Run the Project

1. Prerequisites
Python 3.x: Ensure Python 3.x is installed on your system. You can download it from python.org. During installation, make sure to check "Add Python.exe to PATH".
pip: Python's package installer, which comes with Python.
Git: Ensure Git is installed on your system. Download from git-scm.com. During installation, select "Git from the command line and also from 3rd-party software" for PATH integration.
VS Code (Recommended): For a smooth development experience.



2. Download the Project
Open your terminal or Git Bash.
Clone the repository:
git clone https://github.com/AtharvaMeherkar/Simple-Log-Analyzer.git
Navigate into the project directory:
cd Simple-Log-Analyzer



3. Setup and Installation
Open the project in VS Code:
code.
Open the Integrated Terminal in VS Code (Ctrl + ~).
Create and activate a virtual environment (highly recommended):
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
You should see (venv) at the beginning of your terminal prompt, indicating the virtual environment is active.
Install the required Python packages:
pip install pandas matplotlib



4. Prepare Sample Data
A sample log file named access.log is already included in the repository. This file contains various types of log entries, including simulated attack attempts, for testing purposes.
If you wish to analyze your log file, place it in the same directory as analyzer.py and update the log_file variable in analyzer.py if its name is different.



5. Execution
Please make sure your virtual environment is active in the VS Code terminal.
Run the analysis script:
python analyzer.py

The script will print analysis messages to the console.
Check the output: A new folder named analysis_reports will be created in your project directory.
Inside analysis_reports, you'll find a detailed text report (e.g., access_report.txt).
A graph's subfolder will contain generated image files (e.g., protocol_distribution.png, traffic_over_time.png) visualizing the network data.



What I Learned / Challenges Faced

Log Parsing with Regex: Gained hands-on experience in crafting robust regular expressions to extract structured data from unstructured log files, which is fundamental for security information processing.
Security Event Identification: Deepened understanding of common attack patterns (brute-force, SQLi, XSS, unauthorized access) and how to programmatically detect them within log data.
Data Aggregation & Reporting: Learned to effectively use pandas for efficient data manipulation and matplotlib for generating clear, insightful visual reports from complex security data, enhancing readability and impact.
Automated Analysis: Developed a foundational understanding of building automated tools for security monitoring, demonstrating how scripting can reduce manual review time and improve incident response capabilities.
Handling Edge Cases: Ensured the script handles missing files gracefully, manages different log entry formats, and provides clear error messages for a more robust solution.
