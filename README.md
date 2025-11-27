# VirusTotal-CLI-Scanner
A Python-based CLI tool to analyze hashes, URLs and IP addresses using the VirusTotal API. Includes automatic result parsing and JSON logging. Built for cybersecurity learning, threat analysis and malware research purposes.

VT-Inspector

A lightweight and educational command-line tool for interacting with the VirusTotal API.
It allows security enthusiasts and analysts to quickly inspect file hashes, URLs, and IP addresses, with clean result parsing and automatic JSON logging.

Features

🔍 Analyze file hashes (MD5, SHA1, SHA256)

🔗 Analyze URLs (automatically Base64URL encoded)

🌐 Analyze IP addresses

📊 Displays malicious / suspicious / clean stats

📝 Saves results to results.json

❗ Handles API errors and invalid input

🧪 For ethical research, malware analysis and security testing

Usage

Run the script:

python3 vt_inspector.py


Enter your VirusTotal API key when prompted:

Enter your VirusTotal API key: 


Choose an option:

[1] Analyze Hash
[2] Analyze URL
[3] Analyze IP Address
[0] Exit

Requirements
requests


Install dependencies:

pip install requests

Example Output
Resource status: MALICIOUS (12/68 engines flagged it)

Disclaimer

This tool is intended only for educational, ethical cybersecurity use.
Always follow VirusTotal's terms of service and local laws.
