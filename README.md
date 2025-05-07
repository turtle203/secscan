Network Security Scanning Automation
Show Image
Show Image
Show Image
A comprehensive network security scanning tool that automates domain reconnaissance, host discovery, and vulnerability assessment. This tool wraps Nmap functionality in a user-friendly interface and generates well-formatted HTML reports.
🔐 Features

Domain Resolution: Automatically resolves domains to IP addresses
Host Discovery: Identifies all available hosts within a target domain
Service Detection: Identifies running services and their versions
OS Detection: Attempts to fingerprint operating systems
SSL Cipher Enumeration: Analyzes SSL/TLS configurations for security issues
Vulnerability Scanning: Conducts basic vulnerability checks on discovered services
Comprehensive Reports: Generates professional HTML reports with detailed findings
Target Exclusion: Option to exclude specific hosts from detailed scanning

📋 Requirements

Python 3.6 or higher
Nmap security scanner - Download & Install Nmap
Standard Python libraries: os, re, sys, webbrowser, datetime, socket

🚀 Installation

Clone this repository:
bashgit clone https://github.com/yourusername/network-security-scanner.git
cd network-security-scanner

Ensure Nmap is installed on your system:
bash# On Debian/Ubuntu
sudo apt-get install nmap

# On CentOS/RHEL
sudo yum install nmap

# On macOS (using Homebrew)
brew install nmap

# On Windows
# Download and install from https://nmap.org/download.html

Run the script:
bashpython scanner.py


📊 Usage

Launch the script
Enter the target domain (e.g., example.com)
The script will:

Resolve the domain to IP address(es)
Conduct host discovery
Show found hosts
Allow you to exclude specific hosts if needed
Run service detection, OS fingerprinting, and vulnerability scans
Generate and open an HTML report



📝 Example
╔═══════════════════════════════════════════════╗
║                                               ║
║     NETWORK SECURITY SCANNING AUTOMATION      ║
║                                               ║
╚═══════════════════════════════════════════════╝

Please enter the domain to scan (e.g., alfacorp.cc): example.com

Resolving domain example.com...
Domain resolves to: 93.184.216.34

Running host discovery scan on example.com...

Scan results:
# Nmap 7.92 scan initiated...
Host: 93.184.216.34 Status: Up

The following hosts were identified:
93.184.216.34

An SSL cipher and vulnerability scan will be conducted next
Would you like to exclude an IP Address from this scan?
Enter 'y' or 'n': n
No IP Addresses removed.
Starting vulnerability scan...

Running comprehensive scan with service detection, OS detection, and SSL cipher enumeration...
📊 Report Sample
The generated HTML report includes:

Target Information: Domain, IP, Status, OS
Port Scan Results: Detailed information about open ports and services
Security Recommendations: Based on detected services
Raw Scan Data: Complete Nmap output for further analysis

⚠️ Disclaimer
This tool is provided for legitimate security testing only. Always ensure you have proper authorization before scanning any network or system. Unauthorized scanning may be illegal in many jurisdictions.
🔄 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

Fork the repository
Create your feature branch (git checkout -b feature/amazing-feature)
Commit your changes (git commit -m 'Add some amazing feature')
Push to the branch (git push origin feature/amazing-feature)
Open a Pull Request

📜 License
This project is licensed under the MIT License - see the LICENSE file for details.
🙏 Acknowledgments

Nmap - The powerful network scanner this tool is built upon
All contributors and security professionals who shared their knowledge
