# 🔍 Network Security Scanning Automation

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Nmap](https://img.shields.io/badge/Built%20with-Nmap-blue)](https://nmap.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)](#)

A powerful Python-based tool that automates domain reconnaissance, host discovery, and vulnerability assessment. It wraps the functionality of **Nmap** in an easy-to-use interface and generates detailed, professional-grade HTML reports.

---

## ✨ Features

- **Domain Resolution** – Automatically resolves domains to IP addresses  
- **Host Discovery** – Detects live hosts in the target domain  
- **Service Detection** – Identifies open ports, services, and versions  
- **OS Fingerprinting** – Attempts to identify the target operating system  
- **SSL Cipher Enumeration** – Analyzes TLS/SSL configurations for weaknesses  
- **Basic Vulnerability Scanning** – Flags common misconfigurations and exposures  
- **HTML Reporting** – Generates clear and well-structured reports  
- **Exclusion Options** – Allows skipping of specific hosts from deep scans  

---

## 📦 Requirements

- Python 3.6+
- [Nmap](https://nmap.org/download.html) installed and accessible via terminal
- Standard Python libraries:
  - `os`, `re`, `sys`, `webbrowser`, `datetime`, `socket`

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secscan.git
cd secscan
```

### Install Nmap

```bash
# Debian/Ubuntu
sudo apt-get install nmap

# CentOS/RHEL
sudo yum install nmap

# macOS (Homebrew)
brew install nmap
```

👉 On Windows: [Download and install Nmap](https://nmap.org/download.html)

---

## 🚀 Run the Scanner

```bash
python scanner.py
```

---

## 🛠️ Usage

1. Launch the script  
2. Enter the target domain (e.g., `example.com`)  
3. The scanner will:
   - Resolve domain to IP
   - Perform host discovery
   - List live hosts
   - Allow host exclusions
   - Run detailed service/OS/cipher scans
   - Generate and open an HTML report

---

## 📋 Example Output

```
╔══════════════════════════════════════╗
║   NETWORK SECURITY SCANNING TOOL    ║
╚══════════════════════════════════════╝

Please enter the domain to scan (e.g., example.cc): example.com

Resolving domain example.com...
Domain resolves to: 93.184.216.34

Running host discovery scan...

Host: 93.184.216.34 — Status: Up

An SSL cipher and vulnerability scan will be conducted next.
Would you like to exclude an IP Address from this scan? (y/n): n

Starting comprehensive scan...
```

---

## 📊 Report Overview

The generated HTML report includes:

- Target domain/IP and scan summary  
- Port and service details  
- Detected OS and SSL/TLS configuration  
- Security recommendations  
- Full raw Nmap output  

---

## ⚠️ Disclaimer

> This tool is intended **only for authorized security testing** and educational purposes. Scanning networks without permission may violate local or federal laws.

---


## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Nmap](https://nmap.org/) – The powerful scanner this tool is built upon  
