import os
import re
import sys
import webbrowser
from datetime import datetime
import socket

print('''
╔═══════════════════════════════════════════════╗
║                                               ║
║         NETWORK SECURITY SCANNING             ║
║            BY IBRAHIM GUL                     ║
║                                               ║
╚═══════════════════════════════════════════════╝
''')

domain = input("Please enter the domain to scan (e.g., google.com): ")

# Try to get IP address information before scanning
try:
    print(f"\nResolving domain {domain}...")
    ip_info = socket.gethostbyname_ex(domain)
    print(f"Domain resolves to: {', '.join(ip_info[2])}")
except socket.gaierror:
    print(f"Could not resolve domain {domain}. Will attempt scanning anyway.")

# Run the initial scan for host discovery on the domain
print(f"\nRunning host discovery scan on {domain}...")
os.system(f"nmap -sn -oG host_list.txt {domain}")

# Parse the output file to find hosts
try:
    with open('host_list.txt', 'r') as hl:
        host_content = hl.read()
        print("\nScan results:")
        print(host_content)
        
        # Extract IP addresses - look for the pattern "Host: IP_ADDRESS"
        ip_pattern = re.compile(r'Host:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        hosts_found = ip_pattern.findall(host_content)
        
        # If no hosts found with that pattern, try an alternative
        if not hosts_found:
            alt_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*Status: Up')
            hosts_found = alt_pattern.findall(host_content)
except FileNotFoundError:
    print("Error: host_list.txt was not created. Check if nmap is installed correctly.")
    sys.exit(1)

print("\nThe following hosts were identified:")
if hosts_found:
    print(*hosts_found, sep="\n")
    
    print("\nAn SSL cipher and vulnerability scan will be conducted next")
    
    decision = input("Would you like to exclude an IP Address from this scan?\nEnter 'y' or 'n': ")
    if decision.lower() == 'y':
        print("Which IP Address would you like to exclude?")
        removeip = str(input())
        if removeip in hosts_found:
            hosts_found.remove(removeip)
            print(f"Removed {removeip} from scan list.")
        else:
            print(f"Warning: {removeip} is not in the list of discovered hosts.")
    elif decision.lower() == 'n':
        print("No IP Addresses removed.")
    
    if hosts_found:
        print("Starting vulnerability scan...")
        # Build target list for next scan
        targets = " ".join(hosts_found)
        
        # Create a timestamp for the report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = f"scan_report_{timestamp}"
        
        # Run the detailed scan and generate reports in multiple formats
        print("\nRunning comprehensive scan with service detection, OS detection, and SSL cipher enumeration...")
        os.system(f"nmap -sV -O --script=ssl-enum-ciphers {targets} -oX {report_name}.xml -oN {report_name}.txt")
        
        # Create a simple HTML report manually since xsltproc isn't available
        if os.path.exists(f"{report_name}.txt"):
            try:
                # Read the text report
                with open(f"{report_name}.txt", "r") as txt_file:
                    report_content = txt_file.read()
                
                # Parse the nmap output to extract structured information
                ports_info = []
                host_info = {"ip": "", "status": "", "hostnames": [], "os": "Unknown"}
                current_host = None
                services = []
                
                # Extract information from the report
                for line in report_content.splitlines():
                    # Extract host information
                    if "Nmap scan report for" in line:
                        if "(" in line and ")" in line:
                            # Format: Nmap scan report for hostname (IP)
                            hostname = line.split("Nmap scan report for ")[1].split(" (")[0].strip()
                            ip = line.split("(")[1].split(")")[0].strip()
                            host_info["ip"] = ip
                            host_info["hostnames"].append(hostname)
                        else:
                            # Format: Nmap scan report for IP
                            ip = line.split("Nmap scan report for ")[1].strip()
                            host_info["ip"] = ip
                    
                    # Extract host status
                    elif "Host is " in line:
                        host_info["status"] = line.strip()
                    
                    # Extract port information
                    elif re.match(r'^\d+/\w+\s+\w+\s+\w+', line):
                        # Format: PORT     STATE SERVICE       VERSION
                        parts = line.split()
                        if len(parts) >= 3:
                            port_num = parts[0].split('/')[0]
                            protocol = parts[0].split('/')[1]
                            state = parts[1]
                            service = parts[2]
                            version = " ".join(parts[3:]) if len(parts) > 3 else ""
                            
                            port_info = {
                                "port": port_num,
                                "protocol": protocol,
                                "state": state,
                                "service": service,
                                "version": version
                            }
                            services.append(port_info)
                    
                    # Extract OS detection information
                    elif "OS:" in line:
                        host_info["os"] = line.split("OS:")[1].strip()
                
                # Create a detailed HTML file with better styling
                with open(f"{report_name}.html", "w") as html_file:
                    html_file.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Nmap Scan Report for {domain}</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 0;
            padding: 0;
            background-color: #f0f2f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px 5px 0 0;
            margin-bottom: 20px;
        }}
        h1 {{ 
            margin: 0;
            font-size: 28px;
        }}
        h2 {{ 
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-top: 30px;
        }}
        .timestamp {{ 
            color: #ecf0f1; 
            font-style: italic;
            margin-top: 10px;
        }}
        .card {{
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }}
        .host-info {{
            display: grid;
            grid-template-columns: 150px auto;
            gap: 10px;
        }}
        .host-info div {{
            padding: 5px 0;
        }}
        .host-info .label {{
            font-weight: bold;
            color: #555;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f1f1f1;
        }}
        .port-open {{
            color: #27ae60;
            font-weight: bold;
        }}
        .port-closed {{
            color: #e74c3c;
        }}
        .port-filtered {{
            color: #f39c12;
        }}
        .raw-data {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
            font-family: 'Consolas', 'Courier New', monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            font-size: 14px;
            margin-top: 20px;
        }}
        footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Network Security Scan Report</h1>
            <p class="timestamp">Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </header>
        
        <div class="card">
            <h2>Target Information</h2>
            <div class="host-info">
                <div class="label">Domain:</div>
                <div>{domain}</div>
                
                <div class="label">IP Address:</div>
                <div>{host_info["ip"]}</div>
                
                <div class="label">Status:</div>
                <div>{host_info["status"]}</div>
                
                <div class="label">Hostnames:</div>
                <div>{", ".join(host_info["hostnames"]) if host_info["hostnames"] else "N/A"}</div>
                
                <div class="label">Operating System:</div>
                <div>{host_info["os"]}</div>
            </div>
        </div>
        
        <div class="card">
            <h2>Port Scan Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join([f'''
                    <tr>
                        <td>{service["port"]}</td>
                        <td>{service["protocol"]}</td>
                        <td class="port-{service["state"].lower()}">{service["state"]}</td>
                        <td>{service["service"]}</td>
                        <td>{service["version"]}</td>
                    </tr>
                    ''' for service in services]) if services else '<tr><td colspan="5">No open ports detected</td></tr>'}
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <h2>Security Recommendations</h2>
            <ul>
                <li>Review all open ports and ensure they are necessary for business operations</li>
                <li>Implement firewalls to restrict access to necessary services only</li>
                <li>Ensure all services are updated to the latest secure versions</li>
                <li>Consider implementing intrusion detection systems to monitor network traffic</li>
                <li>Regularly conduct security audits to identify potential vulnerabilities</li>
            </ul>
        </div>
        
        <div class="card">
            <h2>Raw Scan Data</h2>
            <div class="raw-data">{report_content}</div>
        </div>
        
        <footer>
            Scan performed using Nmap. This report is for authorized security assessment purposes only.
        </footer>
    </div>
</body>
</html>""")
                
                print(f"Scan complete. Opening report {report_name}.html...")
                # Open the HTML file in the default browser
                webbrowser.open(f"{report_name}.html")
            except Exception as e:
                print(f"Error creating HTML report: {e}")
                print(f"Text report is available at {report_name}.txt")
        else:
            print("Error: Failed to generate scan report.")
    else:
        print("No hosts left to scan after exclusions.")
else:
    print("No hosts were discovered for the domain. The domain might not be resolvable or accessible.")
    # Alternative approach - scan the domain directly
    print("\nTrying direct domain scan instead...")
    
    # Create a timestamp for the report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"scan_report_{timestamp}"
    
    print("\nRunning comprehensive scan with service detection, OS detection, and SSL cipher enumeration...")
    os.system(f"nmap -sV -O --script=ssl-enum-ciphers {domain} -oX {report_name}.xml -oN {report_name}.txt")
    
    if os.path.exists(f"{report_name}.txt"):
        try:
            # Read the text report
            with open(f"{report_name}.txt", "r") as txt_file:
                report_content = txt_file.read()
            
            # Parse the nmap output for structured information
            ports_info = []
            host_info = {"ip": "", "status": "", "hostnames": [], "os": "Unknown"}
            services = []
            
            # Extract information from the report
            for line in report_content.splitlines():
                # Extract host information
                if "Nmap scan report for" in line:
                    if "(" in line and ")" in line:
                        # Format: Nmap scan report for hostname (IP)
                        hostname = line.split("Nmap scan report for ")[1].split(" (")[0].strip()
                        ip = line.split("(")[1].split(")")[0].strip()
                        host_info["ip"] = ip
                        host_info["hostnames"].append(hostname)
                    else:
                        # Format: Nmap scan report for IP
                        ip = line.split("Nmap scan report for ")[1].strip()
                        host_info["ip"] = ip
                
                # Extract host status
                elif "Host is " in line:
                    host_info["status"] = line.strip()
                
                # Extract port information
                elif re.match(r'^\d+/\w+\s+\w+\s+\w+', line):
                    # Format: PORT     STATE SERVICE       VERSION
                    parts = line.split()
                    if len(parts) >= 3:
                        port_num = parts[0].split('/')[0]
                        protocol = parts[0].split('/')[1]
                        state = parts[1]
                        service = parts[2]
                        version = " ".join(parts[3:]) if len(parts) > 3 else ""
                        
                        port_info = {
                            "port": port_num,
                            "protocol": protocol,
                            "state": state,
                            "service": service,
                            "version": version
                        }
                        services.append(port_info)
                
                # Extract OS detection information
                elif "OS:" in line:
                    host_info["os"] = line.split("OS:")[1].strip()
            
            # Create a detailed HTML file with better styling
            with open(f"{report_name}.html", "w") as html_file:
                html_file.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>Nmap Scan Report for {domain}</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 0;
            padding: 0;
            background-color: #f0f2f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px 5px 0 0;
            margin-bottom: 20px;
        }}
        h1 {{ 
            margin: 0;
            font-size: 28px;
        }}
        h2 {{ 
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-top: 30px;
        }}
        .timestamp {{ 
            color: #ecf0f1; 
            font-style: italic;
            margin-top: 10px;
        }}
        .card {{
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }}
        .host-info {{
            display: grid;
            grid-template-columns: 150px auto;
            gap: 10px;
        }}
        .host-info div {{
            padding: 5px 0;
        }}
        .host-info .label {{
            font-weight: bold;
            color: #555;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f1f1f1;
        }}
        .port-open {{
            color: #27ae60;
            font-weight: bold;
        }}
        .port-closed {{
            color: #e74c3c;
        }}
        .port-filtered {{
            color: #f39c12;
        }}
        .raw-data {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
            font-family: 'Consolas', 'Courier New', monospace;
            white-space: pre-wrap;
            overflow-x: auto;
            font-size: 14px;
            margin-top: 20px;
        }}
        footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #7f8c8d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Network Security Scan Report</h1>
            <p class="timestamp">Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </header>
        
        <div class="card">
            <h2>Target Information</h2>
            <div class="host-info">
                <div class="label">Domain:</div>
                <div>{domain}</div>
                
                <div class="label">IP Address:</div>
                <div>{host_info["ip"]}</div>
                
                <div class="label">Status:</div>
                <div>{host_info["status"]}</div>
                
                <div class="label">Hostnames:</div>
                <div>{", ".join(host_info["hostnames"]) if host_info["hostnames"] else "N/A"}</div>
                
                <div class="label">Operating System:</div>
                <div>{host_info["os"]}</div>
            </div>
        </div>
        
        <div class="card">
            <h2>Port Scan Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State</th>
                        <th>Service</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join([f'''
                    <tr>
                        <td>{service["port"]}</td>
                        <td>{service["protocol"]}</td>
                        <td class="port-{service["state"].lower()}">{service["state"]}</td>
                        <td>{service["service"]}</td>
                        <td>{service["version"]}</td>
                    </tr>
                    ''' for service in services]) if services else '<tr><td colspan="5">No open ports detected</td></tr>'}
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <h2>Security Recommendations</h2>
            <ul>
                <li>Review all open ports and ensure they are necessary for business operations</li>
                <li>Implement firewalls to restrict access to necessary services only</li>
                <li>Ensure all services are updated to the latest secure versions</li>
                <li>Consider implementing intrusion detection systems to monitor network traffic</li>
                <li>Regularly conduct security audits to identify potential vulnerabilities</li>
            </ul>
        </div>
        
        <div class="card">
            <h2>Raw Scan Data</h2>
            <div class="raw-data">{report_content}</div>
        </div>
        
        <footer>
            Scan performed using Nmap. This report is for authorized security assessment purposes only.
        </footer>
    </div>
</body>
</html>""")
            
            print(f"Scan complete. Opening report {report_name}.html...")
            # Open the HTML file in the default browser
            webbrowser.open(f"{report_name}.html")
        except Exception as e:
            print(f"Error creating HTML report: {e}")
            print(f"Text report is available at {report_name}.txt")
    else:
        print("Error: Failed to generate scan report.")
