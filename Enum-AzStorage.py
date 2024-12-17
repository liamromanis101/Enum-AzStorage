import socket
import requests
import re
import json
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict
import ipaddress
import urllib3
# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Constants
COMMON_PORTS = {
    "http": [80, 8080],
    "https": [443, 8443],
    "smb": [445],
    "ssh": [22],
    "mysql": [3306],
    "postgresql": [5432],
    "mssql": [1433],
    "redis": [6379],
    "elasticsearch": [9200],
    "ftp": [21]
    }
INVALID_CREDENTIALS = ("invaliduser", "invalidpassword")
AZURE_STORAGE_REGEX = r"(blob|file|queue|table)\.core\.windows\.net"
# Function to validate IP
def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
# Reverse DNS lookup
def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "No PTR record"
# Port scanning
def scan_ports(ip: str) -> Dict[str, List[int]]:
    open_ports = {key: [] for key in COMMON_PORTS}
    for service, ports in COMMON_PORTS.items():
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    open_ports[service].append(port)
    return open_ports
# Inspect HTTP(S) for Azure-specific storage
def inspect_http(ip: str, port: int) -> Dict:
    url = f"http://{ip}" if port in [80, 8080] else f"https://{ip}"
    try:
        response = requests.get(url, timeout=3, verify=False)
        headers = response.headers
        azure_headers = {k: v for k, v in headers.items() if k.lower().startswith("x-ms-")}
        server_header = headers.get("Server", "")
        azure_storage_match = re.search(AZURE_STORAGE_REGEX, server_header, re.IGNORECASE)
        service_type = None
        if "Windows-Azure-Blob" in server_header:
            service_type = "Blob Storage"
        elif "Windows-Azure-Queue" in server_header:
            service_type = "Queue Storage"
        elif "Windows-Azure-Table" in server_header:
            service_type = "Table Storage"
        return {
            "port": port,
            "status_code": response.status_code,
            "headers": dict(headers),
            "azure_headers": azure_headers,
            "service_type": service_type
        }
    except requests.RequestException as e:
        return {"port": port, "error": str(e)}
# Service-specific checks
def check_service(ip: str, port: int, service: str) -> Dict:
    try:
        with socket.create_connection((ip, port), timeout=3) as s:
            if service == "ssh":
                banner = s.recv(1024).decode("utf-8", errors="ignore")
                return {"service": "SSH", "banner": banner.strip()}
            elif service == "mysql":
                banner = s.recv(1024).decode("utf-8", errors="ignore")
                return {"service": "MySQL", "banner": banner.strip()}
            elif service == "postgresql":
                s.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")  # Minimal PostgreSQL packet
                response = s.recv(1024).decode("utf-8", errors="ignore")
                return {"service": "PostgreSQL", "response": response.strip()}
            elif service == "ftp":
                banner = s.recv(1024).decode("utf-8", errors="ignore")
                return {"service": "FTP", "banner": banner.strip()}
            elif service == "redis":
                s.sendall(b"PING\r\n")
                response = s.recv(1024).decode("utf-8", errors="ignore")
                return {"service": "Redis", "response": response.strip()}
            elif service == "elasticsearch":
                s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                response = s.recv(1024).decode("utf-8", errors="ignore")
                return {"service": "Elasticsearch", "response": response.strip()}
    except Exception as e:
        return {"service": service, "error": str(e)}
# Analyze a single IP
def analyze_ip(ip: str) -> Dict:
    if not validate_ip(ip):
        return {"ip": ip, "error": "Invalid IP address"}
    result = {
        "ip": ip,
        "reverse_dns": reverse_dns(ip),
        "ports": {},
        "http_results": [],
        "service_checks": []
    }
    # Scan ports
    open_ports = scan_ports(ip)
    result["ports"] = open_ports
    # HTTP(S) checks
    for port in open_ports.get("http", []) + open_ports.get("https", []):
        result["http_results"].append(inspect_http(ip, port))
    # Service checks
    for service, ports in open_ports.items():
        for port in ports:
            if service in ["ssh", "mysql", "postgresql", "ftp", "redis", "elasticsearch"]:
                result["service_checks"].append(check_service(ip, port, service))
    return result
# Main function
def main(input_file: str, output_file: str):
    with open(input_file, "r") as f:
        ips = [line.strip() for line in f if line.strip()]
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for result in executor.map(analyze_ip, ips):
            results.append(result)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Azure and Service Enumerator")
    parser.add_argument("input_file", help="Path to the file containing IP addresses.")
    parser.add_argument("output_file", help="Path to save the output in JSON format.")
    args = parser.parse_args()
    main(args.input_file, args.output_file)
