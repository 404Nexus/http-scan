#!/usr/bin/env python3

import argparse, socket, ipaddress, threading, requests
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

COMMON_PATHS = ["/", "/admin", "/login", "/robots.txt"]
VULN_SIGNATURES = ["Apache/2.2.3", "PHP/5.2", "nginx/1.4", "IIS/6.0"]

def scan_http(host, ports, verbose=False, save_file=None):
    for port in ports:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{host}:{port}"
        try:
            r = requests.get(url, timeout=5, verify=False)
            banner = r.headers.get("Server", "Unknown")
            title = extract_title(r.text)

            if verbose:
                print(f"[+] {url} - {banner} - Title: {title}")
            else:
                print(f"[+] {url} - OPEN")

            if any(sig in banner for sig in VULN_SIGNATURES):
                print(f"[!] {url} - Vulnerable HTTP Server Detected: {banner}")

            for path in COMMON_PATHS:
                full_url = f"{url}{path}"
                resp = requests.get(full_url, timeout=5, verify=False)
                if resp.status_code == 200:
                    print(f"    └─ Found: {full_url} (200 OK)")
                    if save_file:
                        with open(save_file, "a") as f:
                            f.write(f"{full_url} - 200 OK\n")

        except requests.RequestException:
            if verbose:
                print(f"[-] {url} - Unreachable or Error")

def extract_title(html):
    start = html.find("<title>")
    end = html.find("</title>")
    if start != -1 and end != -1:
        return html[start+7:end].strip()
    return "No Title"

def parse_targets(target):
    targets = []
    try:
        if "/" in target:
            net = ipaddress.IPv4Network(target, strict=False)
            targets = [str(ip) for ip in net.hosts()]
        else:
            targets = [target]
    except:
        print("[-] Invalid target format")
    return targets

def main():
    parser = argparse.ArgumentParser(description="HTTP VAPT Scanner - by Kuldeep (2025)")
    parser.add_argument("-t", "--target", help="Target IP or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("-d", "--domain", help="Target domain name (e.g., example.com)")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[80, 443], help="Ports to scan (default: 80 443)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", help="Save found paths to file")
    args = parser.parse_args()

    if not args.target and not args.domain:
        parser.error("Please specify either --target (IP) or --domain (hostname)")

    targets = [args.domain] if args.domain else parse_targets(args.target)

    start = datetime.now()
    print(f"[*] HTTP scan started at {start.strftime('%H:%M:%S')}")

    for host in targets:
        thread = threading.Thread(target=scan_http, args=(host, args.ports, args.verbose, args.output))
        thread.start()


if __name__ == "__main__":
    main()
