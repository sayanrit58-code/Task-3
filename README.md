# Task-3
#!/usr/bin/env python3
import argparse
import socket
import requests
import subprocess
import sys
import threading
from queue import Queue
from urllib.parse import urlparse

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

# Banner
def show_banner():
    banner = f"""
{Colors.RED}
  _____           _      _____         _   
 |  __ \         | |    |_   _|       | |  
 | |__) |__  _ __| |_     | | ___  ___| |_ 
 |  ___/ _ \| '__| __|    | |/ _ \/ __| __|
 | |  | (_) | |  | |_    _| |  __/\__ \ |_ 
 |_|   \___/|_|   \__|   \___/\___||___/\__|
{Colors.END}
{Colors.BLUE}Python Penetration Testing Toolkit{Colors.END}
    """
    print(banner)

# Port Scanner Module
class PortScanner:
    def __init__(self, target, ports, threads=100):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.q = Queue()
        self.open_ports = []

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                self.open_ports.append(port)
                service = socket.getservbyport(port, 'tcp')
                print(f"{Colors.GREEN}[+] Port {port} ({service}) is open{Colors.END}")
            sock.close()
        except (socket.timeout, socket.error):
            pass

    def worker(self):
        while not self.q.empty():
            port = self.q.get()
            self.scan_port(port)
            self.q.task_done()

    def run_scan(self):
        print(f"\n{Colors.BLUE}[*] Scanning {self.target}...{Colors.END}")
        for port in self.ports:
            self.q.put(port)
        
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.start()
        
        self.q.join()
        
        if not self.open_ports:
            print(f"{Colors.YELLOW}[-] No open ports found{Colors.END}")
        else:
            print(f"\n{Colors.GREEN}[+] Scan completed. Open ports: {sorted(self.open_ports)}{Colors.END}")

# Directory Bruteforcer Module
class DirectoryBruteforcer:
    def __init__(self, url, wordlist, extensions=None):
        self.url = url if url.startswith('http') else f'http://{url}'
        self.wordlist = wordlist
        self.extensions = extensions or ['']
        self.found_dirs = []

    def check_url(self, path):
        try:
            full_url = f"{self.url}/{path}"
            r = requests.get(full_url, timeout=5)
            if r.status_code == 200:
                self.found_dirs.append(full_url)
                print(f"{Colors.GREEN}[+] Found: {full_url} (Status: {r.status_code}){Colors.END}")
            elif r.status_code in [301, 302, 307, 308]:
                print(f"{Colors.BLUE}[+] Found: {full_url} (Status: {r.status_code}) -> Redirects to: {r.headers['Location']}{Colors.END}")
        except requests.exceptions.RequestException:
            pass

    def run_bruteforce(self):
        print(f"\n{Colors.BLUE}[*] Bruteforcing directories on {self.url}...{Colors.END}")
        try:
            with open(self.wordlist, 'r') as f:
                words = f.read().splitlines()
        except FileNotFoundError:
            print(f"{Colors.RED}[-] Wordlist file not found{Colors.END}")
            return

        for word in words:
            for extension in self.extensions:
                path = f"{word}{extension}"
                self.check_url(path)
        
        if not self.found_dirs:
            print(f"{Colors.YELLOW}[-] No directories found{Colors.END}")
        else:
            print(f"\n{Colors.GREEN}[+] Bruteforce completed. Found {len(self.found_dirs)} directories.{Colors.END}")

# Vulnerability Scanner Module
class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url if url.startswith('http') else f'http://{url}'
        self.vulnerabilities = []

    def check_xss(self):
        test_payload = "<script>alert('XSS')</script>"
        try:
            r = requests.get(f"{self.url}/search?q={test_payload}")
            if test_payload in r.text:
                self.vulnerabilities.append('XSS')
                print(f"{Colors.RED}[!] Possible XSS vulnerability detected{Colors.END}")
        except requests.exceptions.RequestException:
            pass

    def check_sqli(self):
        test_payload = "' OR '1'='1"
        try:
            r = requests.get(f"{self.url}/search?q={test_payload}")
            if "error in your SQL syntax" in r.text.lower():
                self.vulnerabilities.append('SQLi')
                print(f"{Colors.RED}[!] Possible SQL Injection vulnerability detected{Colors.END}")
        except requests.exceptions.RequestException:
            pass

    def run_scan(self):
        print(f"\n{Colors.BLUE}[*] Scanning {self.url} for common vulnerabilities...{Colors.END}")
        self.check_xss()
        self.check_sqli()
        
        if not self.vulnerabilities:
            print(f"{Colors.GREEN}[+] No obvious vulnerabilities detected{Colors.END}")
        else
