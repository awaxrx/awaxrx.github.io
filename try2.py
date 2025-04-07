import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import socket
import time

visited = set()
wildcard_paths = [
    "/vuln2", "/bugz", "/test", "/iframe", "/inject", "/404", "/payload"
]
base_domain = "https://aws.amazon.com"
scan_depth = 2
loop_delay = 15  # seconds between loops

# Patterns to extract
ipv4_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
ipv6_pattern = r"\b(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+\b"
domain_pattern = r"\b(?:[\w\.-]+\.)?amazon\.com\b"
api_pattern = r"\b\/(api|v1|v2|ajax|console)[\w\/\-\._]*"

headers = {
    "User-Agent": "BigHomieRecon/6.0",
    "Accept": "*/*"
}

def resolve_dns(domain):
    try:
        result = socket.gethostbyname(domain)
        print(f"  [DNS] {domain} resolves to {result}")
    except:
        print(f"  [DNS] Failed to resolve: {domain}")

def extract_targets(content, url):
    ipv4s = re.findall(ipv4_pattern, content)
    ipv6s = re.findall(ipv6_pattern, content)
    domains = re.findall(domain_pattern, content)
    apis = re.findall(api_pattern, content)

    if ipv4s or ipv6s or domains or apis:
        print(f"\n[!] Extracted from {url}")
        if ipv4s: print("  IPv4:", set(ipv4s))
        if ipv6s: print("  IPv6:", set(ipv6s))
        if domains:
            print("  Domains:", set(domains))
            for d in set(domains):
                resolve_dns(d)
        if apis: print("  API Paths:", set(apis))

def spider(url, depth):
    if url in visited or depth == 0:
        return
    visited.add(url)
    print(f"\n[+] Crawling: {url}")
    try:
        r = requests.get(url, headers=headers, timeout=10)
        content = r.text
        extract_targets(content, url)

        soup = BeautifulSoup(content, "html.parser")
        for link in soup.find_all("a", href=True):
            next_url = urljoin(url, link['href'])
            if base_domain in next_url:
                spider(next_url, depth - 1)
    except Exception as e:
        print(f"[x] Error on {url}: {e}")

def run_loop():
    while True:
        print(f"\n--- New Loop at {time.ctime()} ---")
        for path in wildcard_paths:
            full_url = f"{base_domain}{path}"
            spider(full_url, scan_depth)
        print(f"\n[~] Sleeping {loop_delay}s before next loop...\n")
        time.sleep(loop_delay)

if __name__ == "__main__":
    run_loop()
