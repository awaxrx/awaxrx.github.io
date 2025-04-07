import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

visited = set()
max_depth = 2

# Wildcard paths to start from
base_urls = [
    "https://aws.amazon.com/vuln2",
    "https://aws.amazon.com/bugz",
    "https://aws.amazon.com/inject",
    "https://aws.amazon.com/testme"
]

trigger_keywords = [
    "awaxrx.github.io",
    "iframe",
    "payload",
    "Recursive Recon",
    "cloudfront.net",
    "frontier.amazon.com",
    "fls-na.amazon.com",
    "iot-console-onebox",
    "2600:9000",
    "205.251"
]

headers = {
    "User-Agent": "BigHomieRon-SpiderLite/1.0",
    "Accept": "*/*"
}

def spider(url, depth):
    if url in visited or depth == 0:
        return
    visited.add(url)
    print(f"[+] Crawling: {url}")
    try:
        r = requests.get(url, headers=headers, timeout=10)
        content = r.text

        for keyword in trigger_keywords:
            if keyword.lower() in content.lower():
                print(f"[!] Found '{keyword}' at {url}")

        soup = BeautifulSoup(content, "html.parser")
        for link in soup.find_all("a", href=True):
            next_url = urljoin(url, link['href'])
            # Keep it within aws.amazon.com
            if "aws.amazon.com" in next_url and urlparse(next_url).netloc.endswith("aws.amazon.com"):
                spider(next_url, depth - 1)

    except Exception as e:
        print(f"[x] Error: {e} on {url}")

if __name__ == "__main__":
    for start_url in base_urls:
        spider(start_url, max_depth)
