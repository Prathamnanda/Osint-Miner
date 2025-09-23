# src/osint_miner/phone_recon.py
"""
phone_recon.py
--------------
Harvest phone numbers from a target domain.
Similar style to email_recon.py but focused on phone numbers.

Functions:
    - find_phones(domain, max_pages=200) -> dict
        Crawl the domain, extract phone numbers, return JSON-like dict.
"""

import re
import time
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import defaultdict

USER_AGENT = "OSINT-Miner/1.0 (phone-recon)"
HEADERS = {"User-Agent": USER_AGENT}
REQUEST_TIMEOUT = 10

# Regex for phone numbers (international + local formats)
PHONE_RE = re.compile(
    r"""
    (?:
      (?:\+?\d{1,3}[\s\-\.\)]*)?          # optional country code like +1, +91
      (?:\(?\d{2,4}\)?[\s\-\.\)]*)?      # optional area code (2-4 digits)
      (?:\d{3,4}[\s\-\.\)]*){1,3}        # main number (groups of 3-4 digits)
    )
    """,
    re.VERBOSE,
)

def _normalize_phone(s: str) -> str:
    """Normalize phone string by trimming and cleaning."""
    s = s.strip()
    s = re.sub(r"\s+", " ", s)
    s = s.strip(".,;:()[]")
    return s

def extract_phones_from_text(text: str):
    """Extract phones from raw text."""
    phones = set()
    for match in PHONE_RE.findall(text or ""):
        ph = _normalize_phone(match)
        digits = re.sub(r"\D", "", ph)
        if len(digits) >= 6 and len(digits) <= 15:
            phones.add(ph)
    return phones

def _safe_fetch(url: str):
    try:
        r = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=False)
        if r.status_code == 200:
            return r.text
    except Exception:
        return ""
    return ""

def _extract_links(domain: str, html: str):
    """Extract internal links from HTML."""
    links = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
        base = f"https://{domain}"
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith("/"):
                links.add(urljoin(base, href))
            elif href.startswith("http"):
                if urlparse(href).netloc.endswith(domain):
                    links.add(href.split("#")[0])
    except Exception:
        pass
    return links

def find_phones(domain: str, max_pages: int = 200):
    """
    Crawl domain pages to extract phone numbers.
    Returns:
        dict: { "phone": {"sources": [urls]} }
    """
    seeds = [f"https://{domain}", f"http://{domain}"]
    seen = set()
    to_crawl = list(seeds)
    results = defaultdict(lambda: {"sources": set()})

    while to_crawl and len(seen) < max_pages:
        url = to_crawl.pop(0)
        if url in seen:
            continue
        seen.add(url)

        html = _safe_fetch(url)
        if not html:
            continue

        phones = extract_phones_from_text(html)
        for ph in phones:
            results[ph]["sources"].add(url)

        # add new links
        for link in _extract_links(domain, html):
            if link not in seen and len(seen) + len(to_crawl) < max_pages:
                to_crawl.append(link)

        time.sleep(0.12)  # politeness

    # convert sets -> lists
    return {ph: {"sources": sorted(info["sources"])} for ph, info in results.items()}


# CLI usage for testing
if __name__ == "__main__":
    import argparse, json
    p = argparse.ArgumentParser(description="Phone recon: harvest phone numbers from a domain")
    p.add_argument("domain", help="Domain to scan (example.com)")
    p.add_argument("--max-pages", type=int, default=200, help="Maximum pages to crawl")
    args = p.parse_args()

    res = find_phones(args.domain, max_pages=args.max_pages)
    print(json.dumps(res, indent=2))
