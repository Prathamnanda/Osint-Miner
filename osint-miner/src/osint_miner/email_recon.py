# src/osint_miner/email_recon.py
import re
import time
import requests
import urllib.parse
from collections import defaultdict
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from pathlib import Path

# optional PDF reader
try:
    from PyPDF2 import PdfReader
except Exception:
    PdfReader = None

USER_AGENT = "OSINT-Miner/1.0 (email-recon)"
HEADERS = {"User-Agent": USER_AGENT}
REQUEST_TIMEOUT = 10

EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+")
UDDG_RE = re.compile(r"uddg=([^&]+)")

# small helper that safely fetches HTML (verify=False to maximize reach; change if desired)
def _safe_get_text(url: str, timeout=REQUEST_TIMEOUT):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
        if r.status_code == 200:
            return r.text
    except Exception:
        return ""
    return ""

def _safe_get_bytes(url: str, timeout=REQUEST_TIMEOUT):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
        if r.status_code == 200:
            return r.content
    except Exception:
        return b""
    return b""

def _decode_duckduckgo_uddg(href: str):
    m = UDDG_RE.search(href)
    if m:
        return urllib.parse.unquote(m.group(1))
    return href

# --------------- crawl site for emails ---------------
def crawl_site_for_emails(domain: str, subdomains: list = None, max_pages: int = 200):
    """
    Crawl homepage, sitemap and shallow subdomains (if provided).
    Returns dict {email: [sources]}
    """
    found = defaultdict(set)
    seen = set()
    to_crawl = []
    seeds = [f"https://{domain}", f"http://{domain}"]
    if subdomains:
        for sd in subdomains[:50]:
            if sd and not sd.startswith("*"):
                seeds.append(f"https://{sd}")
                seeds.append(f"http://{sd}")
    to_crawl.extend(seeds)

    pages = 0
    while to_crawl and pages < max_pages:
        url = to_crawl.pop(0)
        if url in seen:
            continue
        seen.add(url)
        pages += 1
        text = _safe_get_text(url)
        if not text:
            continue
        # mailto links
        try:
            soup = BeautifulSoup(text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.lower().startswith("mailto:"):
                    m = href.split(":", 1)[1].split("?")[0].strip()
                    if EMAIL_RE.match(m):
                        found[m].add(f"mailto:{url}")
                # follow same-host shallow links (first-level)
                if href.startswith("/"):
                    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                    next_url = urljoin(base, href)
                    if next_url not in seen and next_url not in to_crawl and urlparse(next_url).netloc == urlparse(url).netloc:
                        to_crawl.append(next_url)
                elif href.startswith("http"):
                    # same host
                    if urlparse(href).netloc == urlparse(url).netloc and href not in seen:
                        if href not in to_crawl:
                            to_crawl.append(href)
        except Exception:
            pass

        # regex scan for emails in page html
        for m in EMAIL_RE.findall(text):
            # filter false positives (e.g., long domain strings)
            if len(m) > 4 and "@" in m:
                found[m].add(url)

        time.sleep(0.15)
    # return {email: list(sources)}
    return {e: sorted(list(sources)) for e, sources in found.items()}

# --------------- duckduckgo dork for emails ---------------
def duckduckgo_dork_emails(domain: str, queries: list = None, max_results: int = 20):
    """
    Use DuckDuckGo HTML results to look for email addresses related to the domain.
    """
    if queries is None:
        queries = [
            f'site:{domain} "@{domain}"',
            f'site:{domain} "{domain}" email',
            f'site:github.com "{domain}"',
            f'"@{domain}" -site:{domain}',  # external mentions
        ]
    found = defaultdict(set)
    base = "https://duckduckgo.com/html/"
    for q in queries:
        try:
            r = requests.get(base, params={"q": q}, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=False)
            if r.status_code != 200:
                continue
            text = r.text
            # decode uddg redirect links and find emails
            # find all anchors and decode uddg if present
            soup = BeautifulSoup(text, "lxml")
            anchors = soup.find_all("a", href=True)
            for a in anchors:
                href = a["href"]
                if "uddg=" in href:
                    href = _decode_duckduckgo_uddg(href)
                # pull emails from anchor text and href
                snippet = (a.get_text(" ") or "") + " " + (href or "")
                for m in EMAIL_RE.findall(snippet):
                    if m.endswith(domain) or ("@" + domain) in snippet:
                        found[m].add(f"ddg:{q}")
            # last fallback: scan page text
            for m in EMAIL_RE.findall(text):
                if m.endswith(domain):
                    found[m].add(f"ddg:{q}")
        except Exception:
            continue
        time.sleep(0.4)
    return {e: sorted(list(sources)) for e, sources in found.items()}

# --------------- PDF extraction ---------------
def extract_emails_from_pdfs(urls: list):
    """
    Given list of pdf URLs, download and extract emails.
    Returns {email: [pdf_url_sources]}
    """
    found = defaultdict(set)
    for u in urls:
        try:
            data = _safe_get_bytes(u)
            if not data:
                continue
            # if PdfReader available, get text
            if PdfReader:
                try:
                    from io import BytesIO
                    reader = PdfReader(BytesIO(data))
                    text = ""
                    for p in reader.pages:
                        try:
                            text += p.extract_text() or ""
                        except Exception:
                            continue
                    for m in EMAIL_RE.findall(text):
                        found[m].add(u)
                except Exception:
                    # fallback to regex on raw bytes
                    for m in EMAIL_RE.findall(data.decode("utf-8", errors="ignore")):
                        found[m].add(u)
            else:
                # fallback to regex on raw bytes
                for m in EMAIL_RE.findall(data.decode("utf-8", errors="ignore")):
                    found[m].add(u)
        except Exception:
            continue
        time.sleep(0.25)
    return {e: sorted(list(sources)) for e, sources in found.items()}

# --------------- helper to collect candidate pdf/doc links via dorks ---------------
def find_doc_links_via_dorks(domain: str, max_per_query: int = 20):
    """
    Use DuckDuckGo to find pdf/docx links on the domain.
    Returns list of candidate doc URLs (likely on the domain).
    """
    queries = [f"site:{domain} filetype:pdf", f"site:{domain} filetype:docx", f"site:{domain} filetype:doc"]
    out = set()
    base = "https://duckduckgo.com/html/"
    for q in queries:
        try:
            r = requests.get(base, params={"q": q}, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=False)
            if r.status_code != 200:
                continue
            soup = BeautifulSoup(r.text, "lxml")
            # look for ddg uddg links first
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if "uddg=" in href:
                    href = _decode_duckduckgo_uddg(href)
                if href.startswith("http") and (href.endswith(".pdf") or href.endswith(".docx") or href.endswith(".doc")):
                    out.add(href)
            # fallback: regex on page
            for u in re.findall(r"https?://[^\s'\"<>]+(?:\.pdf|\.docx|\.doc)", r.text):
                out.add(u)
        except Exception:
            pass
        time.sleep(0.4)
    return sorted(list(out))[:max_per_query]

# --------------- orchestration function ---------------
def find_emails(domain: str, subdomains: list = None, max_pages: int = 200):
    """
    Run multiple passive techniques and return aggregated emails dict:
    {email: {"sources": [...], "first_seen": "module"}}
    """
    aggregate = defaultdict(lambda: {"sources": set()})
    # 1) crawl site/pages
    try:
        crawl_res = crawl_site_for_emails(domain, subdomains=subdomains, max_pages=max_pages)
        for e, srcs in crawl_res.items():
            aggregate[e]["sources"].update(srcs)
            aggregate[e]["sources"].add("crawl_site")
    except Exception:
        pass

    # 2) ddg dorks
    try:
        ddg = duckduckgo_dork_emails(domain, max_results=20)
        for e, srcs in ddg.items():
            aggregate[e]["sources"].update(srcs)
            aggregate[e]["sources"].add("ddg_dorks")
    except Exception:
        pass

    # 3) find docs and parse them
    try:
        docs = find_doc_links_via_dorks(domain, max_per_query=30)
        pdf_res = extract_emails_from_pdfs(docs)
        for e, srcs in pdf_res.items():
            aggregate[e]["sources"].update(srcs)
            aggregate[e]["sources"].add("pdf_parse")
    except Exception:
        pass

    # 4) GitHub mentions via ddg
    try:
        gh_q = f'site:github.com "{domain}"'
        gh = duckduckgo_dork_emails(domain, queries=[gh_q], max_results=20)
        for e, srcs in gh.items():
            aggregate[e]["sources"].update(srcs)
            aggregate[e]["sources"].add("github_ddg")
    except Exception:
        pass

    # format aggregate into serializable dict
    out = {}
    for e, info in aggregate.items():
        out[e] = {"sources": sorted(list(info["sources"]))}
    return out

# quick run when executed directly
if __name__ == "__main__":
    import sys, pprint
    if len(sys.argv) < 2:
        print("Usage: python email_recon.py domain.tld [max_pages]")
        sys.exit(1)
    domain = sys.argv[1]
    max_pages = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    res = find_emails(domain, max_pages=max_pages)
    pprint.pprint(res)
                                                                                                                                                                                                                   
