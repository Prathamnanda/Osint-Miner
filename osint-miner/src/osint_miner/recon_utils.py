# src/osint_miner/recon_utils.py
import re
import socket
import requests
import urllib.parse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
import warnings
from urllib3.exceptions import InsecureRequestWarning

# suppress noisy SSL warnings when verify=False
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

HEADERS = {"User-Agent": "OSINT-Miner/1.0 (recon-utils)"}
REQUEST_TIMEOUT = 8


# -----------------------
# Robots.txt & Sitemap
# -----------------------
def fetch_url_text(url: str, timeout: int = REQUEST_TIMEOUT) -> str:
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
        if r.status_code == 200:
            return r.text
    except Exception:
        return ""
    return ""


def parse_robots(robots_text: str) -> Dict[str, List[str]]:
    """
    Parse robots.txt text and return dict with lines of interest:
    - sitemap: list of sitemap URLs
    - disallow: list of disallow patterns
    - allow: list of allow patterns
    """
    res = {"sitemap": [], "disallow": [], "allow": [], "other": []}
    if not robots_text:
        return res
    for line in robots_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith("sitemap:"):
            res["sitemap"].append(line.split(":", 1)[1].strip())
        elif lower.startswith("disallow:"):
            res["disallow"].append(line.split(":", 1)[1].strip())
        elif lower.startswith("allow:"):
            res["allow"].append(line.split(":", 1)[1].strip())
        else:
            res["other"].append(line)
    return res


def parse_sitemap_xml(xml_text: str) -> List[str]:
    """
    Parse sitemap XML for <loc> entries. Returns list of URLs.
    """
    urls = []
    if not xml_text:
        return urls
    # prefer XML parser; BeautifulSoup will use xml parser if installed
    try:
        soup = BeautifulSoup(xml_text, "xml")
        locs = soup.find_all("loc")
        for l in locs:
            if l and l.string:
                urls.append(l.string.strip())
    except Exception:
        # fallback: regex
        urls.extend(re.findall(r"<loc>(https?://[^<]+)</loc>", xml_text, flags=re.IGNORECASE))
    return urls


def robots_and_sitemaps(domain: str) -> Dict[str, Any]:
    """
    Fetch robots.txt and sitemap.xml (if referenced) and return parsed info:
    { robots_text, robots_parsed, sitemap_urls, sitemap_index_urls, sitemap_pages_sample }
    """
    out = {}
    base = f"https://{domain}"
    robots_url = urllib.parse.urljoin(base, "/robots.txt")
    sitemap_url = urllib.parse.urljoin(base, "/sitemap.xml")

    robots_text = fetch_url_text(robots_url)
    out["robots_url"] = robots_url
    out["robots_text_present"] = bool(robots_text)
    out["robots_parsed"] = parse_robots(robots_text)

    # sitemaps from robots.txt first
    sitemaps = out["robots_parsed"].get("sitemap", [])[:10]

    # fallback: try common sitemap location
    if not sitemaps:
        sm = fetch_url_text(sitemap_url)
        if sm:
            sitemaps = [sitemap_url]

    out["sitemap_urls"] = sitemaps

    # fetch first sitemap and parse locs (sample)
    sitemap_pages = []
    if sitemaps:
        try:
            sm_text = fetch_url_text(sitemaps[0])
            sitemap_pages = parse_sitemap_xml(sm_text)[:200]  # sample up to 200
        except Exception:
            sitemap_pages = []
    out["sitemap_pages_sample"] = sitemap_pages
    return out


# -----------------------
# Open Directory Finder
# -----------------------
COMMON_DIR_INDICATORS = [
    "Index of /", "<title>Index of", "Directory listing for", "Parent Directory",
]

COMMON_FILES = [
    ".env", "config.php", "wp-config.php", "backup.zip", "backup.tar.gz", "db.sql", "database.sql",
    "credentials.txt", "id_rsa", "id_rsa.pub", "passwords.txt", ".git/config", ".gitignore"
]


def is_directory_listing(html: str) -> bool:
    if not html:
        return False
    for indicator in COMMON_DIR_INDICATORS:
        if indicator.lower() in html.lower():
            return True
    # also if there is a typical file-list table
    if re.search(r"<a\s+href=[\"']\?C=N;O=D[\"']|<a\s+href=[\"'][^\"']+[\"]/\">", html, flags=re.IGNORECASE):
        return True
    return False


def check_open_directory(url: str) -> Dict[str, Any]:
    """
    Try GET on a path; returns {url, status, listing: bool, findings: [files], snippet}
    """
    try:
        txt = fetch_url_text(url)
        if not txt:
            return {"url": url, "status": None, "listing": False, "findings": [], "snippet": ""}
        listing = is_directory_listing(txt)
        findings = []
        # look for common filenames
        for fn in COMMON_FILES:
            if fn.lower() in txt.lower():
                findings.append(fn)
        # also extract obvious links to files
        links = re.findall(r'href=[\'"]([^\'"]+\.(?:zip|tar\.gz|sql|env|conf|txt|bak|php))[\'"]', txt, flags=re.IGNORECASE)
        for l in links:
            findings.append(l)
        snippet = txt[:800]
        return {"url": url, "status": 200, "listing": listing, "findings": sorted(set(findings)), "snippet": snippet}
    except Exception as e:
        return {"url": url, "status": "error", "err": str(e), "listing": False, "findings": [], "snippet": ""}


def find_open_directories(domain: str, paths: List[str] = None, max_checks: int = 40) -> List[Dict[str, Any]]:
    """
    Check a list of common paths on the domain for open directory listings / exposed files.
    - paths: optional list of custom paths (like ['/uploads/', '/files/'])
    """
    base = f"https://{domain.rstrip('/')}"
    if paths is None:
        paths = [
            "/", "/uploads/", "/files/", "/backup/", "/backups/", "/download/", "/downloads/",
            "/wp-content/uploads/", "/static/", "/public/", "/assets/", "/uploads/2024/"
        ]
    # limit checks
    checks = [urllib.parse.urljoin(base, p) for p in paths][:max_checks]
    results = []
    for url in checks:
        results.append(check_open_directory(url))
    return results


# -----------------------
# Lightweight TCP Port Scanner
# -----------------------
DEFAULT_PORTS = [21, 22, 25, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 9200, 8080, 8443]


def _scan_port(host: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        try:
            banner = s.recv(1024).decode(errors="ignore").strip()
        except Exception:
            banner = ""
        s.close()
        return {"port": port, "open": True, "banner": banner}
    except Exception:
        try:
            s.close()
        finally:
            return {"port": port, "open": False, "banner": ""}


def scan_ports(host: str, ports: List[int] = None, max_workers: int = 40, timeout: float = 1.0) -> List[Dict[str, Any]]:
    """
    Lightweight TCP port scanner using ThreadPoolExecutor.
    - host: hostname or IP
    - ports: list of ints (default DEFAULT_PORTS)
    - max_workers: concurrency
    - timeout: per-connection timeout (seconds)
    Returns list of {port, open, banner}
    """
    if ports is None:
        ports = DEFAULT_PORTS
    results = []
    # resolve host to IP (socket.gethostbyname may raise)
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as ex:
        futures = {ex.submit(_scan_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                results.append({"port": futures[fut], "open": False, "banner": ""})
    # sort by port
    results = sorted(results, key=lambda x: x["port"])
    return results
