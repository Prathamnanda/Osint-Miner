# -*- coding: utf-8 -*-
"""
Org recon module - passive OSINT without paid APIs.
Contains: whois, dns, crt.sh subdomains, tech fingerprint, github mentions (scraped),
bucket checks, job page checks, email permutations, passive takeover heuristics,
document discovery & metadata (PDF), crawl for emails/phones/social, duckduckgo dorks,
and IP/ASN info.

Note: Be polite (rate-limit). This is passive reconnaissance only.
"""
import re
import json
import time
from time import sleep
from collections import deque
from typing import List, Dict, Any, Set
from urllib.parse import urljoin, urlparse
from io import BytesIO
from pathlib import Path

import requests
import whois
import dns.resolver
from bs4 import BeautifulSoup

# Optional PDF parsing
try:
    from PyPDF2 import PdfReader
except Exception:
    PdfReader = None

USER_AGENT = "OSINT-Miner/1.0 (+https://example.com)"
HEADERS = {"User-Agent": USER_AGENT}
TIMEOUT = 8

# Basic regexes
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_RE = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{6,12}")
SOCIAL_DOMAINS = ["linkedin.com", "facebook.com", "instagram.com", "twitter.com", "x.com", "youtube.com", "t.me", "github.com", "stackoverflow.com"]

# ----------------- Utilities -----------------
def safe_get(url: str, **kwargs) -> requests.Response:
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, **kwargs)
        return r
    except Exception as e:
        raise

def slugify(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", (name or "").strip().lower())

# ----------------- WHOIS -----------------
def whois_lookup(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)
        out = {}
        for k, v in dict(w).items():
            try:
                out[k] = v if isinstance(v, (str, int, float)) else str(v)
            except Exception:
                out[k] = str(v)
        return {"result": out}
    except Exception as e:
        return {"error": str(e)}

# ----------------- DNS -----------------
def dns_lookup(domain: str) -> Dict[str, List[str]]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    resolver.timeout = 5
    types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    out = {}
    for t in types:
        try:
            answers = resolver.resolve(domain, t)
            out[t] = [str(rdata).strip() for rdata in answers]
        except Exception:
            out[t] = []
    return out

# ----------------- Subdomain enumeration via crt.sh -----------------
def crtsh_subdomains(domain: str) -> List[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = safe_get(url)
        if r.status_code != 200:
            return []
        data = r.json()
        names: Set[str] = set()
        for entry in data:
            for key in ("name_value", "common_name"):
                if key in entry and entry[key]:
                    raw = str(entry[key])
                    for n in raw.split("\n"):
                        n = n.strip()
                        if n and n.endswith(domain):
                            names.add(n)
        return sorted(names)
    except Exception:
        return []

# ----------------- Tech fingerprint (headers + HTML heuristics) -----------------
def tech_fingerprint(domain: str) -> Dict[str, Any]:
    results = {"headers": {}, "html_meta": {}, "scripts": [], "cookies": []}
    urls = [f"https://{domain}", f"http://{domain}"]
    for url in urls:
        try:
            r = safe_get(url, allow_redirects=True)
            results["headers"] = dict(r.headers)
            results["cookies"] = [c.name for c in r.cookies]
            text = r.text or ""
            soup = BeautifulSoup(text, "lxml")
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen and gen.get("content"):
                results["html_meta"]["generator"] = gen["content"]
            if soup.find("script", src=re.compile(r"react|preact|vue|angular", re.I)):
                results.setdefault("frameworks", []).append("JS Framework (likely React/Vue/Angular)")
            server = r.headers.get("Server")
            if server:
                results.setdefault("server", server)
            xpb = r.headers.get("X-Powered-By")
            if xpb:
                results.setdefault("x_powered_by", xpb)
            for s in soup.find_all("script", src=True):
                results["scripts"].append(s["src"])
            break
        except Exception:
            continue
    return results

# ----------------- GitHub mention search via DuckDuckGo scraping -----------------
def github_search_mentions(org_name: str, domain: str = None, max_hits: int = 20) -> List[str]:
    q = f"site:github.com \"{org_name}\""
    if domain:
        q += f" OR \"{domain}\""
    url = f"https://duckduckgo.com/html/?q={requests.utils.quote(q)}"
    out = []
    try:
        r = safe_get(url)
        soup = BeautifulSoup(r.text, "lxml")
        for a in soup.select("a.result__a")[:max_hits]:
            href = a.get("href")
            if href and "github.com" in href:
                out.append(href)
        # fallback parse other links
        if not out:
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if "github.com" in href:
                    out.append(href)
    except Exception:
        pass
    return sorted(list(dict.fromkeys(out)))[:max_hits]

# ----------------- Cloud bucket discovery (safe checks only) -----------------
COMMON_BUCKET_PATTERNS = [
    "{domain}",
    "www.{domain}",
    "{domain}-assets",
    "{domain}-static",
    "{domain}-files",
    "static-{domain}",
    "assets.{domain}",
]

def guess_bucket_hostnames(domain: str) -> List[str]:
    base = domain.split(".")[0]
    hosts = []
    for p in COMMON_BUCKET_PATTERNS:
        hosts.append(p.format(domain=domain, sub=base))
    return sorted(list(dict.fromkeys(hosts)))

def check_bucket_http(hostname):
    urls = [
        f"https://{hostname}.s3.amazonaws.com/",
        f"https://{hostname}-files.s3.amazonaws.com/",
        f"https://{hostname}-static.s3.amazonaws.com/",
        f"https://static-{hostname}.s3.amazonaws.com/",
        f"https://{hostname}.s3.amazonaws.com/",
    ]
    results = []
    for url in urls:
        try:
            r = requests.get(url, timeout=5, verify=False)  # 👈 disable SSL verify
            results.append({"url": url, "status": r.status_code})
        except Exception as e:
            results.append({"url": url, "error": str(e)[:200]})
    return results

# ----------------- Job postings / careers quick check -----------------
COMMON_CAREER_PATHS = ["/careers", "/jobs", "/join-us", "/careers/","/about/careers","/careers.html"]

def find_job_pages(domain: str) -> List[str]:
    out = []
    base = f"https://{domain}"
    for path in COMMON_CAREER_PATHS:
        url = urljoin(base, path)
        try:
            r = safe_get(url, allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 100:
                out.append(url)
            sleep(0.2)
        except Exception:
            continue
    base_http = f"http://{domain}"
    for path in COMMON_CAREER_PATHS:
        url = urljoin(base_http, path)
        try:
            r = safe_get(url, allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 100:
                out.append(url)
            sleep(0.2)
        except Exception:
            continue
    return sorted(list(dict.fromkeys(out)))

# ----------------- Email format guessing -----------------
def generate_email_permutations(name: str, domain: str, limit: int = 50) -> List[str]:
    parts = [p for p in re.split(r"[ ,]+", (name or "").strip()) if p]
    if not parts:
        return []
    first = parts[0].lower()
    last = parts[-1].lower() if len(parts) > 1 else ""
    mids = [p.lower() for p in parts[1:-1]] if len(parts) > 2 else []
    candidates = set()
    domain = domain.strip()
    candidates.add(f"{first}@{domain}")
    if last:
        candidates.add(f"{first}.{last}@{domain}")
        candidates.add(f"{first[0]}{last}@{domain}")
        candidates.add(f"{first}{last}@{domain}")
        candidates.add(f"{first}_{last}@{domain}")
        candidates.add(f"{first}-{last}@{domain}")
        candidates.add(f"{first}.{last[0]}@{domain}")
        candidates.add(f"{first[0]}.{last}@{domain}")
    for m in mids:
        candidates.add(f"{first}.{m}.{last}@{domain}")
    out = list(candidates)[:limit]
    return out

# ----------------- Subdomain takeover heuristic (passive) -----------------
KNOWN_TAKEOVER_TARGETS = [
    (r"herokuapp\.com", "No such app"),
    (r"amazonaws\.com", "NoSuchBucket"),
    (r"cloudfront\.net", "ERROR: The request could not be satisfied"),
    (r"azurewebsites\.net", "The resource you are looking for has been removed"),
    (r"github\.io", "There isn't a Github Pages site here"),
    (r"wpengine\.com", "No site configured at this address"),
]

def passive_takeover_checks(subdomains: List[str]) -> List[Dict[str, Any]]:
    out = []
    resolver = dns.resolver.Resolver()
    for sd in subdomains:
        entry = {"subdomain": sd, "cname": [], "http": None, "likely_vulnerable": False, "evidence": []}
        try:
            answers = resolver.resolve(sd, "CNAME", lifetime=5)
            cnames = [str(x.target).rstrip(".") for x in answers]
            entry["cname"] = cnames
        except Exception:
            entry["cname"] = []
        for scheme in ("https://", "http://"):
            url = scheme + sd
            try:
                r = safe_get(url, allow_redirects=True)
                entry["http"] = {"status": r.status_code, "len": len(r.content)}
                text = (r.text or "").lower()
                for pattern, signature in KNOWN_TAKEOVER_TARGETS:
                    for cname in entry["cname"]:
                        if re.search(pattern, cname):
                            if signature.lower() in text:
                                entry["likely_vulnerable"] = True
                                entry["evidence"].append({"url": url, "signature": signature})
                break
            except Exception:
                continue
        out.append(entry)
    return out

# ----------------- Document metadata (PDF) extraction -----------------
def find_and_extract_pdfs(domain: str, max_pages: int = 50) -> List[Dict[str, Any]]:
    discovered = []
    seen = set()
    seeds = [f"https://{domain}", f"http://{domain}"]
    checked = 0
    while seeds and checked < max_pages:
        url = seeds.pop(0)
        if url in seen:
            continue
        seen.add(url)
        checked += 1
        try:
            r = safe_get(url, allow_redirects=True)
            soup = BeautifulSoup(r.text or "", "lxml")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.lower().endswith(".pdf"):
                    pdf_url = urljoin(url, href)
                    if pdf_url in [d.get("url") for d in discovered]:
                        continue
                    meta = {"url": pdf_url}
                    try:
                        r2 = safe_get(pdf_url, stream=True)
                        content = r2.content
                        meta["http_status"] = r2.status_code
                        meta["size"] = len(content)
                        if PdfReader:
                            try:
                                reader = PdfReader(BytesIO(content))
                                info = reader.metadata or {}
                                meta["pdf_metadata"] = {k.replace("/", ""): str(v) for k, v in (info.items() if hasattr(info, "items") else [])}
                            except Exception as e:
                                meta["pdf_metadata"] = {"error": f"failed to parse PDF: {e}"}
                        else:
                            meta["pdf_metadata"] = {"error": "PyPDF2 not installed"}
                    except Exception as e:
                        meta["error"] = str(e)
                    discovered.append(meta)
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("/"):
                    parsed = urlparse(url)
                    seeds.append(parsed.scheme + "://" + parsed.netloc + href)
            sleep(0.1)
        except Exception:
            continue
    return discovered

# ----------------- Crawl for contacts, social links, docs -----------------

# ----------------- ASN/IP range via DNS resolution and whois on IP -----------------
def ip_and_asn_info(domain: str) -> Dict[str, Any]:
    info = {"resolved_ips": [], "asns": []}
    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [str(rdata) for rdata in answers]
        info["resolved_ips"] = ips
        for ip in ips:
            try:
                w = whois.whois(ip)
                info["asns"].append({ip: str(w)})
            except Exception:
                info["asns"].append({ip: "whois lookup failed"})
    except Exception:
        pass
    return info

# ----------------- Orchestration: run all org scans -----------------
def run_org_scan(name: str, domain: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"name": name, "domain": domain}
    try:
        out["whois"] = whois_lookup(domain)
    except Exception as e:
        out["whois"] = {"error": str(e)}
    try:
        out["dns"] = dns_lookup(domain)
    except Exception as e:
        out["dns"] = {"error": str(e)}
    try:
        out["subdomains"] = crtsh_subdomains(domain)
    except Exception as e:
        out["subdomains"] = []
    try:
        out["tech"] = tech_fingerprint(domain)
    except Exception as e:
        out["tech"] = {"error": str(e)}
    try:
        out["github_mentions"] = github_search_mentions(name, domain)
    except Exception as e:
        out["github_mentions"] = {"error": str(e)}
    try:
        bucket_hosts = guess_bucket_hostnames(domain)
        out["bucket_checks"] = [check_bucket_http(h) for h in bucket_hosts]
    except Exception as e:
        out["bucket_checks"] = {"error": str(e)}
    try:
        out["job_pages"] = find_job_pages(domain)
    except Exception as e:
        out["job_pages"] = {"error": str(e)}
    try:
        out["email_permutations"] = generate_email_permutations(name, domain)
    except Exception as e:
        out["email_permutations"] = {"error": str(e)}
    try:
        out["takeover_checks"] = passive_takeover_checks(out.get("subdomains", [])[:200])
    except Exception as e:
        out["takeover_checks"] = {"error": str(e)}
    try:
        out["documents"] = find_and_extract_pdfs(domain)
    except Exception as e:
        out["documents"] = {"error": str(e)}
    try:
        out["ip_asn"] = ip_and_asn_info(domain)
    except Exception as e:
        out["ip_asn"] = {"error": str(e)}
    # additional indexing/crawl and dorks
    try:
        out["crawl_contacts"] = crawl_for_contacts_and_docs(domain, out.get("subdomains", [])[:80], max_pages=200)
    except Exception as e:
        out["crawl_contacts"] = {"error": str(e)}
    try:
        out["dork_results"] = run_dorks(domain)
    except Exception as e:
        out["dork_results"] = {"error": str(e)}
    return out

# quick test when run directly
if __name__ == "__main__":
    import sys, pprint
    if len(sys.argv) < 3:
        print("Usage: python org_recon.py \"Org Name\" domain.tld")
        sys.exit(1)
    name = sys.argv[1]
    domain = sys.argv[2]
    result = run_org_scan(name, domain)
    pprint.pprint(result)
