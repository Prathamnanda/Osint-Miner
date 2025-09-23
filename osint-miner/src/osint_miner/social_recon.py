# src/osint_miner/social_recon.py
import re
import requests
from bs4 import BeautifulSoup
import warnings
import urllib.parse

# Suppress insecure-request warnings when verify=False is used
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Suppress XML-as-HTML parser warning (we'll try XML parser where possible)
from bs4 import XMLParsedAsHTMLWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

SOCIAL_PATTERNS = {
    "facebook": r"(https?://(?:www\.)?facebook\.com/[A-Za-z0-9\.\-_]+)",
    "instagram": r"(https?://(?:www\.)?instagram\.com/[A-Za-z0-9\.\-_]+)",
    "twitter": r"(https?://(?:www\.)?(?:x|twitter)\.com/[A-Za-z0-9\.\-_]+)",
    "linkedin": r"(https?://(?:[a-z]+\.)?linkedin\.com/(?:school|company|in)/[A-Za-z0-9\.\-_]+)",
    "youtube": r"(https?://(?:www\.)?youtube\.com/[A-Za-z0-9\.\-_\/]+)",
    "github": r"(https?://(?:www\.)?github\.com/[A-Za-z0-9\.\-_]+)",
}

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Miner/1.0)"}
REQUEST_TIMEOUT = 10

# helper: safe fetch (keeps verify=False for compatibility on some lab hosts,
# but we suppressed warnings above). If you prefer strict TLS, set verify=True.
def fetch_url(url: str) -> str:
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=False)
        if resp.status_code == 200 and resp.text:
            return resp.text
    except Exception:
        return ""
    return ""

# normalize and filter candidate social URLs
def _normalize_social_url(u: str) -> str:
    if not u:
        return ""
    # decode any URL encoding
    u = urllib.parse.unquote(u)
    # strip trailing slashes
    u = u.rstrip("/")
    # remove common tracking query params
    p = urllib.parse.urlparse(u)
    if not p.scheme or not p.netloc:
        return ""
    # rebuild without tracking query params
    q = urllib.parse.parse_qsl(p.query)
    qf = [(k, v) for k, v in q if k.lower() not in ("utm_source","utm_medium","utm_campaign","utm_term","utm_content","ref")]
    newq = urllib.parse.urlencode(qf)
    cleaned = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, p.params, newq, ""))
    # filter obviously truncated results (short paths like '/watch' or just domain-level)
    path = p.path or ""
    if len(path) <= 1:  # no useful path
        return ""
    # reject suspicious short last-path elements like 'tr' (facebook.com/tr)
    last = path.rstrip("/").split("/")[-1]
    if len(last) <= 2:
        return ""
    return cleaned

# run regexes and normalize matches
def extract_socials_from_text(text: str):
    results = {}
    for platform, pattern in SOCIAL_PATTERNS.items():
        matches = re.findall(pattern, text, flags=re.IGNORECASE)
        cleaned = []
        for m in matches:
            nm = _normalize_social_url(m)
            if nm:
                cleaned.append(nm)
        if cleaned:
            results[platform] = sorted(set(cleaned))
    return results

# try to parse sitemap.xml using an XML parser if available
def _parse_sitemap(xml_text: str):
    try:
        # prefer xml parser if lxml present
        soup = BeautifulSoup(xml_text, "xml")
        urls = [loc.get_text() for loc in soup.find_all("loc") if loc and loc.get_text()]
        return urls
    except Exception:
        return []

def crawl_domain(domain: str):
    urls_to_check = [
        f"https://{domain}/",
        f"http://{domain}/",
    ]
    # try sitemap and robots.txt as well
    sitemap_url = f"https://{domain}/sitemap.xml"
    robots_url = f"https://{domain}/robots.txt"
    found = {}

    # check homepage + http
    for url in urls_to_check:
        html = fetch_url(url)
        if not html:
            continue
        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(" ") + " " + html
        socials = extract_socials_from_text(text)
        for k, v in socials.items():
            found.setdefault(k, []).extend(v)

    # sitemap (parse as XML)
    sitemap_text = fetch_url(sitemap_url)
    if sitemap_text:
        urls = _parse_sitemap(sitemap_text)
        for u in urls:
            html = fetch_url(u)
            if not html:
                continue
            s = BeautifulSoup(html, "html.parser")
            text = s.get_text(" ") + " " + html
            socials = extract_socials_from_text(text)
            for k, v in socials.items():
                found.setdefault(k, []).extend(v)

    # robots: simple scan for social urls or sitemap links
    robots_text = fetch_url(robots_url)
    if robots_text:
        # robots may contain sitemap entries or direct URLs
        for line in robots_text.splitlines():
            if line.lower().startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                sm_html = fetch_url(sm)
                if sm_html:
                    urls = _parse_sitemap(sm_html)
                    for u in urls:
                        html = fetch_url(u)
                        if not html:
                            continue
                        s = BeautifulSoup(html, "html.parser")
                        text = s.get_text(" ") + " " + html
                        socials = extract_socials_from_text(text)
                        for k, v in socials.items():
                            found.setdefault(k, []).extend(v)
            else:
                # also run quick regex search in robots
                socials = extract_socials_from_text(line)
                for k, v in socials.items():
                    found.setdefault(k, []).extend(v)

    # dedupe & sort
    for k in list(found.keys()):
        found[k] = sorted(set(found[k]))
    return found

# decode DuckDuckGo uddg redirect links if present
def _decode_uddg_link(href: str) -> str:
    # examples: //duckduckgo.com/l/?uddg=<encoded>
    if "uddg=" in href:
        m = re.search(r"uddg=([^&]+)", href)
        if m:
            return urllib.parse.unquote(m.group(1))
    # direct /l/?uddg=...
    if href.startswith("/l/") or href.startswith("//duckduckgo.com/l/"):
        parsed = urllib.parse.urlparse(href)
        q = urllib.parse.parse_qs(parsed.query)
        if "uddg" in q and q["uddg"]:
            return urllib.parse.unquote(q["uddg"][0])
    return href

def social_recon(name: str, domain: str):
    out = {"domain": domain, "name": name, "socials": {}}

    # Crawl homepage/robots/sitemap
    out["socials"].update(crawl_domain(domain))

    # DuckDuckGo dorks (fallback)
    dork_queries = [
        f"site:{domain} facebook.com",
        f"site:{domain} instagram.com",
        f"site:{domain} linkedin.com",
        f"site:{domain} twitter.com",
        f"site:{domain} github.com",
        f"{name} official LinkedIn",
        f"{name} github",
    ]
    ddg_results = {}
    for q in dork_queries:
        try:
            r = requests.get("https://duckduckgo.com/html/", params={"q": q}, headers=HEADERS, timeout=REQUEST_TIMEOUT, verify=False)
            if r.status_code == 200:
                # look for result links including uddg redirects
                soup = BeautifulSoup(r.text, "lxml")
                # preferred anchors
                anchors = soup.select("a.result__a") or soup.find_all("a", href=True)
                for a in anchors:
                    href = a.get("href") or ""
                    if href:
                        decoded = _decode_uddg_link(href)
                        # also find any http(s) URLs inside the anchor/html
                        if decoded.startswith("/l/") or "uddg=" in decoded:
                            decoded = _decode_uddg_link(decoded)
                        # normalize & extract socials from anchor HTML/text too
                        snippet = ""
                        try:
                            snippet = a.get_text(" ") + " " + (a.get("href") or "")
                        except Exception:
                            snippet = a.get("href") or ""
                        # extract socials both from decoded href and snippet
                        candidates = [decoded, snippet]
                        for cand in candidates:
                            socials = extract_socials_from_text(cand)
                            for k, v in socials.items():
                                ddg_results.setdefault(k, []).extend(v)
        except Exception:
            continue

    # merge ddg results into out
    for k, v in ddg_results.items():
        out["socials"].setdefault(k, []).extend(v)

    # final dedupe + normalize
    for k in list(out["socials"].keys()):
        cleaned = []
        for u in out["socials"][k]:
            nu = _normalize_social_url(u)
            if nu:
                cleaned.append(nu)
        out["socials"][k] = sorted(set(cleaned))

    return out

if __name__ == "__main__":
    import sys, pprint
    if len(sys.argv) < 3:
        print("Usage: python social_recon.py \"Org Name\" domain.tld")
        sys.exit(1)
    name = sys.argv[1]
    domain = sys.argv[2]
    result = social_recon(name, domain)
    pprint.pprint(result)
