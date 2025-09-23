# src/osint_miner/vuln_recon.py
"""
Lightweight vuln_recon for OSINT-Miner (fixed duplicates + configurable nmap timeout).

Features:
- optional nmap service scan (configurable timeout)
- HTTP/HTTPS fetch + per-URL fingerprinting (CMS, JS libs, meta generator)
- TLS handshake probe for multiple TLS versions
- local heuristics to flag potentially outdated components (no external APIs)
- returns ONE clean report with:
    - 'nmap_raw' (or "skipped" / error)
    - 'services' (parsed)
    - 'http' (per-url dict)
    - 'fingerprint' (combined summary)
    - 'tls'
    - 'local_checks'
- CLI helper: supports --no-nmap
"""
from __future__ import annotations
import subprocess
import shutil
import re
import socket
import ssl
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

NMAP_CMD = shutil.which("nmap")

# Regex helpers
VERSION_RE = re.compile(r"([0-9]+(?:\.[0-9]+)+)")
LIB_INLINE_VER_RE = re.compile(
    r"(jquery|bootstrap|vue|react|angular)[^\d\n\r]{0,20}v?([0-9]+(?:\.[0-9]+)+)",
    re.I,
)


def version_lt(a: str, b: str) -> bool:
    """Return True if version a < b (simple numeric comparison)."""
    def parts(x):
        return [int(p) for p in re.findall(r"\d+", x)]
    pa = parts(a)
    pb = parts(b)
    for i in range(max(len(pa), len(pb))):
        ai = pa[i] if i < len(pa) else 0
        bi = pb[i] if i < len(pb) else 0
        if ai < bi:
            return True
        if ai > bi:
            return False
    return False


def run_nmap(target: str, ports: str = "-p- -sV -T4 --version-intensity 2", timeout: int = 360) -> str:
    """Run nmap and return stdout. If nmap isn't installed returns 'nmap-not-found'."""
    if not NMAP_CMD:
        return "nmap-not-found"
    cmd = [NMAP_CMD] + ports.split() + [target]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return f"nmap-run-error: timed out after {timeout} seconds"
    except subprocess.CalledProcessError as e:
        return e.output.decode("utf-8", errors="replace")
    except Exception as e:
        return f"nmap-run-error: {e}"


def parse_nmap_services(nmap_text: str) -> List[Dict[str, Any]]:
    """Best-effort parse of nmap -sV output for open TCP services."""
    services: List[Dict[str, Any]] = []
    if not nmap_text:
        return services
    for ln in nmap_text.splitlines():
        ln = ln.strip()
        m = re.match(r"^(\d+)\/tcp\s+open\s+([^\s]+)\s*(.*)$", ln)
        if m:
            port = int(m.group(1))
            svc = m.group(2)
            rest = m.group(3).strip()
            ver = None
            vm = VERSION_RE.search(rest)
            if vm:
                ver = vm.group(0)
            services.append({"port": port, "service": svc, "raw": rest, "version": ver})
    return services


def fingerprint_html(html: str) -> Dict[str, Any]:
    """Return fingerprint dict with cms list, js_libs map and meta generator."""
    soup = BeautifulSoup(html or "", "html.parser")
    fp = {"cms": [], "js_libs": {}, "meta_generator": None}

    # meta generator tag
    mg = soup.find("meta", attrs={"name": "generator"})
    if mg and mg.get("content"):
        fp["meta_generator"] = mg.get("content").strip()

    text = (html or "").lower()
    # CMS heuristics
    if "wp-content" in text or "wordpress" in text:
        if "WordPress" not in fp["cms"]:
            fp["cms"].append("WordPress")
    if "/sites/default" in text or "drupal" in text:
        if "Drupal" not in fp["cms"]:
            fp["cms"].append("Drupal")
    if "joomla" in text or "content/joomla" in text:
        if "Joomla" not in fp["cms"]:
            fp["cms"].append("Joomla")
    if "shopify" in text or "cdn.shopify.com" in text:
        if "Shopify" not in fp["cms"]:
            fp["cms"].append("Shopify")
    if "django" in text:
        if "Django" not in fp["cms"]:
            fp["cms"].append("Django")

    # script src detection (try to extract version numbers)
    for s in soup.find_all("script", src=True):
        src = s.get("src", "")
        # look for X.Y.Z pattern in src
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", src)
        name = src.split("/")[-1].split("?")[0]
        if m:
            fp["js_libs"].setdefault(name or src, m.group(1))
        else:
            # try to capture name-only libs like jquery.js (no version) - mark as present
            fp["js_libs"].setdefault(name or src, "unknown")

    # inline lib comments (jquery vX.Y.Z)
    for m in LIB_INLINE_VER_RE.finditer(html or ""):
        name = m.group(1).lower()
        ver = m.group(2)
        fp["js_libs"].setdefault(name, ver)

    return fp


def fetch_http_pages(host: str, ports_to_try: Tuple[int, ...] = (80, 443), timeout: int = 12) -> Dict[str, Any]:
    """
    Fetch pages for host at the provided ports.
    Returns dict keyed by URL with either {'status_code', 'headers', 'fingerprint'} or {'error': '...'}.
    """
    out: Dict[str, Any] = {}
    session = requests.Session()
    session.headers.update({"User-Agent": "OSINT-Miner/1.0 (vuln_recon)"})
    # ensure uniqueness & canonical order (http then https if both)
    tried_urls = []
    for port in ports_to_try:
        proto = "https" if port == 443 else "http"
        url = f"{proto}://{host}"
        if url in tried_urls:
            continue
        tried_urls.append(url)
        try:
            r = session.get(url, timeout=timeout, verify=False)
            html = r.text or ""
            headers = dict(r.headers)
            fp = fingerprint_html(html)
            out[url] = {"status_code": r.status_code, "headers": headers, "fingerprint": fp}
        except requests.exceptions.SSLError as e:
            out[url] = {"error": f"ssl-error: {e}"}
        except requests.exceptions.RequestException as e:
            out[url] = {"error": f"request-error: {e}"}
    return out


def probe_tls_versions(host: str, port: int = 443, timeout: int = 6) -> Dict[str, Any]:
    """Attempt TLS handshake with a few different contexts and return results."""
    results = {"supported": [], "cert": None, "error": None}
    proto_map = {}
    # Build contexts if available
    if hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
        # selectively add contexts for older names if present
        if hasattr(ssl, "PROTOCOL_TLSv1"):
            proto_map["TLSv1"] = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        if hasattr(ssl, "PROTOCOL_TLSv1_1"):
            proto_map["TLSv1_1"] = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
        if hasattr(ssl, "PROTOCOL_TLSv1_2"):
            proto_map["TLSv1_2"] = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        proto_map["TLS"] = ssl.create_default_context()
    else:
        proto_map["TLS"] = ssl.create_default_context()

    for name, ctx in proto_map.items():
        if ctx is None:
            continue
        try:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    results["supported"].append({"proto": name, "cipher": cipher})
                    if results["cert"] is None:
                        results["cert"] = ssock.getpeercert()
        except Exception:
            continue

    if not results["supported"]:
        results["error"] = "no-tls-handshake"
    return results


def local_vuln_checks(fingerprint: Dict[str, Any], services: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Simple local heuristics to flag possibly outdated components."""
    notes = []
    js = fingerprint.get("js_libs", {})
    jq = js.get("jquery")
    # heuristics: outdated jquery
    if jq and jq != "unknown":
        try:
            if version_lt(str(jq), "3.5.0"):
                notes.append({"component": "jquery", "version": jq,
                              "issue": "Outdated jQuery (<3.5.0) — check NVD / CVE databases"})
        except Exception:
            pass

    # service-based heuristics
    for s in services:
        svc = (s.get("service") or "").lower()
        ver = s.get("version")
        if svc:
            if "nginx" in svc and ver:
                notes.append({"component": "nginx", "version": ver,
                              "issue": "Detected nginx — check NVD for CVEs for this version"})
            if ("apache" in svc or "httpd" in svc) and ver:
                notes.append({"component": "apache", "version": ver,
                              "issue": "Detected Apache/httpd — check NVD for CVEs for this version"})
            if "php" in svc and ver:
                try:
                    if version_lt(str(ver), "7.4"):
                        notes.append({"component": "php", "version": ver,
                                      "issue": "Old PHP detected (<7.4) — end-of-life or security risk"})
                except Exception:
                    pass
    return {"notes": notes}


def scan_target(target: str,
                run_nmap_scan: bool = True,
                nmap_timeout: int = 360,
                ports_to_probe: Tuple[int, ...] = (80, 443),
                http_timeout: int = 12) -> Dict[str, Any]:
    """
    Main function. Returns a single consolidated dict report.
    - run_nmap_scan: whether to run nmap (False for faster runs)
    - nmap_timeout: seconds to wait for nmap (increase if necessary)
    """
    report: Dict[str, Any] = {
        "target": target,
        "generated": datetime.utcnow().isoformat() + "Z",
        "nmap_raw": None,
        "services": [],
        "http": {},
        "fingerprint": {},
        "tls": {},
        "local_checks": {},
    }

    # NMAP
    if run_nmap_scan:
        report["nmap_raw"] = run_nmap(target, timeout=nmap_timeout)
        report["services"] = parse_nmap_services(report["nmap_raw"] or "")
    else:
        report["nmap_raw"] = "skipped"
        report["services"] = []

    # HTTP fetch / fingerprint per-URL
    report["http"] = fetch_http_pages(target, ports_to_try=ports_to_probe, timeout=http_timeout)

    # combine fingerprints into one summary (unique)
    combined_fp = {"cms": [], "js_libs": {}, "meta_generator": None}
    for url, res in report["http"].items():
        if isinstance(res, dict) and res.get("fingerprint"):
            fp = res["fingerprint"]
            for c in fp.get("cms", []):
                if c not in combined_fp["cms"]:
                    combined_fp["cms"].append(c)
            for k, v in fp.get("js_libs", {}).items():
                if k not in combined_fp["js_libs"]:
                    combined_fp["js_libs"][k] = v
            if not combined_fp["meta_generator"] and fp.get("meta_generator"):
                combined_fp["meta_generator"] = fp.get("meta_generator")
    report["fingerprint"] = combined_fp

    # TLS probing
    try:
        report["tls"] = probe_tls_versions(target, port=443, timeout=6)
    except Exception as e:
        report["tls"] = {"error": str(e)}

    # Local vulnerability heuristics
    try:
        report["local_checks"] = local_vuln_checks(report["fingerprint"], report["services"])
    except Exception as e:
        report["local_checks"] = {"error": str(e)}

    # Add a small summary for convenience
    report["summary"] = {
        "target": target,
        "generated": report["generated"],
        "open_services_count": len(report["services"]),
        "detected_cms": report["fingerprint"].get("cms", []),
        "js_libs": report["fingerprint"].get("js_libs", {}),
        "tls_supported": report["tls"].get("supported", []),
        "local_checks": report["local_checks"],
    }

    return report


# CLI helper
if __name__ == "__main__":
    import argparse, json
    p = argparse.ArgumentParser(description="vuln_recon - nmap + TLS + fingerprinting (no external APIs)")
    p.add_argument("target", help="hostname or ip")
    p.add_argument("--no-nmap", action="store_true", help="skip nmap (faster)")
    p.add_argument("--nmap-timeout", type=int, default=360, help="nmap timeout in seconds")
    args = p.parse_args()
    rpt = scan_target(args.target, run_nmap_scan=not args.no_nmap, nmap_timeout=args.nmap_timeout)
    print(json.dumps(rpt, indent=2))
