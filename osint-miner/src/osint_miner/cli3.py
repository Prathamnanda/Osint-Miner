# src/osint_miner/cli2.py
"""
OSINT Miner CLI - Organization Recon Only (concurrent runner, phone_recon removed)

Drop-in replacement for your concurrent runner with:
 - compact VULN_RECON console output (no repeated fingerprint blocks)
 - http/https duplicate collapse for display
 - concurrent execution and progress bar
"""

from __future__ import annotations
import click
from pathlib import Path
import json
import datetime
import re
import traceback
import concurrent.futures
import os
from typing import Dict, Any
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn

console = Console(log_path=False)

# Try package-mode relative imports, else fall back to script-mode absolute imports
try:
    from . import org_recon, formatter, recon_utils, email_recon
    from .social_recon import social_recon
except Exception:
    import org_recon, formatter, recon_utils, email_recon  # type: ignore
    from social_recon import social_recon  # type: ignore

# vuln_recon import (package or script mode)
try:
    from . import vuln_recon
except Exception:
    import vuln_recon  # type: ignore

# convenience refs from recon_utils (may be None)
robots_and_sitemaps = getattr(recon_utils, "robots_and_sitemaps", None)
find_open_directories = getattr(recon_utils, "find_open_directories", None)
scan_ports = getattr(recon_utils, "scan_ports", None)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# slugify (same behaviour as before)
def _slugify(s: str):
    return re.sub(r"[^a-zA-Z0-9_-]", "_", (s or "").lower()).strip("_") or "target"

# wrapper to call step and capture exceptions
def _call_step(fn):
    try:
        return fn()
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}


@click.group()
def cli():
    """OSINT Miner CLI (concurrent)"""
    pass


@cli.command()
@click.option("--type", "target_type", type=click.Choice(["org"]), required=True)
@click.option("--name", help="Organization name", required=True)
@click.option("--domain", help="Domain (for organizations)", required=True)
@click.option("--output", help="Save Markdown report to a file (defaults to outputs/{slug}.md)")
@click.option("--max-pages", default=200, help="Max pages to crawl for documents/contacts")
def scan(target_type, name, domain, output, max_pages):
    """Scan an organization target (concurrent)."""
    # show banner if available
    try:
        if hasattr(formatter, "print_banner"):
            formatter.print_banner()
    except Exception:
        pass

    console.print("✅ Starting OSINT organization scan...\n")

    slug = _slugify(name or domain or "target")
    outputs_dir = Path("outputs")
    outputs_dir.mkdir(parents=True, exist_ok=True)
    md_path = Path(output) if output else (outputs_dir / f"{slug}.md")

    # start markdown file (UTC timezone-aware)
    try:
        utcnow = datetime.datetime.now(datetime.timezone.utc).isoformat()
    except Exception:
        # fallback if timezone isn't available
        utcnow = datetime.datetime.utcnow().isoformat() + "Z"
    with md_path.open("w", encoding="utf-8") as md:
        md.write(f"# OSINT Org Scan: {name} ({domain})\n")
        md.write(f"_Generated: {utcnow}_\n\n")

    # Prepare steps (phone_recon removed)
    steps = [
        ("NAME", lambda: {"name": name}),
        ("DOMAIN", lambda: {"domain": domain}),
        ("WHOIS", lambda: org_recon.whois_lookup(domain)),
        ("DNS", lambda: org_recon.dns_lookup(domain)),
        ("SUBDOMAINS", lambda: org_recon.crtsh_subdomains(domain)),
        ("TECH", lambda: org_recon.tech_fingerprint(domain)),
        ("GITHUB_MENTIONS", lambda: org_recon.github_search_mentions(name, domain)),
        ("BUCKET_CHECKS", lambda: [org_recon.check_bucket_http(h) for h in org_recon.guess_bucket_hostnames(domain)]),
        ("JOB_PAGES", lambda: org_recon.find_job_pages(domain)),
        ("TAKEOVER_CHECKS", lambda: org_recon.passive_takeover_checks(org_recon.crtsh_subdomains(domain)[:100])),
        ("IP_ASN", lambda: org_recon.ip_and_asn_info(domain)),
        ("SOCIAL_MEDIA", lambda: social_recon(name, domain)),
        ("EMAILS", lambda: email_recon.find_emails(domain, max_pages=max_pages)),
        ("ROBOTS_SITEMAPS", lambda: robots_and_sitemaps(domain) if robots_and_sitemaps else {"error": "robots_and_sitemaps not found"}),
        ("OPEN_DIRS", lambda: find_open_directories(domain, max_checks=30) if find_open_directories else {"error": "find_open_directories not found"}),
        ("PORT_SCAN", lambda: scan_ports(domain, ports=[80,443,22,3306,8080], max_workers=20, timeout=0.9) if scan_ports else {"error": "scan_ports not found"}),
        ("VULN_RECON", lambda: vuln_recon.scan_target(domain) if hasattr(vuln_recon, "scan_target") else {"error": "vuln_recon.scan_target not found"}),
    ]

    # concurrency settings
    try:
        cpu_count = os.cpu_count() or 4
    except Exception:
        cpu_count = 4
    max_workers = min(12, max(2, cpu_count))

    futures_map = {}

    # Progress UI
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.fields[title]}"),
        BarColumn(bar_width=None),
        TextColumn("[green]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("running", title="Running steps", total=len(steps))

        # submit tasks
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for idx, (title, fn) in enumerate(steps):
                fut = executor.submit(_call_step, fn)
                futures_map[fut] = (title, idx)

            # As futures finish, display and write results
            emails_result = None
            results_by_index = {}
            for fut in concurrent.futures.as_completed(futures_map):
                title, idx = futures_map[fut]
                try:
                    data = fut.result()
                except Exception as e:
                    data = {"error": str(e), "trace": traceback.format_exc()}

                # --- Pretty/compact printing ---
                try:
                    # Special handling for VULN_RECON to avoid repeated nested output:
                    if title == "VULN_RECON" and isinstance(data, dict):
                        # 1) services summary (compact)
                        services = data.get("services") or []
                        if services:
                            try:
                                svc_map = {
                                    str(s.get("port", "?")): f"{s.get('service','?')} {s.get('version') or ''}".strip()
                                    for s in services
                                }
                                formatter.print_table("VULN_SERVICES", svc_map)
                            except Exception:
                                console.print(f"[yellow]VULN_SERVICES: {len(services)} services detected[/yellow]")

                        # 2) combined fingerprint (cms)
                        fingerprint = data.get("fingerprint") or {}
                        cms = fingerprint.get("cms") if isinstance(fingerprint, dict) else None
                        js_libs = fingerprint.get("js_libs") if isinstance(fingerprint, dict) else None

                        if cms:
                            try:
                                formatter.print_table("DETECTED_CMS", {"cms": ", ".join(cms)})
                            except Exception:
                                console.print(f"[yellow]DETECTED_CMS: {', '.join(cms)}[/yellow]")

                        # 3) short JS libs sample (limit to top 10)
                        if js_libs:
                            try:
                                short_js = dict(list(js_libs.items())[:10])
                                formatter.print_table("JS_LIBS_SAMPLE", short_js)
                            except Exception:
                                console.print(f"[yellow]JS_LIBS_SAMPLE: {', '.join(list(js_libs.keys())[:10])}[/yellow]")

                        # 4) TLS summary
                        tls = data.get("tls") or {}
                        supported = tls.get("supported") if isinstance(tls, dict) else None
                        if supported:
                            proto_list = [s.get("proto") if isinstance(s, dict) else str(s) for s in supported]
                            try:
                                formatter.print_table("TLS_SUPPORTED", {"protocols": ", ".join(proto_list)})
                            except Exception:
                                console.print(f"[yellow]TLS_SUPPORTED: {', '.join(proto_list)}[/yellow]")

                        # 5) Optionally show per-URL http entries BUT collapse http/https duplicates
                        try:
                            http_block = data.get("http") or {}
                            # collapse http/https: prefer https if both present
                            visible_http = {}
                            for url, info in http_block.items():
                                # normalize host portion
                                try:
                                    from urllib.parse import urlparse
                                    parsed = urlparse(url)
                                    host_key = parsed.netloc.lower()
                                    scheme = parsed.scheme.lower()
                                except Exception:
                                    host_key = url
                                    scheme = "http"
                                # if already have https for same host, skip http
                                if host_key in visible_http:
                                    # prefer https over http
                                    if visible_http[host_key].get("scheme") == "https":
                                        continue
                                visible_http[host_key] = {"url": url, "info": info, "scheme": scheme}

                            # print a compact table of visible_http (host -> status_code / error)
                            if visible_http:
                                compact = {}
                                for host, rec in visible_http.items():
                                    info = rec.get("info") or {}
                                    if isinstance(info, dict) and "status_code" in info:
                                        compact[host] = f"{rec.get('scheme')} {info.get('status_code')}"
                                    elif isinstance(info, dict) and "error" in info:
                                        compact[host] = f"{rec.get('scheme')} error"
                                    else:
                                        compact[host] = f"{rec.get('scheme')} unknown"
                                formatter.print_table("VULN_HTTP_OVERVIEW", compact)
                        except Exception:
                            pass

                    else:
                        # Default: pretty-print entire data for non-vuln steps
                        if hasattr(formatter, "print_table"):
                            formatter.print_table(title, data)
                        else:
                            console.print(json.dumps(data, indent=2, default=str))
                except Exception:
                    # Fallback: raw JSON
                    try:
                        console.print(json.dumps(data, indent=2, default=str))
                    except Exception:
                        console.print(str(data))

                # --- always write full raw JSON to markdown file (preserve full data) ---
                try:
                    with md_path.open("a", encoding="utf-8") as md:
                        md.write(f"\n## {title}\n\n")
                        md.write("```\n")
                        try:
                            md.write(json.dumps(data, indent=2, default=str))
                        except Exception:
                            md.write(str(data))
                        md.write("\n```\n")
                except Exception:
                    console.log(f"[red]Failed writing section {title} to markdown: {traceback.format_exc()}")

                # capture emails result for later summary
                if title == "EMAILS":
                    emails_result = data

                # store by original index
                results_by_index[idx] = (title, data)

                # update progress
                progress.advance(task, 1)
                progress.refresh()

        # end executor/progress

    # Post-process harvested emails summary (same behaviour, compact)


if __name__ == "__main__":
    cli()
