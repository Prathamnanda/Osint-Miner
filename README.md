OSINT Miner is a comprehensive automated framework for deep open-source intelligence gathering on organizations and individuals, leveraging only Python modules (no paid APIs). Below is a properly structured summary covering its functionality, operational phases, and project file layout.[1][2]

***

### OSINT Miner Overview (will work for any website)

OSINT Miner automates the discovery, aggregation, processing, and reporting of open-source data. It is designed for both active and passive reconnaissance, yielding actionable intelligence for risk, compliance, and threat assessment, with robust privacy and legal adherence built-in.[5][1]

***

## Reconnaissance Workflow

#### Domain Intelligence
- WHOIS lookup
- DNS records extraction: A, MX, TXT, NS
- ASN & IP information gathering

#### Subdomain Discovery & Enumeration
- Passive: Certificate Transparency logs (crt.sh)
- Active: DNS brute-forcing, scraping, custom lists

#### Subdomain Deduplication
- Resolve subdomains
- Remove duplicate HTTP/HTTPS endpoints

#### Technology Fingerprinting
- Detect CMS: WordPress, Joomla, Drupal
- Identify JavaScript libraries, web frameworks
- Analyze overall tech stack

#### Cloud Asset Discovery
- Detect AWS, Azure, GCP storage buckets
- Assess access permissions

#### Job Page & Employee Discovery
- Locate career/job pages for personnel research

#### Subdomain Takeover Checking
- Passive checks for vulnerable assets

#### Port & Service Scanning
- Scan ports 80, 443, 22, 3306, 8080
- Identify running services and banners

#### TLS & SSL Analysis
- Supported protocol extraction
- Weak/legacy cipher detection

#### Vulnerability Recon
- Fingerprint versions for CVE mapping
- Provide CVE hints for CMS or JS libraries

#### Robots & Sitemap Crawl
- Extract paths from robots.txt
- Enumerate sitemap.xml endpoints

#### Open Directory Discovery
- Identify misconfigured directories

#### GitHub Asset & Mention Search
- Discover company/domain mentions on GitHub

#### Email Harvesting
- Scrape for potential employee emails (regex supported)
- Summarize harvested data

#### Social Media Discovery
- Identify official LinkedIn, Twitter/X, Facebook accounts

***

## Output & Reporting

- Console output: Tabular format, rich progress feedback
- Markdown report: Sections for WHOIS, DNS, subdomains, tech stack, TLS, ports, CVEs, emails
- Summarized findings: Harvested emails and vulnerability formatting

***

## Performance & Execution

- Multiprocessing and multithreading for parallel execution
- Deduplication avoids repetitive scans
- Expected runtime: 6–8 minutes (network dependent)

***

## Project Directory Structure

```text
osint-miner/
├── src/
│   └── osint_miner/
│       ├── cli.py            # Main entrypoint
│       ├── cli2.py           # Parallel scanning (faster)
│       ├── org_recon.py      # Organization reconnaissance
│       ├── social_recon/     # Social media OSINT modules
│       ├── email_recon.py    # Email intelligence
│       ├── vuln_recon.py     # Vulnerability, TLS, tech stack scans
│       ├── formatter.py      # Console & Markdown reporting
│       └── recon_utils.py    # Utility functions
└── outputs/                  # Markdown reports generated here
```

***

## Example Command

```sh
python3 cli3.py scan --type org --name "Example Corp" --domain "example.com"
```

***

