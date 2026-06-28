<div align="center">

# 🔍 SecretScanner

### Async Secret & API Key Leak Detector for JavaScript, Web Pages, and Exposed Configs

<br>

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge&logo=python)
![Version](https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge)
![Signatures](https://img.shields.io/badge/signatures-151-critical?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-orange?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Kali%20%7C%20WSL-brightgreen?style=for-the-badge&logo=linux)
![Async](https://img.shields.io/badge/async-aiohttp-9cf?style=for-the-badge)

<br>

> **SecretScanner** is a high-concurrency, deobfuscation-aware Python framework that scans domains, subdomains, JavaScript bundles, source maps, and exposed configuration files for leaked API keys, tokens, credentials, and private keys — with 151 detection signatures, Shannon entropy filtering, and three output formats.

**Fast. Deep. Noise-Free.**

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Why SecretScanner](#-why-secretscanner)
- [Core Capabilities](#-core-capabilities)
- [Detection Coverage](#-detection-coverage)
- [Architecture](#-architecture)
- [Scan Workflow](#-scan-workflow)
- [Output Files](#-output-files)
- [Installation](#-installation)
- [First Run](#-first-run)
- [Usage](#-usage)
- [domains.txt Format](#-domainstxt-format)
- [Configuration & Tuning](#-configuration--tuning)
- [Performance Features](#-performance-features)
- [Module Reference](#-module-reference)
- [Project Structure](#-project-structure)
- [Example Output](#-example-output)
- [FAQ](#-faq)
- [Roadmap](#-roadmap)
- [Security Notice](#-security-notice)
- [Disclaimer](#-disclaimer)
- [License](#-license)

---

## ⚡ Features

| Feature | Detail | Status |
|---|---|---|
| 🧠 151 Detection Signatures | Cloud, payments, AI/LLM, identity, private keys, database strings, JWTs | ✅ Implemented |
| 🔓 Deobfuscation Layer | Hex, unicode, string concat, `atob()`, base64, `fromCharCode()`, webpack | ✅ Implemented |
| 📊 Entropy Filtering | Shannon entropy + JS-identifier detection eliminates false positives | ✅ Implemented |
| 🔄 Cross-Pattern Deduplication | One finding per secret value, regardless of how many patterns match | ✅ Implemented |
| 🗺️ Source Map Scanning | Fetches and scans `.map` files — often expose full unminified source | ✅ Implemented |
| 🌐 133 Leak-Path Probes | `.env` variants, git exposure, CI/CD configs, debug endpoints per domain | ✅ Implemented |
| 🕵️ Subdomain Discovery | crt.sh certificate transparency + async DNS brute-force | ✅ Implemented |
| ⚡ Async High Concurrency | Independent semaphores: domain-level + per-domain request concurrency | ✅ Implemented |
| 📂 Three Output Formats | `.json` (full detail), `.csv` (spreadsheet), `.txt` (grep-friendly) | ✅ Implemented |
| 🎯 Direct JS URL Mode | Scan a flat list of JS/page URLs — bypasses domain crawling entirely | ✅ Implemented |

---

## 🎯 Why SecretScanner

### The Problem with Basic Secret Scanners

Most secret detection tools rely on a short list of simple regex patterns applied to raw page source. This produces two failure modes:

**False Negatives — things missed:**
- Secrets embedded in **minified JavaScript bundles** (common: hex-escaped strings, string concatenation, `atob()` calls, `String.fromCharCode()` arrays, webpack key/value reassembly)
- Secrets in **source map files** that were left publicly accessible alongside the minified bundle
- Credentials in **exposed configuration files** — `.env` variants, `config.js`, `docker-compose.yml`, CI/CD manifests — that live at predictable paths a crawler won't find

**False Positives — noise that wastes your time:**
- Generic patterns like `KEY=value` matching every CSS class name, React prop, and JavaScript identifier
- Patterns matching `accessKey: a.spaceSeparated` or `requestKey: g.HEAD_REQUEST_KEY` — clearly not secrets

### How SecretScanner Solves This

SecretScanner is a layered detection system, not a regex grep:

1. **Deobfuscation first** — before any pattern runs, the source is decoded through 8 static deobfuscation transforms that reconstruct secrets hidden across obfuscation layers
2. **Two-tier pattern system** — branded patterns (`sk_live_`, `AIza`, `ghp_`) need no filtering; generic patterns require quoted values AND pass through Shannon entropy + JS-identifier checks
3. **133 path probes per domain** — actively checks predictable paths where configuration files are commonly exposed
4. **Source map fetching** — discovers and scans `.map` files for full unminified source
5. **Cross-pattern deduplication** — a single secret value matched by multiple overlapping patterns appears once, under its highest-confidence label

The result: high-signal findings you can act on immediately, with the noise removed before it reaches your report.

---

## 🔥 Core Capabilities

### 🧠 151-Signature Pattern Engine

Detection signatures are organized in two tiers:

**Tier 1 — Branded Patterns** (near-zero false positive rate): Fixed-prefix tokens like `sk_live_`, `AIza`, `ghp_`, `glpat-`, `npm_`, `dop_v1_`. These are matched directly — their fixed prefix provides sufficient precision with no additional filtering.

**Tier 2 — Generic Patterns** (with entropy gating): Patterns for `KEY=`, `TOKEN=`, `SECRET=`, `PASSWORD=` constructs. These require the matched value to be a quoted string, pass Shannon entropy thresholds, and not match a known JS-identifier structure before being reported.

### 🔓 Deobfuscation Layer

All source is pre-processed through 8 static transforms before scanning — nothing is executed or eval'd, making this safe on untrusted JS:

| Transform | Example Input | Decoded |
|---|---|---|
| Hex escapes | `\x41\x49\x7a\x61` | `AIza` |
| Unicode escapes | `\u0041\u0049` | `AI` |
| String concatenation | `"sk_live_" + "abc123"` | `sk_live_abc123` |
| `atob()` calls | `atob("c2tfbGl2ZQ==")` | `sk_live` |
| Bare base64 strings | `_k="c2tfbGl2ZQ=="` | decoded if high-entropy + printable |
| `String.fromCharCode()` | `String.fromCharCode(65,73,122)` | `AIz` |
| Webpack array KV | `n[0]="val",n[1]="KEY_NAME"` | `KEY_NAME:"val"` |
| Octal escapes | `\101\111` | `AI` |

### 📊 Shannon Entropy False-Positive Filtering

For generic patterns, the extracted value passes through:
- Shannon entropy calculation — low-entropy strings (repeated chars, dictionary words) are rejected
- JS-identifier detection — strings matching camelCase/UPPER_CASE identifier patterns are rejected
- Known-safe literal blocklist — `"staging"`, `"localhost"`, `"placeholder"`, `"changeme"`, etc.

### 🌐 133 Leak-Path Probes

Every domain is probed at 133 predictable paths covering: `.env` variants, `config.js`, `settings.json`, `docker-compose.yml`, CI/CD manifests (`.travis.yml`, `Jenkinsfile`, `.circleci/config.yml`), git exposure (`.git/config`, `.git/HEAD`), debug endpoints, and mobile app config files.

### 🕵️ Subdomain Discovery

When `--subs` is passed (or a `*.domain.com` wildcard entry is found in the input file), SecretScanner discovers subdomains via:
- **crt.sh** — certificate transparency log queries
- **DNS brute-force** — async resolution of a curated common-subdomain wordlist via DNS-over-HTTPS

Both sources are merged and deduplicated before scanning.

---

## 🔍 Detection Coverage

<details>
<summary><strong>View all 151 signature categories</strong></summary>

| Category | Providers |
|---|---|
| ☁️ Cloud | AWS (Access Key, Secret, Session Token, MWS), GCP (API Key, OAuth, Service Account, Private Key, FCM), Azure (Storage Key, SAS), DigitalOcean, Alibaba Cloud, Tencent Cloud, IBM Cloud, Oracle Cloud |
| 📦 Source Control | GitHub (Classic PAT, Fine-Grained PAT, OAuth, App Token, Refresh), GitLab (PAT, Pipeline Trigger, Runner), Bitbucket, NPM, PyPI, Docker Hub |
| 💳 Payments | Stripe (Live + Test), PayPal, Square, Razorpay, Plaid, Coinbase |
| 💬 Messaging | Slack (Bot Token, Webhook), Discord (Bot Token, Webhook), Twilio, SendGrid, Mailgun, Mailchimp |
| 🤖 AI / LLM | OpenAI, Anthropic, HuggingFace, Replicate, Pinecone, Groq, Mistral |
| 🗺️ Maps | Google Maps, Mapbox |
| 🛒 E-Commerce | Shopify |
| 📰 CMS | Contentful, Sanity, Prismic |
| 📊 Analytics | Algolia, Segment, Mixpanel, Datadog, Sentry, New Relic |
| 🏗️ Infrastructure | Vercel, Netlify, Cloudflare, Supabase, PlanetScale |
| 🔑 Identity | Auth0, Okta, Clerk |
| 🔧 Dev Tools | CircleCI, Jenkins, Terraform Cloud, Notion, Airtable, Figma |
| 🔐 Private Keys | RSA, EC, PGP, OpenSSH private key blocks |
| 🗄️ Databases | PostgreSQL connection strings, MySQL, MongoDB URI, Redis URI |
| 🎫 JWTs | JWT token detection |
| 🎲 Generic | High-entropy secrets matching KEY/TOKEN/SECRET/PASSWORD constructs |

</details>

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SECRETSCANNER FRAMEWORK                         │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │                         main.py                                 │  │
│   │              CLI entry point / arg parsing / orchestration      │  │
│   └───────────────┬─────────────────────────────┬───────────────────┘  │
│                   │                             │                      │
│          ┌────────┴────────┐          ┌─────────┴──────────┐          │
│          │  Domain Scan    │          │   JS-List Scan      │          │
│          │  (run_domain    │          │   (run_js_list      │          │
│          │   _scan)        │          │    _scan)           │          │
│          └────────┬────────┘          └─────────┬──────────┘          │
│                   │                             │                      │
│          ┌────────▼────────┐                   │                      │
│          │  subdomains.py  │                   │                      │
│          │  crt.sh + DNS   │                   │                      │
│          │  brute-force    │                   │                      │
│          └────────┬────────┘                   │                      │
│                   │                             │                      │
│          ┌────────▼─────────────────────────────▼──────────┐          │
│          │                   scraper.py                     │          │
│          │   High-concurrency async HTTP engine             │          │
│          │   - Single shared aiohttp session + pool         │          │
│          │   - Domain semaphore + per-domain semaphore      │          │
│          │   - HTML page fetch → JS URL extraction          │          │
│          │   - robots.txt / sitemap.xml parsing             │          │
│          │   - JS file fetch + source map discovery         │          │
│          │   - 133 leak-path probes per domain              │          │
│          └────────────────────┬────────────────────────────┘          │
│                               │  raw source text                      │
│          ┌────────────────────▼────────────────────────────┐          │
│          │              deobfuscator.py                     │          │
│          │   hex → unicode → concat → atob → b64 →         │          │
│          │   fromCharCode → webpack KV → octal             │          │
│          └────────────────────┬────────────────────────────┘          │
│                               │  decoded text                         │
│          ┌────────────────────▼────────────────────────────┐          │
│          │                  engine.py                       │          │
│          │   Pattern matching across 151 signatures         │          │
│          │   ┌──────────────┐   ┌──────────────────────┐   │          │
│          │   │  BRANDED     │   │  GENERIC             │   │          │
│          │   │  (Tier 1)    │   │  (Tier 2)            │   │          │
│          │   │  Direct hit  │   │  → entropy.py gate   │   │          │
│          │   └──────────────┘   └──────────────────────┘   │          │
│          │   Cross-pattern deduplication                    │          │
│          └────────────────────┬────────────────────────────┘          │
│                               │  Finding objects                      │
│          ┌────────────────────▼────────────────────────────┐          │
│          │                 reporter.py                      │          │
│          │        JSON  │  CSV  │  TXT (plain-text)        │          │
│          └──────────────────────────────────────────────────┘          │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Scan Workflow

```
          ┌──────────────────────────────┐
          │         INPUT                │
          │  domains.txt  /  --js-list   │
          └──────────────┬───────────────┘
                         │
                         ▼
          ┌──────────────────────────────┐
          │   SUBDOMAIN EXPANSION        │  ← Only when --subs or *.domain.com
          │   crt.sh + DNS brute-force   │    wildcard entries detected
          └──────────────┬───────────────┘
                         │
                         ▼
          ┌──────────────────────────────┐
          │   ASYNC DOMAIN SCRAPER       │  ← Concurrent across all domains
          │   HTML → JS URL extraction   │    Semaphore-bounded parallelism
          │   robots.txt / sitemap.xml   │
          └──────────────┬───────────────┘
                         │
                    ┌────┴────────────────────────┐
                    │                             │
                    ▼                             ▼
     ┌──────────────────────────┐  ┌──────────────────────────┐
     │   JS FILE FETCH          │  │   133 LEAK-PATH PROBES   │
     │   + Source Map Discovery │  │   .env, .git, configs,   │
     │   (up to 80 per domain)  │  │   CI/CD, debug endpoints │
     └──────────┬───────────────┘  └──────────────────────────┘
                │
                ▼
          ┌──────────────────────────────┐
          │   DEOBFUSCATION              │  ← All 8 transforms applied
          │   hex, unicode, concat,      │    before any pattern runs
          │   atob, b64, fromCharCode,   │
          │   webpack KV, octal          │
          └──────────────┬───────────────┘
                         │
                         ▼
          ┌──────────────────────────────┐
          │   PATTERN ENGINE (151 sigs)  │
          │                              │
          │   Branded → direct match     │
          │   Generic → entropy gate     │
          │   Dedup → highest-confidence │
          └──────────────┬───────────────┘
                         │
                         ▼
          ┌──────────────────────────────┐
          │   REPORTER                   │
          │   scan_<timestamp>.json      │
          │   scan_<timestamp>.csv       │
          │   scan_<timestamp>.txt       │
          └──────────────────────────────┘
```

---

## 📂 Output Files

All results are written to `./reports/` (or your custom `-o` path) with a timestamp in the filename.

| File | Format | Contents | Best For |
|---|---|---|---|
| `scan_<ts>.json` | JSON | Full findings with domain, pattern name, masked/raw value, source URL, source type, severity, confidence, line context | Programmatic processing, integration with other tools |
| `scan_<ts>.csv` | CSV | All findings in spreadsheet-friendly tabular format | Reporting to clients, filtering in Excel/LibreOffice |
| `scan_<ts>.txt` | Plain text | One finding per line (grep-friendly) | Quick review, piping to other CLI tools |

### Severity Levels

| Level | Meaning |
|---|---|
| `CRITICAL` | Confirmed high-value secret — branded pattern match (AWS, Stripe live, GitHub PAT, etc.) |
| `HIGH` | High-confidence match — branded pattern, slightly lower value (test keys, webhook URLs with tokens) |
| `MEDIUM` | Moderate confidence — generic pattern passed entropy filter |
| `LOW` | Low-value exposure — public URLs, Firebase database URLs, non-sensitive identifiers |

---

## 🚀 Installation

### Requirements

- Python 3.8 or higher
- `pip` (Python package installer)
- Internet access for scanning

### Kali Linux / Parrot OS

```bash
git clone https://github.com/yourhandle/secret-scanner.git
cd secret-scanner
pip install -r requirements.txt
```

### Ubuntu / Debian

```bash
sudo apt update && sudo apt install -y python3 python3-pip git
git clone https://github.com/yourhandle/secret-scanner.git
cd secret-scanner
pip3 install -r requirements.txt
```

### Virtual Environment (Recommended)

Using a virtual environment keeps dependencies isolated and avoids system-wide package conflicts:

```bash
git clone https://github.com/yourhandle/secret-scanner.git
cd secret-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### WSL2 (Windows Subsystem for Linux)

```bash
# Inside Ubuntu WSL terminal:
sudo apt update && sudo apt install -y python3 python3-pip git
git clone https://github.com/yourhandle/secret-scanner.git
cd secret-scanner
pip3 install -r requirements.txt
```

### Dependencies

| Package | Version | Purpose |
|---|---|---|
| `aiohttp` | ≥ 3.9.0 | Async HTTP client — all domain/JS fetching |
| `beautifulsoup4` | ≥ 4.12.0 | HTML parsing for JS URL extraction |
| `lxml` | ≥ 5.0.0 | Fast HTML parser backend for BeautifulSoup |
| `rich` | ≥ 13.7.0 | Terminal UI — progress bars, summary tables |

---

## 🎯 First Run

```bash
python main.py -f domains.txt
```

**What happens:**

1. `domains.txt` is parsed — comments and blank lines are stripped, `*.domain.com` wildcards are detected
2. Any wildcard entries trigger automatic subdomain discovery via crt.sh + DNS brute-force
3. All domains are fed to the async scraper with the default concurrency of 30 domains / 25 per-domain requests
4. Each domain's HTML page is fetched, JS URLs are extracted, up to 80 JS files are scanned
5. Source map files discovered alongside JS bundles are fetched and scanned
6. 133 predictable paths are probed per domain
7. All source text passes through 8 deobfuscation transforms then through 151 detection patterns
8. Results are written to `./reports/scan_<timestamp>.json`, `.csv`, and `.txt`

---

## 🛠️ Usage

### Scan a Domain List

```bash
python main.py -f domains.txt
```

### Auto-Discover Subdomains

```bash
python main.py -f domains.txt --subs
```

### Wildcard Entry (Auto-Triggers Subdomain Discovery)

```bash
# In domains.txt:
*.example.com

python main.py -f domains.txt
```

### Scan a Flat List of JS URLs Directly

```bash
# Pipe js_files.txt from arm-recon or any other source
python main.py --js-list js_files.txt
```

### Show Unmasked Secret Values

```bash
# ⚠️ Handle output securely — raw values written to report files
python main.py -f domains.txt --raw
```

### Tune Concurrency

```bash
python main.py -f domains.txt --concurrency 50 --per-domain-concurrency 40
```

### Custom Output Directory

```bash
python main.py -f domains.txt -o ./engagements/client1/
```

### Skip Source Map Scanning

```bash
python main.py -f domains.txt --no-sourcemaps
```

### crt.sh Only (Skip DNS Brute-Force)

```bash
python main.py -f domains.txt --subs --no-brute
```

### Full Flag Reference

```
Usage: python main.py [OPTIONS]

Input (one required):
  -f, --file PATH               .txt file with domains (one per line)
  --js-list PATH                .txt file with direct JS/page URLs to scan

Subdomain Discovery:
  --subs                        Auto-discover subdomains (crt.sh + DNS brute-force)
  --no-brute                    With --subs: use crt.sh only, skip DNS brute-force

Scanning:
  --concurrency INT             Concurrent domains (default: 30)
  --per-domain-concurrency INT  Concurrent requests per domain (default: 25)
  --timeout INT                 Request timeout in seconds (default: 10)
  --max-js INT                  Max JS files scanned per domain (default: 80)
  --no-sourcemaps               Skip .map source map scanning

Output:
  -o, --output-dir PATH         Report output directory (default: ./reports)
  --raw                         Show/store UNMASKED secret values
                                ⚠️  Handle output carefully
```

---

## 📄 domains.txt Format

```
# Comments are ignored
example.com
api.example.org

# Wildcard — auto-runs subdomain discovery on this root
*.targetdomain.com

# http:// and https:// prefixes and trailing slashes are stripped automatically
https://another.com/
```

---

## ⚙️ Configuration & Tuning

### Concurrency Tuning

| Use Case | `--concurrency` | `--per-domain-concurrency` |
|---|---|---|
| Default / balanced | 30 | 25 |
| Large scope, fast network | 50 | 40 |
| Rate-limit sensitive targets | 10 | 8 |
| Single domain, deep scan | 1 | 50 |

> ⚠️ Higher concurrency increases scan speed but also increases the chance of triggering WAF rate limits or getting your IP temporarily blocked. Tune based on your target environment.

### JS File Limit

`--max-js` caps the number of JS files scanned per domain (default: 80). On large applications with hundreds of bundled JS files, increasing this value finds more but takes longer:

```bash
python main.py -f domains.txt --max-js 200
```

### Raw Output

`--raw` causes full unmasked secret values to appear in all three output formats. By default, values are masked (e.g., `sk_live_****`). Only use `--raw` when you need the actual values and can secure the output files appropriately.

---

## 📈 Performance Features

| Feature | Detail |
|---|---|
| **Dual Semaphore Architecture** | Independent semaphores for domain-level and per-domain request concurrency — no single bottleneck |
| **Single Shared Connection Pool** | One `aiohttp.TCPConnector` with configurable limits shared across all requests — avoids connection churn |
| **Redirect-Aware Fetching** | Returns the final resolved URL after redirects so all relative JS/config paths are built correctly |
| **Async Subdomain Discovery** | crt.sh and DNS resolution both fully async — no sequential blocking during enumeration |
| **Source Map Auto-Discovery** | Detects `//# sourceMappingURL=` comments in JS and fetches maps automatically |
| **robots.txt / sitemap.xml Parsing** | Additional JS and page discovery from standard locations, not just link extraction |
| **User-Agent Rotation** | Rotates between 3 realistic browser user agents to reduce fingerprinting |
| **SSL Verification Disabled** | Scans self-signed and misconfigured HTTPS targets without errors |

---

## 📦 Module Reference

| Module | Role |
|---|---|
| `main.py` | CLI entry point, argument parsing, orchestration of domain and JS-list scan modes |
| `patterns.py` | 151 compiled regex signatures organized into Tier 1 (branded) and Tier 2 (generic) |
| `engine.py` | Core detection engine — runs deobfuscation, applies all patterns, entropy-gates generics, deduplicates |
| `entropy.py` | Shannon entropy calculation, false-positive detection, JS-identifier matching, known-safe value blocklist |
| `deobfuscator.py` | 8 static deobfuscation transforms — safe for untrusted source (nothing executed) |
| `scraper.py` | Async HTTP engine — page fetch, JS extraction, leak-path probing, source map discovery |
| `leak_paths.py` | 133 predictable path definitions: `.env` variants, git exposure, CI/CD configs, debug endpoints |
| `subdomains.py` | Passive (crt.sh) + active (DNS brute-force) subdomain enumeration |
| `reporter.py` | Writes findings to JSON, CSV, and plain-text formats |
| `ui.py` | Rich terminal UI — banner, progress bar, live updates, summary table |

---

## 📁 Project Structure

```
secret-scanner/
│
├── main.py               # Entry point — orchestration, CLI, scan modes
├── patterns.py           # 151 detection signatures (Tier 1 + Tier 2)
├── engine.py             # Detection engine — deobfuscate → match → filter → dedup
├── entropy.py            # Shannon entropy + false-positive filtering
├── deobfuscator.py       # 8 static JS deobfuscation transforms
├── scraper.py            # Async HTTP scraper — pages, JS, leak paths, source maps
├── leak_paths.py         # 133 predictable sensitive path definitions
├── subdomains.py         # crt.sh + DNS brute-force subdomain discovery
├── reporter.py           # JSON / CSV / TXT report generation
├── ui.py                 # Rich terminal UI
├── requirements.txt      # Python dependencies
│
└── reports/              # Auto-created — all scan output lands here
    ├── scan_20250115_142301.json
    ├── scan_20250115_142301.csv
    └── scan_20250115_142301.txt
```

---

## 📊 Example Output

### Console (during scan)

```
  ╔══════════════════════════════════════════════════════════╗
  ║           SECRET SCANNER  •  151 signatures             ║
  ║         Deobfuscation  •  Entropy filtering             ║
  ╚══════════════════════════════════════════════════════════╝

  Domains queued : 3
  Concurrency    : 30 domains / 25 per-domain

  Scanning ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 3/3  100%

  ┌─────────────────────────────────────────────────────────┐
  │ FINDINGS SUMMARY                                        │
  ├──────────────────────┬──────────┬────────────┬──────────┤
  │ Domain               │ Findings │ Severity   │ JS Files │
  ├──────────────────────┼──────────┼────────────┼──────────┤
  │ example.com          │ 3        │ CRITICAL   │ 14       │
  │ api.example.com      │ 1        │ HIGH       │ 7        │
  │ dev.example.com      │ 5        │ CRITICAL   │ 22       │
  └──────────────────────┴──────────┴────────────┴──────────┘

  Total findings : 9
  Scan duration  : 28.4s

  Reports written to:
    ./reports/scan_20250115_142301.json
    ./reports/scan_20250115_142301.csv
    ./reports/scan_20250115_142301.txt
```

### `scan_<ts>.txt` (excerpt)

```
[CRITICAL] example.com | AWS Access Key ID | AKIA****************XAMPLE | https://example.com/static/js/main.4f3a.js | JS
[CRITICAL] dev.example.com | Stripe Live Secret Key | sk_live_****************************abc | https://dev.example.com/js/config.js | JS
[HIGH] api.example.com | GitHub Personal Access Token (classic) | ghp_****************************xyz | https://api.example.com/assets/vendor.js | JS
[CRITICAL] dev.example.com | OpenAI API Key | sk-****************************XYZ | https://dev.example.com/.env | Config
[MEDIUM] dev.example.com | Generic High-Entropy Secret | ****************************Kw== | https://dev.example.com/static/js/chunk.123.js | JS
```

### `scan_<ts>.json` (single finding)

```json
{
  "domain": "dev.example.com",
  "pattern": "Stripe Live Secret Key",
  "value_masked": "sk_live_****************************abc",
  "source_url": "https://dev.example.com/js/config.js",
  "source_type": "JS",
  "severity": "CRITICAL",
  "confidence": 0.98,
  "line_number": 47,
  "context": "const stripeKey = \"sk_live_[REDACTED]\";"
}
```

---

## ❓ FAQ

<details>
<summary><strong>Does --raw store unmasked values in the report files?</strong></summary>

Yes. When `--raw` is passed, all three output formats (JSON, CSV, TXT) will contain the full unmasked secret values. Treat these files with the same sensitivity as the secrets themselves — do not commit them to version control, and store them securely.

Without `--raw`, values are masked with asterisks and only the type/pattern is recorded.

</details>

<details>
<summary><strong>How does the deobfuscation work — is it safe on untrusted JS?</strong></summary>

All deobfuscation transforms are pure regex and string decode operations. Nothing is executed or eval'd. This makes deobfuscator.py safe to run on untrusted or potentially malicious JavaScript source without any code execution risk.

</details>

<details>
<summary><strong>What does --js-list mode do differently?</strong></summary>

In `--js-list` mode, SecretScanner skips domain crawling entirely. You provide a flat list of JS/page URLs (one per line), and the scanner fetches and scans each URL directly. This is useful when you already have a list of JS files — for example, the `js_files.txt` output from Arm-Recon or Katana.

</details>

<details>
<summary><strong>What are the 133 leak-path probes?</strong></summary>

SecretScanner probes 133 predictable paths on every domain where sensitive files are commonly exposed. This includes `.env` and its variants (`.env.local`, `.env.production`, `.env.backup`), git metadata (`.git/config`, `.git/HEAD`), CI/CD manifests (`.travis.yml`, `Jenkinsfile`, `.circleci/config.yml`), common config files (`config.js`, `settings.json`, `docker-compose.yml`), debug endpoints, and mobile app config files.

</details>

<details>
<summary><strong>Can I combine this with Arm-Recon?</strong></summary>

Yes — this is the intended workflow. Run Arm-Recon first to discover subdomains and crawl JS files, then feed its output directly into SecretScanner:

```bash
# Use js_files.txt from arm-recon as direct input
python main.py --js-list results/target.com/latest/js_files.txt

# Or use subdomains_alive.txt as your domain list
python main.py -f results/target.com/latest/subdomains_alive.txt
```

</details>

<details>
<summary><strong>Why does the scanner disable SSL verification?</strong></summary>

Many internal applications, staging environments, and misconfigured production hosts use self-signed or expired SSL certificates. Disabling verification ensures these hosts are scanned rather than silently skipped. Do not pass scan results through untrusted networks without additional controls.

</details>

---

## 🗺️ Roadmap

- [x] 151 branded + generic detection signatures
- [x] 8-transform static deobfuscation layer
- [x] Shannon entropy false-positive filtering
- [x] Cross-pattern finding deduplication
- [x] 133 predictable leak-path probes per domain
- [x] Source map auto-discovery and scanning
- [x] Subdomain discovery (crt.sh + DNS brute-force)
- [x] Direct JS-URL list scan mode
- [x] JSON / CSV / TXT output formats
- [x] Rich terminal UI with progress and summary table
- [ ] Authenticated scanning (cookie / Bearer token support)
- [ ] Nuclei template generation from findings
- [ ] SARIF output format for CI/CD integration
- [ ] Slack / webhook notification on CRITICAL findings
- [ ] Scope-aware filtering (include/exclude patterns)
- [ ] Retry logic with exponential backoff on rate-limited hosts

---

## 🔒 Security Notice

SecretScanner is designed for use in **authorized security assessments only**.

Before running this tool against any target:

- Obtain **explicit written authorization** from the asset owner
- Ensure your scope document covers the target domain and all discovered subdomains
- Understand that leak-path probing sends HTTP requests to 133 paths per domain — this is detectable and may trigger alerts on monitored infrastructure
- Store output files containing `--raw` values securely; treat them as credential material

Unauthorized use against systems you do not own or have permission to test is **illegal** and may result in criminal prosecution.

---

## ⚠️ Disclaimer

SecretScanner is provided for:

- **Educational purposes** — understanding how secrets are inadvertently exposed in JavaScript bundles and configuration files
- **Authorized penetration testing** — use within scoped engagements with documented client authorization
- **Bug bounty programs** — use against assets explicitly listed in a program's in-scope targets
- **Internal security auditing** — scanning infrastructure you own or are responsible for

The authors and contributors accept **no liability** for misuse, unauthorized use, or any damage caused by the use of this tool. Users assume full responsibility for ensuring all usage complies with applicable laws and authorization requirements.

---

## 📜 License

```
MIT License

Copyright (c) 2025 SecretScanner Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

<div align="center">

## ⭐ Star This Repository

If SecretScanner surfaces a finding that saves you hours of manual review, consider starring the repository.

[![Star on GitHub](https://img.shields.io/github/stars/yourhandle/secret-scanner?style=social)](https://github.com/yourhandle/secret-scanner)

<br>

**Built for offensive security professionals. Used responsibly.**

<br>

*SecretScanner is not affiliated with ProjectDiscovery, Amazon Web Services, Google, or any other vendor whose tokens it detects.*

</div>
