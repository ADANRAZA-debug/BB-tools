<div align="center">

# 🛡️ Arm-Recon

### Automated Reconnaissance Framework for Offensive Security Professionals

<br>

![Version](https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge)
![Shell](https://img.shields.io/badge/shell-bash-green?style=for-the-badge&logo=gnu-bash)
![License](https://img.shields.io/badge/license-MIT-orange?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Kali%20%7C%20WSL-critical?style=for-the-badge&logo=linux)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge)

<br>

> **Arm-Recon** is a structured, modular reconnaissance framework that automates subdomain enumeration, live host validation, crawling, JavaScript discovery, and output normalization — producing clean, pipeline-ready results from a single command.

**Fast. Modular. Noise-Free.**

</div>

---

## 📋 Table of Contents

- [Features](#-features)

- [Why Arm-Recon](#-why-arm-recon)
- [Core Capabilities](#-core-capabilities)
- [Architecture](#-architecture)
- [Recon Workflow](#-recon-workflow)
- [Output Files](#-output-files)
- [Installation](#-installation)
- [First Run](#-first-run)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Performance](#-performance-features)
- [Supported Tools](#-supported-tools)
- [Project Structure](#-project-structure)
- [Example Output](#-example-output)
- [FAQ](#-faq)
- [Roadmap](#-roadmap)
- [Security Notice](#-security-notice)
- [Disclaimer](#-disclaimer)
- [License](#-license)

---

## ⚡ Features

| Feature | Description | Status |
|---|---|---|
| 🔍 Passive Enumeration | Multi-source subdomain discovery via Subfinder, crt.sh, and chaos | ✅ Implemented |
| 🌐 HTTP Validation | Live host probing with status codes, titles, and tech detection via httpx | ✅ Implemented |
| 🕷️ Crawling | Deep endpoint discovery with Katana across live hosts | ✅ Implemented |
| 📜 JS Discovery | Automatic JavaScript file collection from crawled pages | ✅ Implemented |
| 🚫 CDN Filtering | Strips CDN-backed IPs to isolate real attack surface | ✅ Implemented |
| ⚙️ Zero-Dependency Installer | Installs all required tools automatically on first run | ✅ Implemented |
| 📂 Structured Output | Organizes all results into clean, deduplicated, pipeline-ready files | ✅ Implemented |
| 🏗️ Concurrent Execution | Parallel module execution for maximum throughput | ✅ Implemented |
| 🛠️ Modular Design | Run any individual module independently or the full chain | ✅ Implemented |
| 🔒 Race-Safe Operations | File writes protected against concurrent collision | ✅ Implemented |

---

## 🎯 Why Arm-Recon

### The Problem with Manual Toolchains

Most penetration testers and bug bounty hunters assemble recon pipelines manually — chaining tools like `subfinder | httpx | katana` in long one-liners or throwaway wrapper scripts. This approach has serious drawbacks:

- **Noisy output**: Raw tool output includes ANSI escape codes, progress bars, banners, and inconsistent formatting that pollutes downstream processing
- **No deduplication**: Results from multiple passive sources are stacked without deduplication, inflating scope
- **No state**: If a step fails mid-run, there is no recovery — you restart everything
- **Undocumented APIs**: Manual runs skip optional API sources (Chaos, VirusTotal, Shodan) because configuring them per-run is tedious
- **No output structure**: Results land wherever the terminal session is, with no consistent naming, timestamping, or organization

### How Arm-Recon Solves This

Arm-Recon is not a wrapper. It is a **framework** that:

- Enforces a clean, reproducible execution order across all recon phases
- Produces **deduplicated, sorted, normalized** output at every stage
- Stores results in a **consistent directory structure** named per target and timestamp
- Supports **partial execution** — run only the modules you need
- Handles tool installation, path resolution, and environment setup automatically
- Strips all noise (banners, colors, progress indicators) before writing output files

The result is a recon run you can hand directly to another tool, a report, or a junior analyst without cleanup.

---

## 🔥 Core Capabilities

### 📦 Zero-Dependency Installer

Arm-Recon checks for required tools at startup and installs any that are missing. Go, Subfinder, httpx, Katana, Naabu, Nuclei, and FFUF are all resolved automatically. No manual `go install` commands. No PATH confusion.

### 🔍 Passive Enumeration

Subdomain discovery pulls from multiple passive sources simultaneously:

- **Subfinder** — aggregates results across 40+ passive DNS providers
- **crt.sh** — certificate transparency log queries
- **Chaos** (optional) — ProjectDiscovery's curated dataset (API key required)
- **VirusTotal** (optional) — passive DNS enrichment (API key required)

All sources are merged, sorted, and deduplicated into a single clean list.

### 🌐 HTTP Validation

Live host probing via **httpx** with configurable concurrency. Output captures:

- HTTP status codes
- Page titles
- Web server headers
- Detected technologies
- Response times

Results are written to `live_urls.txt` with full URL context preserved.

### 🕷️ Crawler

Deep link and endpoint discovery via **Katana** across all validated live hosts. The crawler follows JavaScript-rendered pages, respects scope boundaries, and dumps all discovered paths for manual review or automated fuzzing.

### 📜 JavaScript Discovery

All `.js` files discovered during crawling are automatically extracted into a dedicated `js_files.txt` list. These files are high-value targets for secrets, tokens, hidden endpoints, and internal API schemas.

### 🚫 CDN Filtering

IP addresses resolved from live hosts are checked against known CDN ranges (Cloudflare, Akamai, Fastly, AWS CloudFront). CDN-backed IPs are separated from origin IPs, reducing wasted effort on infrastructure you cannot directly attack.

### ⚡ Concurrency

Modules that can run in parallel are dispatched concurrently. Passive enumeration sources run simultaneously. Crawling and IP resolution happen in parallel where safe. Configurable thread and rate limits prevent throttling on external APIs.

### 📂 Output Cleanup

Every output file is post-processed: ANSI codes stripped, blank lines removed, results sorted and deduplicated. Files are immediately usable by other tools without preprocessing.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          ARM-RECON FRAMEWORK                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐ │
│   │   Installer  │    │  Config Mgr  │    │    Scope Handler     │ │
│   │  (auto-tool  │    │  (API keys,  │    │  (single target /   │ │
│   │   setup)     │    │   wordlists) │    │   target list)       │ │
│   └──────┬───────┘    └──────┬───────┘    └──────────┬───────────┘ │
│          └─────────────────┬─┘                       │             │
│                            ▼                         │             │
│   ┌─────────────────────────────────────────────────────────────┐  │
│   │                    ORCHESTRATION LAYER                      │  │
│   │           (module selection, order, concurrency)            │  │
│   └────────┬───────────────────────────────────────────────────┘  │
│            │                                                        │
│     ┌──────┴──────────────────────────────────────────────┐        │
│     │                   RECON MODULES                     │        │
│     │                                                     │        │
│  ┌──▼───────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │        │
│  │ Passive  │  │   HTTP   │  │ Crawler  │  │    JS    │  │        │
│  │  Enum    │  │  Probe   │  │ (Katana) │  │Discovery │  │        │
│  │(Subfinder│  │ (httpx)  │  │          │  │          │  │        │
│  │ crt.sh   │  │          │  │          │  │          │  │        │
│  │ Chaos)   │  │          │  │          │  │          │  │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │        │
│                                                     │        │        │
│  ┌──────────┐  ┌──────────┐                         │        │        │
│  │   CDN    │  │   IP     │                         │        │        │
│  │ Filter   │  │ Resolve  │◄────────────────────────┘        │        │
│  │          │  │ (Naabu)  │                                  │        │
│  └──────────┘  └──────────┘                                  │        │
│     └──────────────────────────────────────────────────────┘        │
│                            │                                         │
│                            ▼                                         │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                     OUTPUT HANDLER                          │   │
│   │       (dedup → sort → strip → write → organize)            │   │
│   └─────────────────────────────────────────────────────────────┘   │
│                            │                                         │
│              ┌─────────────┼─────────────┐                          │
│              ▼             ▼             ▼                          │
│       subdomains_    live_urls.txt   js_files.txt                   │
│        alive.txt     live_ips.txt    (timestamped)                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Recon Workflow

```
          ┌─────────────────────────┐
          │        TARGET           │
          │  (domain or list)       │
          └────────────┬────────────┘
                       │
                       ▼
          ┌─────────────────────────┐
          │   PASSIVE ENUMERATION   │  ← Subfinder, crt.sh, Chaos, VT
          │   subdomains.txt        │
          └────────────┬────────────┘
                       │
                       ▼
          ┌─────────────────────────┐
          │   DNS RESOLUTION        │  ← Resolves all discovered
          │   resolved.txt          │    subdomains to IPs
          └────────────┬────────────┘
                       │
                       ▼
          ┌─────────────────────────┐
          │   HTTP VALIDATION       │  ← httpx probes all hosts
          │   live_urls.txt         │    filters dead / unreachable
          └────────────┬────────────┘
                       │
                       ▼
          ┌─────────────────────────┐
          │   CDN FILTERING         │  ← Removes Cloudflare/Akamai
          │   live_ips.txt          │    isolates real origin IPs
          └────────────┬────────────┘
                       │
                       ▼
          ┌─────────────────────────┐
          │   CRAWLER               │  ← Katana crawls all live hosts
          │   crawled_paths.txt     │    discovers endpoints, forms
          └────────────┬────────────┘
                       │
                       ▼
          ┌─────────────────────────┐
          │   JAVASCRIPT DISCOVERY  │  ← Extracts all .js file URLs
          │   js_files.txt          │    from crawled content
          └────────────┬────────────┘
                       │
                       ▼
          ┌─────────────────────────┐
          │   OUTPUT & CLEANUP      │  ← Dedup, sort, normalize all
          │   results/<target>/     │    files into final structure
          └─────────────────────────┘
```

---

## 📂 Output Files

All results are written to `results/<target>/<timestamp>/` automatically.

| File | Contents | Practical Use |
|---|---|---|
| `subdomains_alive.txt` | Deduplicated list of all discovered subdomains that resolved | Feed directly into httpx, nmap, Nuclei, or manual testing |
| `live_urls.txt` | Full URLs of confirmed live HTTP/HTTPS hosts with status codes | Input to Nuclei template scanning or directory bruteforce |
| `js_files.txt` | All JavaScript file URLs discovered during crawling | Manual review for secrets, tokens, and hidden API routes |
| `live_ips.txt` | Deduplicated IP addresses of live hosts (CDN IPs excluded) | Network scanning with Nmap or Naabu port discovery |
| `crawled_paths.txt` | All unique paths and endpoints discovered by the crawler | Manual testing, parameter fuzzing with FFUF |
| `recon.log` | Full execution log with timestamps and tool outputs | Debugging, audit trail, reproducibility |

---

## 🚀 Installation

### Requirements

- Linux (Kali, Ubuntu 20.04+, Debian, Parrot OS, or WSL2)
- `bash` 4.0+
- Internet access for tool installation
- `curl` and `git` (standard on all listed distros)

### Kali Linux / Parrot OS

```bash
git clone https://github.com/yourhandle/arm-recon.git
cd arm-recon
chmod +x install.sh arm-recon.sh
./install.sh
```

### Ubuntu / Debian

```bash
sudo apt update && sudo apt install -y curl git golang-go
git clone https://github.com/yourhandle/arm-recon.git
cd arm-recon
chmod +x install.sh arm-recon.sh
./install.sh
```

### WSL2 (Windows Subsystem for Linux)

```bash
# Ensure you are running WSL2 with Ubuntu 22.04
wsl --set-default-version 2

# Inside WSL terminal:
sudo apt update && sudo apt install -y curl git golang-go
git clone https://github.com/yourhandle/arm-recon.git
cd arm-recon
chmod +x install.sh arm-recon.sh
./install.sh
```

> ⚠️ **Note:** WSL2 is supported for lab use. For production engagements, a native Linux environment is recommended.

---

## 🎯 First Run

```bash
./arm-recon.sh -t example.com
```

**What happens on first run:**

1. `install.sh` checks for Go, Subfinder, httpx, Katana, Naabu, Nuclei, and FFUF
2. Any missing tools are downloaded and installed automatically to `~/.local/bin`
3. PATH is updated for the current session
4. Recon begins immediately after setup completes
5. Results are written to `results/example.com/<timestamp>/`

The first run takes longer due to tool installation. Subsequent runs start immediately.

---

## 🛠️ Usage

### Single Target

```bash
./arm-recon.sh -t target.com
```

### Target List

```bash
./arm-recon.sh -l targets.txt
```

### Run Specific Module

```bash
# Only passive enumeration
./arm-recon.sh -t target.com --module enum

# Only HTTP validation
./arm-recon.sh -t target.com --module http

# Only crawler
./arm-recon.sh -t target.com --module crawl

# Only JavaScript discovery
./arm-recon.sh -t target.com --module js
```

### Full Reference

```
Usage: arm-recon.sh [OPTIONS]

Options:
  -t, --target      <domain>      Single target domain
  -l, --list        <file>        File containing list of target domains
      --module      <module>      Run a specific module only
                                  Modules: enum, http, crawl, js, ips, all
      --threads     <int>         Override default thread count (default: 50)
      --timeout     <int>         HTTP probe timeout in seconds (default: 10)
      --output      <dir>         Override default output directory
      --no-cdn                    Skip CDN filtering step
      --silent                    Suppress all console output (log only)
  -h, --help                      Show this help message
```

### Examples

```bash
# Full recon with thread override
./arm-recon.sh -t example.com --threads 100

# Recon on a list, silent mode
./arm-recon.sh -l scope.txt --silent

# Passive enumeration only, custom output directory
./arm-recon.sh -t example.com --module enum --output ~/engagements/client1/

# Skip CDN filtering (when all infrastructure is self-hosted)
./arm-recon.sh -t internal.corp --no-cdn
```

---

## ⚙️ Configuration

API keys are optional. Arm-Recon runs without them using only free passive sources. Keys unlock additional passive DNS coverage.

Edit `config/api.conf`:

```bash
# config/api.conf

# VirusTotal — passive DNS enrichment
# https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=""

# Chaos (ProjectDiscovery) — curated public program dataset
# https://cloud.projectdiscovery.io/
CHAOS_API_KEY=""

# Shodan — IP and service metadata (used in IP enrichment module)
# https://account.shodan.io/
SHODAN_API_KEY=""

# ProjectDiscovery Cloud (PDCP) — optional Nuclei cloud reporting
# https://cloud.projectdiscovery.io/
PDCP_API_KEY=""
```

> 🔑 **All keys are optional.** Without them, Arm-Recon uses Subfinder's built-in free sources plus crt.sh. Adding keys significantly increases subdomain coverage.

<details>
<summary>📋 How to obtain API keys</summary>

| Provider | URL | Free Tier |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/my-apikey | Yes (500 req/day) |
| Chaos (PDCP) | https://cloud.projectdiscovery.io/ | Yes |
| Shodan | https://account.shodan.io/ | Limited free |

</details>

---

## 📈 Performance Features

| Feature | Detail |
|---|---|
| **Concurrent Modules** | Independent modules execute in parallel using background processes |
| **Configurable Threads** | Per-tool thread counts are tunable via CLI flags or `config/settings.conf` |
| **Pipe-Safe Output** | All file writes use atomic temp-file + rename pattern — no partial writes |
| **Deduplication at Each Stage** | `sort -u` applied after every module; no file grows unbounded |
| **Rate Limiting** | httpx and Katana respect per-host rate limits to avoid triggering WAF blocks |
| **CDN Filtering** | ASN and CIDR matching against maintained CDN IP lists; no external lookups |
| **Race-Condition Resistance** | Temp files and lockfiles prevent corruption when multiple modules finish simultaneously |
| **Graceful Interruption** | `SIGINT` / `SIGTERM` handlers flush and close all output files cleanly on Ctrl+C |

---

## 🔧 Supported Tools

Arm-Recon manages installation and invocation of all dependencies automatically.

| Tool | Role | Source |
|---|---|---|
| **Subfinder** | Passive subdomain enumeration | github.com/projectdiscovery/subfinder |
| **httpx** | HTTP probing and validation | github.com/projectdiscovery/httpx |
| **Katana** | Web crawling and endpoint discovery | github.com/projectdiscovery/katana |
| **Go** | Runtime for all ProjectDiscovery tools | go.dev |
| **Nuclei** | Template-based vulnerability scanning (optional) | github.com/projectdiscovery/nuclei |
| **FFUF** | Directory and parameter fuzzing (optional) | github.com/ffuf/ffuf |
| **Naabu** | Port scanning on resolved IPs | github.com/projectdiscovery/naabu |
| **dnsx** | DNS resolution and wildcard filtering | github.com/projectdiscovery/dnsx |

---

## 📁 Project Structure

```
arm-recon/
│
├── arm-recon.sh              # Main entry point
├── install.sh                # Tool installer and environment setup
├── README.md
│
├── modules/
│   ├── enum.sh               # Passive subdomain enumeration
│   ├── http.sh               # HTTP validation with httpx
│   ├── crawl.sh              # Crawler module (Katana)
│   ├── js.sh                 # JavaScript file discovery
│   ├── ips.sh                # IP resolution and CDN filtering
│   └── cleanup.sh            # Output normalization and dedup
│
├── config/
│   ├── api.conf              # API key configuration
│   ├── settings.conf         # Thread counts, timeouts, paths
│   └── cdn_ranges.txt        # Known CDN CIDR ranges for filtering
│
├── wordlists/
│   └── resolvers.txt         # Trusted DNS resolvers list
│
├── results/                  # Auto-created — all recon output lands here
│   └── <target>/
│       └── <timestamp>/
│           ├── subdomains_alive.txt
│           ├── live_urls.txt
│           ├── js_files.txt
│           ├── live_ips.txt
│           ├── crawled_paths.txt
│           └── recon.log
│
├── docs/
│   ├── images/
│   │   ├── dashboard.png
│   │   ├── results.png
│   │   └── output.png
│   └── demo.gif
│
└── LICENSE
```

---

## 📊 Example Output

### Console (during run)

```
[arm-recon] Target       : example.com
[arm-recon] Output Dir   : results/example.com/2025-01-15_1423/
[arm-recon] Modules      : enum → http → crawl → js → ips

[enum]  Starting passive enumeration...
[enum]  Subfinder     → 214 subdomains
[enum]  crt.sh        → 89 subdomains
[enum]  Chaos         → 41 subdomains (API key detected)
[enum]  Merged total  → 287 unique subdomains

[http]  Probing 287 hosts with httpx [threads: 50]...
[http]  Live hosts    → 143 responded
[http]  Written       → results/example.com/2025-01-15_1423/live_urls.txt

[ips]   Resolving IPs for 143 live hosts...
[ips]   CDN filtered  → 31 Cloudflare, 7 Akamai (removed)
[ips]   Origin IPs    → 105 unique addresses written to live_ips.txt

[crawl] Crawling 143 live hosts with Katana [depth: 3]...
[crawl] Discovered    → 1,842 unique paths

[js]    Extracting JavaScript files...
[js]    JS files      → 94 unique .js URLs written to js_files.txt

[done]  Recon complete in 4m 12s
[done]  Results       → results/example.com/2025-01-15_1423/
```

### `subdomains_alive.txt` (excerpt)

```
api.example.com
auth.example.com
cdn-legacy.example.com
dev.example.com
internal-staging.example.com
mail.example.com
portal.example.com
vpn.example.com
```

### `live_urls.txt` (excerpt)

```
https://api.example.com [200] [Example API Gateway] [nginx/1.24.0]
https://auth.example.com [302] [Redirecting...] [cloudflare]
https://dev.example.com [200] [Dev Environment - Restricted] [Apache/2.4.52]
https://portal.example.com [403] [Forbidden] [nginx]
```

### `js_files.txt` (excerpt)

```
https://example.com/static/js/main.4f3a9b.js
https://example.com/assets/vendor.bundle.js
https://dev.example.com/js/config.js
https://api.example.com/swagger-ui/swagger-ui-bundle.js
```

---

## ❓ FAQ

<details>
<summary><strong>Does Arm-Recon require root?</strong></summary>

No. Arm-Recon runs as a standard user. The installer places tools in `~/.local/bin` and does not require `sudo`. The only exception is if Go is not installed and you choose to install it system-wide.

</details>

<details>
<summary><strong>Can I run it against multiple targets simultaneously?</strong></summary>

Yes. Pass a target list with `-l targets.txt`. The framework processes each target sequentially by default. Parallel target execution is on the roadmap.

</details>

<details>
<summary><strong>Will this work on macOS?</strong></summary>

macOS is not officially supported. Most modules will work under Homebrew with minor path adjustments, but the installer is Linux-only. A macOS compatibility layer is planned.

</details>

<details>
<summary><strong>What if a tool installation fails?</strong></summary>

The installer logs all failures to `install.log`. Re-run `./install.sh` after resolving the reported issue. If Go is not available in PATH, the installer will attempt to install it automatically. You can also install any missing tool manually — Arm-Recon detects it on the next run.

</details>

<details>
<summary><strong>How do I update the CDN filter list?</strong></summary>

Edit `config/cdn_ranges.txt` directly. The file is plain CIDR notation, one range per line. Community contributions to this list are welcome via pull request.

</details>

<details>
<summary><strong>Can I integrate this with Nuclei?</strong></summary>

Yes. `live_urls.txt` is formatted for direct input into Nuclei:

```bash
nuclei -l results/target.com/latest/live_urls.txt -t nuclei-templates/
```

</details>

---

## 🗺️ Roadmap

- [x] Passive subdomain enumeration (multi-source)
- [x] HTTP validation via httpx
- [x] Web crawling via Katana
- [x] JavaScript file extraction
- [x] CDN IP filtering
- [x] Zero-dependency auto-installer
- [x] Structured timestamped output
- [ ] Parallel multi-target execution
- [ ] Screenshot capture for live hosts (gowitness integration)
- [ ] Port scanning module (Naabu)
- [ ] Nuclei scan integration as optional final module
- [ ] macOS compatibility
- [ ] Interactive HTML report generation
- [ ] Configurable DNS resolver rotation
- [ ] Scope enforcement (in-scope / out-of-scope filtering)

---

## 🔒 Security Notice

Arm-Recon is designed for use in **authorized security assessments only**.

Before using this framework against any target:

- Obtain **explicit written authorization** from the asset owner
- Ensure your engagement scope clearly includes the target domain and all discovered subdomains
- Review applicable laws in your jurisdiction (CFAA, Computer Misuse Act, etc.)
- Do not use Arm-Recon on targets where you do not have documented permission

Unauthorized use of this tool against systems you do not own or have permission to test is **illegal** and may result in criminal prosecution.

---

## ⚠️ Disclaimer

Arm-Recon is provided for:

- **Educational purposes** — learning how recon frameworks are structured and how offensive security toolchains work
- **Authorized penetration testing** — use within scoped engagements with documented client authorization
- **Bug bounty programs** — use against assets explicitly listed in a program's scope

The authors and contributors accept **no liability** for misuse, unauthorized use, or any damage caused by the use of this framework. Users assume full responsibility for ensuring all usage is legal and authorized.

---

## 📜 License

```
MIT License

Copyright (c) 2025 Arm-Recon Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

<div align="center">

## ⭐ Star This Repository

If Arm-Recon saves you time on engagements, consider starring the repository.

It helps other security professionals discover the project.

[![Star on GitHub](https://img.shields.io/github/stars/yourhandle/arm-recon?style=social)](https://github.com/yourhandle/arm-recon)

<br>

**Built for offensive security professionals. Used responsibly.**

<br>

*Arm-Recon is not affiliated with ProjectDiscovery, Wazuh, or any third-party tool vendor.*

</div>
