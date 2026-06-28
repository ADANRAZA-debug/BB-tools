# 🛡️ Arm-Recon v1.0

An enterprise-grade, asynchronous asset discovery engine designed for bug bounty hunters and red team operators. `Arm-Recon` automates multi-source passive harvesting, active validation, and directory mapping into a single, noise-filtered processing stream.

## 🏗️ Key Architecture Features

* **📦 Zero-Dependency Auto-Provisioning:** Detects, installs, and configures missing binaries (`go`, `subfinder`, `httpx`, `katana`, etc.) dynamically on first run.
* **⚡ Race-Condition Proof Concurrency:** Leverages isolated subshells and per-domain background threads to handle heavy targets without file write collisions.
* **🔍 Built-in WAF/CDN De-Blinding:** Automatically strips out RFC-1918 private scopes, loopbacks, and major CDN edges (Cloudflare, Akamai, Fastly) to keep your final target lists accurate.
* **🔄 Stream-Optimized Handshakes:** Implements pipe-safe operations (`trap '' PIPE`) to guarantee data integrity across heavy string manipulation routines.

---

## 📊 Output Architecture

Unlike standard wrapper scripts that flood your directories with raw data, `Arm-Recon` cleans up intermediate artifacts and leaves you with exactly four highly actionable files:

| Output File | Target Intel Category | Practical Next Action |
|---|---|---|
| `subdomains_alive.txt` | 🟢 Valid HTTP/HTTPS active endpoints | Feed directly into vulnerability templates (Nuclei). |
| `live_urls.txt` | 🔗 Discovered crawlable paths & parameters | Run fuzzing loops (ffuf/dirsearch) for hidden files. |
| `js_files.txt` | 📜 JavaScript resources only | Analyze for hardcoded secrets or API endpoints. |
| `live_ips.txt` | 🖥️ Valid non-CDN resolved IPv4 assets | Scan for open ports or network-level exposures. |

---

## 🚀 Getting Started

### 1. Installation & Usage
Clone the repository and make the engine executable:
```bash
git clone [https://github.com/ADANRAZA-debug/BB-tools/.git)
cd BB-tools
cd Recon
chmod +x Arm-Recon.sh
./Arm-Recon.sh --install
```

### 2. Running Full Reconnaissance
```bash
./Arm-Recon.sh -d target.com
```

### 3. Target List Ingestion (Multi-Domain Parallel Operation)
```bash
./Arm-Recon.sh -l live_domains.txt --jobs 5
```

### 4. Modular URL Harvesting (Skips passive setup, consumes local file)
```bash
./Arm-Recon.sh -d live_subs.txt -m urls,js
```

## 🔑 API Configuration
To maximize passive harvesting thresholds, export your keys into your terminal profile (`~/.bashrc` or `~/.zshrc`) or paste them inside the script config area:

```bash
export VT_API="your_virustotal_key"
export SHODAN_KEY="your_shodan_key"
export CHAOS_KEY="your_projectdiscovery_key"
```

---

## ⚠️ Important Notices

* **🛑 Running with root privileges (`sudo`):** Avoid running the entire script as root. The script uses `sudo` internally only when executing package installations (`apt-get`). Running the full script as root will clone Go paths and binaries into `/root/go/bin`, making them inaccessible during standard user runtime.
* **📉 Overloading thread counts globally:** If running on a low-tier Virtual Private Server (VPS), reduce th
