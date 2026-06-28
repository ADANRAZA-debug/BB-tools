<div align="center">

# 🛠️ BB-Tools

### Advanced Concurrency & Multi-Vector Toolkit for Professional Bug Bounty Reconnaissance

<br>

![Python](https://shields.io)
![Tools Included](https://shields.io)
![License](https://shields.io)
![Platform](https://shields.io)

<br>

> A centralized collection of high-concurrency security assessment utilities designed for automation-heavy asset mapping and data exposure workflows.

</div>

---

## 🧰 Current Toolset

### 1. 🔍 SecretScanner
An asynchronous, deobfuscation-aware credential and API key discovery framework.
* **Intelligent Scanning**: Analyzes JavaScript bundles, source maps, subdomains, and predictable endpoint paths.
* **Deep Deobfuscation**: Strips out obfuscation layers (Hex/Unicode encoding, Base64 strings, array reassembly) without code execution.
* **High Signal**: Filters findings via Shannon Entropy and strict JS-identifier rules to minimize false-positive triage time.
* **Exposure Probing**: Actively maps 133 distinct leak paths, targeting exposed `.env` configs, backup items, and cloud-provider templates.

### 2. 🛡️ Arm-Recon
An active target reconnaissance and asset-mapping command-line utility.
* **Automated Discovery**: High-velocity multi-vector active discovery engine built to map unknown perimeter surfaces.
* **Asset Mapping**: Handles fast DNS/vhost brute-forcing alongside port scanning and active service fingerprint integration.
* **Pipeline Integration**: Built natively to chain target asset logs directly into scanning engines like SecretScanner.
