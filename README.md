<div align="center">
<hr style="border:2px solid red;">
<pre>
<pre>
<img src="https://placehold.co" width="100%" height="3" alt="red divider line">
  _     ____   __  __         ____   _____   ____ 
  / \   |  _ \ |  \/  |       / ___| | ____| / ___|
 / _ \  | |_) || |\/| |      \___ \ |  _|  | |    
/ ___ \ |  _ < | |  | |  _    ___) || |___ | |___ 
/_/   \_\|_| \_\|_|  |_| (_)  |____/ |_____| \____|
</pre>

<img src="https://placehold.co" width="100%" height="3" alt="red divider line">


### Advanced Concurrency & Multi-Vector Toolkit for Professional Bug Bounty Reconnaissance

<br>

![Language](https://img.shields.io/badge/Language-Python%20%2F%20Bash-red?style=for-the-badge&logo=linux)
![Tools](https://img.shields.io/badge/Tools-SecretScanner%20%7C%20Arm--Recon-black?style=for-the-badge&logo=securityscorecard&logoColor=red)
![Platform](https://img.shields.io/badge/Platform-WSL2%20%2F%20Linux-red?style=for-the-badge&logo=ubuntu)
![License](https://img.shields.io/badge/License-MIT-black?style=for-the-badge)

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
