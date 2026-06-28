#!/usr/bin/env bash
# =============================================================================
#  BugHunter Recon — v6.0
#  Auto-install tools · Single unified output · Modular · Pipe-safe
#
#  Usage:
#    ./recon.sh -d target.com                    full recon (all modules)
#    ./recon.sh -d live_subs.txt -m urls         FILE as input → URLs/JS
#    ./recon.sh -l domains.txt [--jobs 5]        multi-domain parallel
#    ./recon.sh -d target.com -m passive,ips     comma-separated modules
#    ./recon.sh --install                        install / update all tools
#
#  Modules: passive | active | probe | urls | js | ips | all (default)
#
#  Final output (clean — only these files survive):
#    subdomains_alive.txt  live_urls.txt  js_files.txt  live_ips.txt
# =============================================================================
[ -z "$BASH_VERSION" ] && exec bash "$0" "$@"
set +e          # never abort on non-zero (grep returns 1 on no-match)
set -u          # catch unbound vars
trap '' PIPE    # ignore SIGPIPE (sort/head can close early)

# ── PATH — prepend Go bin dirs before any tool checks ────────────────────────
export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin:$HOME/.local/bin"

# ── Colours ──────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
C='\033[0;36m'; M='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

# =============================================================================
#  ★  API KEYS  — edit values below OR export as env vars before running
# ─────────────────────────────────────────────────────────────────────────────
#  HOW TO GET EACH FREE KEY (see --help for step-by-step URLs):
#
#  VT_API      → https://www.virustotal.com  → Sign up → Profile icon → API Key
#  GH_TOKEN    → https://github.com/settings/tokens → Generate new (classic)
#                  No scopes needed — just create and copy
#  SHODAN_KEY  → https://account.shodan.io → Overview → Your API Key (free tier)
#  CHAOS_KEY   → https://cloud.projectdiscovery.io → API Keys (free, needs signup)
#  URLSCAN_KEY → https://urlscan.io/user/profile → API Keys → Add API Key (free)
# =============================================================================
VT_API="${VT_API:-<add-here-your-token>}"    # ← paste your free 
GH_TOKEN="${GH_TOKEN:-<add-here-your-token>}"     # ← paste your free 
SHODAN_KEY="${SHODAN_KEY:-<add-here-your-token>}"   #←paste your free 
CHAOS_KEY="${CHAOS_KEY:-}"         # ← paste your free Chaos/PDCP key here
URLSCAN_KEY="${URLSCAN_KEY:-}"     # ← paste your free URLScan key here

# ── Defaults (override with flags) ───────────────────────────────────────────
OUT_DIR="./recon_output"
RUN_MODULES="all"
MAX_JOBS=3
CURL_TO=30
VALID_MODULES=(passive active probe urls js ips all)

# =============================================================================
#  HELPERS
# =============================================================================
_i()  { echo -e "${B}[*]${NC} $*"; }
_ok() { echo -e "${G}[+]${NC} $*"; }
_w()  { echo -e "${Y}[!]${NC} $*"; }
_e()  { echo -e "${R}[✗]${NC} $*"; }
_hd() { echo -e "\n${BOLD}${C}══════ $* ══════${NC}"; }

# Count non-empty lines in a file (returns 0 if missing)
nl() { [ -f "$1" ] && grep -c '' "$1" 2>/dev/null || echo 0; }

safe_curl() {
    curl -sk --max-time "$CURL_TO" --retry 2 --retry-delay 3 \
         -H "User-Agent: Mozilla/5.0 (compatible; recon/6.0)" \
         "$@" 2>/dev/null || true
}

# Extract valid public IPv4 from stdin, drop RFC-1918 / loopback / link-local
pub_ips() {
    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' 2>/dev/null \
        | grep -vE '^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|224\.|255\.)' \
        || true
}

# CDN / WAF prefix filter (Cloudflare, Fastly, Akamai, CloudFront, Imperva…)
_CDN='^(173\.245\.|103\.2[12]\.|103\.31\.|141\.101\.|108\.162\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.|162\.158\.|104\.1[6-9]\.|104\.2[0-7]\.|172\.6[4-9]\.|172\.7[01]\.|151\.101\.|13\.3[23]\.|13\.35\.|52\.84\.|64\.252\.|99\.86\.|130\.176\.|205\.251\.|204\.246\.|23\.(235|236|237)\.)'
no_cdn() { grep -vE "$_CDN" 2>/dev/null || true; }

uniq_sort() {  # sort a file in-place safely
    [ -f "$1" ] || return
    local t; t=$(mktemp)
    sort -u "$1" > "$t" && mv "$t" "$1" || rm -f "$t"
}

# Returns 0 if module $1 should run
mod() {
    [[ "$RUN_MODULES" == "all" ]] && return 0
    local IFS=',' m
    for m in $RUN_MODULES; do
        [[ "${m// /}" == "$1" ]] && return 0
    done
    return 1
}

validate_modules() {
    local IFS=',' m v ok
    for m in $RUN_MODULES; do
        m="${m// /}"; ok=0
        for v in "${VALID_MODULES[@]}"; do [[ "$m" == "$v" ]] && ok=1 && break; done
        [[ $ok -eq 0 ]] && { _e "Unknown module '$m'. Valid: ${VALID_MODULES[*]}"; exit 1; }
    done
}

# =============================================================================
#  AUTO-INSTALL ALL TOOLS
# =============================================================================
install_tools() {
    _hd "TOOL AUTO-INSTALL"

    # ── jq ────────────────────────────────────────────────────────────────────
    command -v jq &>/dev/null || {
        _i "Installing jq..."; sudo apt-get install -y -qq jq 2>/dev/null \
            || sudo yum install -y -q jq 2>/dev/null || _w "jq install failed — install manually"; }

    # ── Go ────────────────────────────────────────────────────────────────────
    if ! command -v go &>/dev/null; then
        _i "Installing Go 1.22..."
        local arch; arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/armv7l/armv6l/')
        local tar="go1.22.4.linux-${arch}.tar.gz"
        curl -fsSL "https://go.dev/dl/${tar}" -o "/tmp/${tar}" 2>/dev/null \
            && sudo rm -rf /usr/local/go \
            && sudo tar -C /usr/local -xzf "/tmp/${tar}" 2>/dev/null \
            && export PATH="$PATH:/usr/local/go/bin" \
            && _ok "Go installed" || _w "Go install failed"
        rm -f "/tmp/${tar}"
    fi
    export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin:$HOME/go/bin"

    # ── Go-based tools ────────────────────────────────────────────────────────
    declare -A GO_TOOLS=(
        [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        [assetfinder]="github.com/tomnomnom/assetfinder@latest"
        [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
        [gau]="github.com/lc/gau/v2/cmd/gau@latest"
        [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        [chaos]="github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        [github-subdomains]="github.com/gwen001/github-subdomains@latest"
        [gospider]="github.com/jaeles-project/gospider@latest"
        [hakrawler]="github.com/hakluke/hakrawler@latest"
        [shosubgo]="github.com/incogbyte/shosubgo@latest"
    )
    for tool in "${!GO_TOOLS[@]}"; do
        command -v "$tool" &>/dev/null && { _ok "$tool ✓"; continue; }
        _i "Installing $tool ..."
        go install "${GO_TOOLS[$tool]}" 2>/dev/null \
            && _ok "$tool installed" || _w "$tool failed — check Go is in PATH"
    done

    # ── waymore (Python) ──────────────────────────────────────────────────────
    command -v waymore &>/dev/null && { _ok "waymore ✓"; } || {
        _i "Installing waymore ..."
        if command -v pipx &>/dev/null; then
            pipx install waymore 2>/dev/null && _ok "waymore installed (pipx)" || _w "waymore pipx failed"
        elif command -v pip3 &>/dev/null; then
            pip3 install waymore --quiet 2>/dev/null && _ok "waymore installed (pip3)" || _w "waymore pip3 failed"
        else
            _w "pip3/pipx not found — install Python3 then: pip3 install waymore"
        fi
    }

    export PATH="$PATH:$HOME/go/bin"
    echo ""
    _ok "Install complete — re-run the script to start recon"
}

# Warn (not abort) about missing optional tools
check_soft_deps() {
    local missing=()
    for t in subfinder assetfinder httpx katana gau; do
        command -v "$t" &>/dev/null || missing+=("$t")
    done
    [ ${#missing[@]} -gt 0 ] && {
        _w "Missing tools: ${missing[*]}"
        _w "Run:  $0 --install   to auto-install everything"
    }
}

# =============================================================================
#  MODULE: PASSIVE SUBDOMAIN SOURCES
# =============================================================================
do_passive() {
    local domain="$1" D="$2"
    _hd "PASSIVE — $domain"
    local tmp; tmp=$(mktemp -d)

    # crt.sh
    safe_curl "https://crt.sh/?q=%.${domain}&output=json" \
        | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | tr ',' '\n' \
        | grep -E "(^|\.)${domain//./\\.}$" | sort -u > "$tmp/crt.txt" || touch "$tmp/crt.txt"
    _ok "  crt.sh        $(nl "$tmp/crt.txt")"

    # Wayback Machine
    safe_curl "http://web.archive.org/cdx/search/cdx?url=*.${domain}/&output=text&fl=original&collapse=urlkey" \
        | sed -e 's_https*://__' -e 's_/.*__' -e 's_:.*__' \
        | grep -E "(^|\.)${domain//./\\.}$" | sort -u > "$tmp/wb.txt" || touch "$tmp/wb.txt"
    _ok "  Wayback       $(nl "$tmp/wb.txt")"

    # VirusTotal
    [[ -n "$VT_API" ]] && {
        safe_curl "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${VT_API}&domain=${domain}" \
            | jq -r '.domain_siblings[]? // empty' 2>/dev/null \
            | grep -E "(^|\.)${domain//./\\.}$" | sort -u > "$tmp/vt.txt" || touch "$tmp/vt.txt"
        _ok "  VirusTotal    $(nl "$tmp/vt.txt")"; } || touch "$tmp/vt.txt"

    # HackerTarget
    safe_curl "https://api.hackertarget.com/hostsearch/?q=${domain}" \
        | cut -d',' -f1 | grep -E "(^|\.)${domain//./\\.}$" | sort -u > "$tmp/ht.txt" || touch "$tmp/ht.txt"
    _ok "  HackerTarget  $(nl "$tmp/ht.txt")"

    # URLScan.io
    local us_h=(); [[ -n "$URLSCAN_KEY" ]] && us_h=(-H "API-Key: $URLSCAN_KEY")
    safe_curl "${us_h[@]}" "https://urlscan.io/api/v1/search/?q=domain:${domain}&size=10000" \
        | jq -r '.results[]?.page?.domain // empty' 2>/dev/null \
        | grep -E "(^|\.)${domain//./\\.}$" | sort -u > "$tmp/us.txt" || touch "$tmp/us.txt"
    _ok "  URLScan.io    $(nl "$tmp/us.txt")"

    # CommonCrawl (latest index)
    safe_curl "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.${domain}&output=json" \
        | jq -r '.url' 2>/dev/null | sed -e 's_https*://__' -e 's_/.*__' \
        | grep -E "(^|\.)${domain//./\\.}$" | sort -u > "$tmp/cc.txt" || touch "$tmp/cc.txt"
    _ok "  CommonCrawl   $(nl "$tmp/cc.txt")"

    # OTX AlienVault
    safe_curl "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns" \
        | jq -r '.passive_dns[]?.hostname // empty' 2>/dev/null \
        | grep -E "(^|\.)${domain//./\\.}$" | sort -u > "$tmp/otx.txt" || touch "$tmp/otx.txt"
    _ok "  OTX           $(nl "$tmp/otx.txt")"

    # RapidDNS
    safe_curl "https://rapiddns.io/subdomain/${domain}?full=1#result" \
        | grep -oP "[a-zA-Z0-9._-]+\\.${domain//./\\.}" | sort -u > "$tmp/rd.txt" || touch "$tmp/rd.txt"
    _ok "  RapidDNS      $(nl "$tmp/rd.txt")"

    # BufferOver
    safe_curl "https://dns.bufferover.run/dns?q=.${domain}" \
        | jq -r '.FDNS_A[]? // empty' 2>/dev/null | cut -d',' -f2 \
        | grep -E "(^|\.)${domain//./\\.}$" | sort -u > "$tmp/bo.txt" || touch "$tmp/bo.txt"
    _ok "  BufferOver    $(nl "$tmp/bo.txt")"

    # Merge into domain-specific file (race-condition safe)
    local out="$D/passive_${domain//./_}.txt"
    cat "$tmp"/*.txt 2>/dev/null | grep -E "^[a-zA-Z0-9._-]+\\.${domain//./\\.}$" \
        | sort -u > "$out" || touch "$out"
    rm -rf "$tmp"
    _ok "Passive done → $(nl "$out") subs for $domain"
}

# =============================================================================
#  MODULE: ACTIVE TOOL-BASED ENUMERATION
# =============================================================================
do_active() {
    local domain="$1" D="$2"
    _hd "ACTIVE — $domain"
    local tmp; tmp=$(mktemp -d)

    command -v subfinder &>/dev/null && {
        subfinder -d "$domain" -all -recursive -silent -o "$tmp/sf.txt" 2>/dev/null || touch "$tmp/sf.txt"
        _ok "  subfinder      $(nl "$tmp/sf.txt")"; } || _w "  subfinder — not found"

    command -v assetfinder &>/dev/null && {
        assetfinder --subs-only "$domain" 2>/dev/null \
            | grep -E "(^|\.)${domain//./\\.}$" | sort -u > "$tmp/af.txt" || touch "$tmp/af.txt"
        _ok "  assetfinder    $(nl "$tmp/af.txt")"; } || _w "  assetfinder — not found"

    command -v chaos &>/dev/null && {
        local ck=(); [[ -n "$CHAOS_KEY" ]] && ck=(-key "$CHAOS_KEY")
        chaos -d "$domain" "${ck[@]}" -silent 2>/dev/null | sort -u > "$tmp/ch.txt" || touch "$tmp/ch.txt"
        _ok "  chaos          $(nl "$tmp/ch.txt")"; } || _w "  chaos — not found"

    command -v github-subdomains &>/dev/null && [[ -n "$GH_TOKEN" ]] && {
        github-subdomains -d "$domain" -t "$GH_TOKEN" 2>/dev/null \
            | grep -E "(^|\.)${domain//./\\.}$" | sort -u > "$tmp/gh.txt" || touch "$tmp/gh.txt"
        _ok "  github-subs    $(nl "$tmp/gh.txt")"; } || _w "  github-subdomains — not found or no token"

    command -v shosubgo &>/dev/null && [[ -n "$SHODAN_KEY" ]] && {
        shosubgo -d "$domain" -s "$SHODAN_KEY" 2>/dev/null \
            | grep -E "(^|\.)${domain//./\\.}$" | sort -u > "$tmp/sho.txt" || touch "$tmp/sho.txt"
        _ok "  shosubgo       $(nl "$tmp/sho.txt")"; } || _w "  shosubgo — not found or no key"

    local out="$D/active_${domain//./_}.txt"
    cat "$tmp"/*.txt 2>/dev/null | grep -E "^[a-zA-Z0-9._-]+\\.${domain//./\\.}$" \
        | sort -u > "$out" || touch "$out"
    rm -rf "$tmp"
    _ok "Active done → $(nl "$out") subs for $domain"
}

# =============================================================================
#  MODULE: PROBE — httpx live-host check
# =============================================================================
do_probe() {
    local D="$1"
    _hd "LIVE HOST PROBE"
    local subfile="$D/all_subs.txt"

    if ! [ -s "$subfile" ]; then
        _w "No subdomains to probe — run passive/active first"; touch "$D/subdomains_alive.txt"; return; fi

    _ok "Total unique subs: $(nl "$subfile")"

    if ! command -v httpx &>/dev/null; then
        _w "httpx not found — copying raw subs as fallback"
        cp "$subfile" "$D/subdomains_alive.txt"; return; fi

    httpx -l "$subfile" -ports 80,443,8080,8000,8888 \
          -threads 200 -silent \
          -o "$D/subdomains_alive.txt" 2>/dev/null || touch "$D/subdomains_alive.txt"
    _ok "Live subdomains → $(nl "$D/subdomains_alive.txt")"
}

# =============================================================================
#  MODULE: URL DISCOVERY
# =============================================================================
do_urls() {
    local D="$1" ext_input="$2"
    _hd "URL DISCOVERY"
    local input=""

    # Input priority: explicit file → subdomains_alive → all_subs
    if   [[ -n "$ext_input" && -s "$ext_input" ]]; then input="$ext_input"
         _ok "Input: $ext_input ($(nl "$ext_input") hosts)"
    elif [ -s "$D/subdomains_alive.txt" ]; then        input="$D/subdomains_alive.txt"
         _ok "Input: subdomains_alive.txt ($(nl "$input") hosts)"
    elif [ -s "$D/all_subs.txt" ]; then                input="$D/all_subs.txt"
         _w "Fallback to all_subs.txt ($(nl "$input") subs — not probed)"
    else
        _e "No input for URL discovery."
        _e "Fix: run passive+active+probe first, OR:  ./recon.sh -d live_hosts.txt -m urls"
        touch "$D/live_urls.txt"; return
    fi

    local tmp; tmp=$(mktemp -d)

    # ── katana ────────────────────────────────────────────────────────────────
    command -v katana &>/dev/null && {
        katana -list "$input" -d 2 -silent -o "$tmp/katana.txt" 2>/dev/null || touch "$tmp/katana.txt"
        _ok "  katana    $(nl "$tmp/katana.txt")"; } || { _w "  katana not found"; touch "$tmp/katana.txt"; }

    # ── gau ───────────────────────────────────────────────────────────────────
    command -v gau &>/dev/null && {
        sed 's_https*://__g' "$input" 2>/dev/null \
            | gau --threads 5 --blacklist ttf,woff,woff2,eot,svg,png,jpg,gif \
                  2>/dev/null | sort -u > "$tmp/gau.txt" || touch "$tmp/gau.txt"
        _ok "  gau       $(nl "$tmp/gau.txt")"; } || { _w "  gau not found"; touch "$tmp/gau.txt"; }

    # ── waymore ───────────────────────────────────────────────────────────────
    command -v waymore &>/dev/null && {
        # waymore needs bare hostnames
        sed 's_https*://__g; s_/.*__; s_:.*__' "$input" | sort -u > "$tmp/_wm_hosts.txt"
        waymore -i "$tmp/_wm_hosts.txt" -mode U -oU "$tmp/waymore.txt" 2>/dev/null || touch "$tmp/waymore.txt"
        _ok "  waymore   $(nl "$tmp/waymore.txt")"; } || { _w "  waymore not found"; touch "$tmp/waymore.txt"; }

    # ── gospider ──────────────────────────────────────────────────────────────
    command -v gospider &>/dev/null && {
        local gs; gs=$(mktemp -d)
        gospider -S "$input" -c 10 -d 2 --sitemap --robots \
                 -o "$gs" --quiet 2>/dev/null || true
        grep -hroE 'https?://[^ "]+' "$gs"/ 2>/dev/null \
            | sort -u > "$tmp/gospider.txt" || touch "$tmp/gospider.txt"
        rm -rf "$gs"
        _ok "  gospider  $(nl "$tmp/gospider.txt")"; } || { _w "  gospider not found"; touch "$tmp/gospider.txt"; }

    # ── hakrawler ─────────────────────────────────────────────────────────────
    command -v hakrawler &>/dev/null && {
        hakrawler -d 2 -subs < "$input" 2>/dev/null \
            | sort -u > "$tmp/hakrawler.txt" || touch "$tmp/hakrawler.txt"
        _ok "  hakrawler $(nl "$tmp/hakrawler.txt")"; } || { _w "  hakrawler not found"; touch "$tmp/hakrawler.txt"; }

    # ── Merge all URL sources ─────────────────────────────────────────────────
    local merged="$tmp/all_merged.txt"
    cat "$tmp"/*.txt 2>/dev/null | grep -Eo 'https?://[^ ]+' | sort -u > "$merged"
    _ok "Total unique URLs (pre-probe): $(nl "$merged")"

    # ── Probe live ────────────────────────────────────────────────────────────
    if command -v httpx &>/dev/null && [ -s "$merged" ]; then
        httpx -l "$merged" -silent -o "$D/live_urls.txt" 2>/dev/null || touch "$D/live_urls.txt"
    else
        cp "$merged" "$D/live_urls.txt" 2>/dev/null || touch "$D/live_urls.txt"
    fi
    _ok "Live URLs → $(nl "$D/live_urls.txt")"
    rm -rf "$tmp"
}

# =============================================================================
#  MODULE: JS FILE EXTRACTION
# =============================================================================
do_js() {
    local D="$1"
    _hd "JS FILE EXTRACTION"
    local src="$D/live_urls.txt"

    if ! [ -s "$src" ]; then
        _w "live_urls.txt is empty — run urls module first"; touch "$D/js_files.txt"; return; fi

    grep -iE '\.js(\?|$)' "$src" 2>/dev/null \
        | grep -ivE '\.(json|jsx|ts|tsx)(\?|$)' \
        | sort -u > "$D/js_files.txt" || touch "$D/js_files.txt"
    _ok "JS files → $(nl "$D/js_files.txt")"
}

# =============================================================================
#  MODULE: IP DISCOVERY (per-domain, parallel sources)
# =============================================================================
do_ips_domain() {
    local domain="$1" D="$2"
    _hd "IP SOURCES — $domain"
    local tmp; tmp=$(mktemp -d)
    local pids=()

    # ── Parallel API sources ──────────────────────────────────────────────────
    (safe_curl "https://otx.alienvault.com/api/v1/indicators/hostname/${domain}/url_list?limit=500&page=1" \
        | jq -r '.url_list[]?.result?.urlworker?.ip // empty' 2>/dev/null \
        | pub_ips | sort -u > "$tmp/otx.txt") & pids+=($!)

    (safe_curl "https://urlscan.io/api/v1/search/?q=domain:${domain}&size=10000" \
        | jq -r '.results[]?.page?.ip // empty' 2>/dev/null \
        | pub_ips | sort -u > "$tmp/urlscan.txt") & pids+=($!)

    ([[ -n "$VT_API" ]] && safe_curl "https://www.virustotal.com/vtapi/v2/domain/report?domain=${domain}&apikey=${VT_API}" \
        | jq -r '.. | .ip_address? // empty' 2>/dev/null | pub_ips | sort -u > "$tmp/vt.txt" \
        || touch "$tmp/vt.txt") & pids+=($!)

    (safe_curl "https://api.hackertarget.com/hostsearch/?q=${domain}" \
        | cut -d',' -f2 | pub_ips | sort -u > "$tmp/ht.txt") & pids+=($!)

    (safe_curl "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${domain}" \
        | jq -r '.resolutions[]?.ip_address // empty' 2>/dev/null \
        | pub_ips | sort -u > "$tmp/tc.txt") & pids+=($!)

    (safe_curl "https://api.threatminer.org/v2/domain.php?q=${domain}&rt=2" \
        | jq -r '.results[]? // empty' 2>/dev/null | pub_ips | sort -u > "$tmp/tm.txt") & pids+=($!)

    (safe_curl "https://api.bgpview.io/search?query_term=${domain}" \
        | jq -r '.data.ip_addresses[]?.ip_address // empty' 2>/dev/null \
        | pub_ips | sort -u > "$tmp/bgp.txt") & pids+=($!)

    (safe_curl "https://viewdns.info/iphistory/?domain=${domain}" \
        | pub_ips | sort -u > "$tmp/vdns.txt") & pids+=($!)

    (safe_curl "https://rapiddns.io/subdomain/${domain}?full=1" \
        | pub_ips | sort -u > "$tmp/rd.txt") & pids+=($!)

    for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done

    # ── DNS resolve (uses this domain's passive+active subs) ──────────────────
    local dom_subs; dom_subs=$(mktemp)
    cat "$D/passive_${domain//./_}.txt" "$D/active_${domain//./_}.txt" 2>/dev/null \
        | sort -u > "$dom_subs"
    if [ -s "$dom_subs" ]; then
        if command -v dnsx &>/dev/null; then
            dnsx -l "$dom_subs" -a -resp-only -silent 2>/dev/null \
                | pub_ips | sort -u > "$tmp/dns.txt" || touch "$tmp/dns.txt"
            _ok "  DNS/dnsx  $(nl "$tmp/dns.txt")"
        elif command -v dig &>/dev/null; then
            while IFS= read -r s; do
                dig +short +time=3 +tries=1 A "$s" 2>/dev/null
            done < "$dom_subs" | pub_ips | sort -u > "$tmp/dns.txt" || touch "$tmp/dns.txt"
            _ok "  DNS/dig   $(nl "$tmp/dns.txt")"
        fi
    fi
    rm -f "$dom_subs"

    # ── Merge + CDN filter → domain-specific file (no shared-file races) ──────
    local out="$D/ips_raw_${domain//./_}.txt"
    cat "$tmp"/*.txt 2>/dev/null | pub_ips | no_cdn | sort -u > "$out" || touch "$out"
    _ok "$domain → $(nl "$out") IPs (CDN filtered)"
    rm -rf "$tmp"
}

# Finalize: merge all domain IP files → httpx probe → live_ips.txt
finalize_ips() {
    local D="$1"
    _hd "IP FINALIZATION"

    # Merge all per-domain IP files
    local merged="$D/_all_ips_merged.txt"
    cat "$D"/ips_raw_*.txt 2>/dev/null | sort -u > "$merged" || touch "$merged"
    rm -f "$D"/ips_raw_*.txt 2>/dev/null
    _ok "Total unique IPs (all domains, CDN filtered): $(nl "$merged")"

    if ! [ -s "$merged" ]; then
        _w "No IPs collected"; touch "$D/live_ips.txt"; rm -f "$merged"; return; fi

    if command -v httpx &>/dev/null; then
        httpx -l "$merged" \
              -ports 80,443,8080,8443,8000,8888,3000,9090 \
              -sc -title -td -server -silent -threads 100 2>/dev/null \
            | grep -vE    '\[(400|403|404)\]' \
            | grep -ivE   'cloudflare|incapsula|sucuri|akamaighost' \
            > "$D/live_ips.txt" || touch "$D/live_ips.txt"
        _ok "Live IPs → $(nl "$D/live_ips.txt")"
    else
        _w "httpx not found — saving raw IPs"
        cp "$merged" "$D/live_ips.txt"
    fi
    rm -f "$merged"
}

# =============================================================================
#  SUMMARY
# =============================================================================
print_summary() {
    local D="$1" t0="$2"
    local elapsed=$(( $(date +%s) - t0 ))
    echo ""
    echo -e "${BOLD}${C}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${C}║   FINAL OUTPUT — $D${NC}"
    echo -e "${BOLD}${C}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    local files=(subdomains_alive.txt live_urls.txt js_files.txt live_ips.txt)
    for f in "${files[@]}"; do
        local n; n=$(nl "$D/$f")
        if [[ $n -gt 0 ]]; then printf "  ${G}✓${NC}  %-28s %s entries\n" "$f" "$n"
        else                     printf "  ${Y}–${NC}  %-28s empty\n"      "$f"; fi
    done
    echo ""
    echo -e "  Elapsed: ${elapsed}s"
    echo ""
}

# =============================================================================
#  USAGE
# =============================================================================
usage() {
    echo -e "${BOLD}${B}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║   BugHunter Recon v6.0                                       ║"
    echo "║   Auto-install · Single output · Modular · Parallel          ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "  $0 -d target.com                    full recon (all modules)"
    echo "  $0 -d live_hosts.txt -m urls        file → URL discovery"
    echo "  $0 -d live_hosts.txt -m urls,js     file → URLs + JS"
    echo "  $0 -l domains.txt [--jobs 5]        multi-domain parallel"
    echo "  $0 -d target.com -m passive,ips     selective modules"
    echo "  $0 --install                        install / update all tools"
    echo ""
    echo "  Modules: passive | active | probe | urls | js | ips | all"
    echo ""
    echo -e "${BOLD}  API Keys — edit lines 34–44 of script OR set as env vars:${NC}"
    printf "  %-14s %s\n" "VT_API"      "→ virustotal.com → Profile → API Key tab (free)"
    printf "  %-14s %s\n" "GH_TOKEN"    "→ github.com/settings/tokens → classic, no scopes (free)"
    printf "  %-14s %s\n" "SHODAN_KEY"  "→ account.shodan.io → Overview page (free tier)"
    printf "  %-14s %s\n" "CHAOS_KEY"   "→ cloud.projectdiscovery.io → API Keys (free signup)"
    printf "  %-14s %s\n" "URLSCAN_KEY" "→ urlscan.io → Settings → API Keys → Add (free)"
    echo ""
    echo "  Or: export VT_API=xxx && ./recon.sh -d target.com"
    exit 1
}

# =============================================================================
#  MAIN
# =============================================================================
[[ $# -eq 0 ]] && usage

TARGET="" DOMAIN_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d)           TARGET="$2";                                         shift 2 ;;
        -l)           DOMAIN_FILE="$2";                                    shift 2 ;;
        -m|--module)  RUN_MODULES=$(echo "$2" | tr '[:upper:]' '[:lower:]'); shift 2 ;;
        -o|--output)  OUT_DIR="$2";                                        shift 2 ;;
        --jobs)       MAX_JOBS="$2";                                       shift 2 ;;
        --install)    install_tools; exit 0 ;;
        -h|--help)    usage ;;
        *)            _e "Unknown option: $1"; usage ;;
    esac
done

validate_modules
mkdir -p "$OUT_DIR"
export RUN_MODULES OUT_DIR VT_API GH_TOKEN SHODAN_KEY CHAOS_KEY URLSCAN_KEY CURL_TO _CDN

echo -e "${BOLD}${B}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║   BugHunter Recon v6.0  —  $(date '+%F %T')              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Detect if -d arg is a FILE (existing host list) vs a domain name ─────────
FILE_INPUT=""
DOMAINS=()

if [[ -n "$TARGET" ]]; then
    if [[ -f "$TARGET" ]]; then
        FILE_INPUT="$TARGET"
        _ok "File input detected: $TARGET ($(nl "$TARGET") lines)"
    else
        DOMAINS=("$TARGET")
    fi
fi

if [[ -n "$DOMAIN_FILE" ]]; then
    [[ -f "$DOMAIN_FILE" ]] || { _e "File not found: $DOMAIN_FILE"; exit 1; }
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"; line="${line// /}"; [[ -z "$line" ]] && continue
        DOMAINS+=("$line")
    done < "$DOMAIN_FILE"
fi

# ── File-only mode: skip domain steps, run urls/js directly ──────────────────
if [[ -n "$FILE_INPUT" && ${#DOMAINS[@]} -eq 0 ]]; then
    _ok "File-input mode — domain-based modules (passive/active/ips) skipped"
    T0=$(date +%s)
    mod "urls" && do_urls "$OUT_DIR" "$FILE_INPUT"
    mod "js"   && do_js   "$OUT_DIR"
    print_summary "$OUT_DIR" "$T0"
    exit 0
fi

[[ ${#DOMAINS[@]} -eq 0 ]] && { _e "No domains provided. Use -d domain or -l list.txt"; usage; }

# ── Auto-install if core tools missing ───────────────────────────────────────
_need=0
for t in subfinder httpx katana gau; do command -v "$t" &>/dev/null || { _need=1; break; }; done
[[ $_need -eq 1 ]] && { _w "Core tools missing — running auto-install first..."; install_tools; }

check_soft_deps
_ok "${#DOMAINS[@]} domain(s) | modules: $RUN_MODULES | output: $OUT_DIR | parallel jobs: $MAX_JOBS"

T0=$(date +%s)

# ── Per-domain function (runs as background subshell) ────────────────────────
# Subshells inherit all functions + variables — no export -f needed
run_domain() {
    local domain="$1"
    mod "passive" && do_passive    "$domain" "$OUT_DIR"
    mod "active"  && do_active     "$domain" "$OUT_DIR"
    mod "ips"     && do_ips_domain "$domain" "$OUT_DIR"
}

# ── Parallel domain execution ─────────────────────────────────────────────────
running=0
for dom in "${DOMAINS[@]}"; do
    run_domain "$dom" &
    (( ++running ))
    if (( running >= MAX_JOBS )); then
        wait        # wait for current batch, then reset (bash 3+ compatible)
        running=0
    fi
done
wait    # catch any remaining jobs

# ── Merge per-domain subdomain files → single all_subs.txt ───────────────────
_hd "MERGING ALL SUBDOMAIN FILES"
cat "$OUT_DIR"/passive_*.txt "$OUT_DIR"/active_*.txt 2>/dev/null \
    | sort -u > "$OUT_DIR/all_subs.txt" || touch "$OUT_DIR/all_subs.txt"
rm -f "$OUT_DIR"/passive_*.txt "$OUT_DIR"/active_*.txt 2>/dev/null
_ok "All unique subdomains: $(nl "$OUT_DIR/all_subs.txt")"

# ── Sequential post-processing (depends on prior steps) ──────────────────────
mod "probe" && do_probe      "$OUT_DIR"
mod "urls"  && do_urls       "$OUT_DIR" "$FILE_INPUT"
mod "js"    && do_js         "$OUT_DIR"
mod "ips"   && finalize_ips  "$OUT_DIR"

# ── Cleanup intermediate files ────────────────────────────────────────────────
rm -f "$OUT_DIR/all_subs.txt" 2>/dev/null

print_summary "$OUT_DIR" "$T0"
