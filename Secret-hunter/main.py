#!/usr/bin/env python3
"""
Secret Scanner — comprehensive API key / token / secret detector
==================================================================
150+ branded detection signatures, deobfuscation for minified/obfuscated JS,
entropy-based false-positive filtering, async high-concurrency scanning.

Usage:
  python main.py -f domains.txt
  python main.py -f domains.txt --subs              # auto subdomain discovery
  python main.py -f domains.txt --raw                # show unmasked secrets
  python main.py -f domains.txt -o ./out --concurrency 50
  python main.py --js-list jsfiles.txt                # scan a list of JS URLs directly

domains.txt supports:
  example.com              plain domain
  *.example.com            wildcard — auto-runs subdomain discovery
  # comment lines ignored
"""

import asyncio
import argparse
import re
import sys
from pathlib import Path
from datetime import datetime

from scraper import SecretScraper, DomainResult
from engine import scan_text
from reporter import generate_reports
from ui import ScannerUI

_WILDCARD_RE = re.compile(r'^\*\.(\w[\w\-\.]+\.\w+)$')


def load_domains(filepath: str) -> tuple:
    path = Path(filepath)
    if not path.exists():
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    plain, wildcards = [], []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = line.replace("https://", "").replace("http://", "").rstrip("/")
            m = _WILDCARD_RE.match(line)
            if m:
                wildcards.append(m.group(1))
            else:
                plain.append(line)

    if not plain and not wildcards:
        print("[ERROR] No domains found in file.")
        sys.exit(1)
    return plain, wildcards


def load_url_list(filepath: str) -> list:
    path = Path(filepath)
    if not path.exists():
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    urls = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls


def ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def parse_args():
    p = argparse.ArgumentParser(
        description="Secret Scanner — find leaked API keys, tokens, and secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -f domains.txt
  python main.py -f domains.txt --subs --concurrency 50
  python main.py -f domains.txt --raw -o ./reports
  python main.py --js-list urls.txt
        """
    )
    p.add_argument("-f", "--file", help=".txt file with domains (one per line, supports *.domain.com wildcards)")
    p.add_argument("--js-list", help=".txt file with direct JS/page URLs to scan (skips domain crawling)")
    p.add_argument("--concurrency", type=int, default=30, help="Concurrent domains (default 30)")
    p.add_argument("--per-domain-concurrency", type=int, default=25, help="Concurrent requests per domain (default 25)")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout seconds (default 10)")
    p.add_argument("--max-js", type=int, default=80, help="Max JS files scanned per domain (default 80)")
    p.add_argument("--no-sourcemaps", action="store_true", help="Skip .map source map scanning")
    p.add_argument("-o", "--output-dir", default="./reports", help="Report output directory")
    p.add_argument("--raw", action="store_true", help="Show/store UNMASKED secret values (sensitive — handle output carefully)")
    p.add_argument("--subs", action="store_true", help="Auto-discover subdomains via crt.sh + DNS brute-force")
    p.add_argument("--no-brute", action="store_true", help="With --subs: skip DNS brute-force, crt.sh only")
    return p.parse_args()


async def run_js_list_scan(args, ui: ScannerUI, output_dir: Path, timestamp: str):
    """Scan a flat list of JS/page URLs directly — no domain crawling."""
    import aiohttp
    urls = load_url_list(args.js_list)
    ui.print_banner(len(urls))

    scraper = SecretScraper(
        concurrency=args.concurrency,
        per_domain_concurrency=args.per_domain_concurrency,
        timeout=args.timeout,
    )

    sem = asyncio.Semaphore(args.concurrency)
    connector = aiohttp.TCPConnector(limit=args.concurrency * 2, ssl=False)

    results_holder = []

    async def fetch_and_scan(url):
        async with sem:
            content = await scraper._fetch_content(session, url)
        if content:
            domain = url.split("/")[2] if "://" in url else url
            findings = scan_text(content, url, "JS/Page", domain)
            results_holder.append((domain, findings))
        ui._progress.advance(ui._task) if ui._progress else None

    ui.start_progress(len(urls))
    start = datetime.now()
    async with aiohttp.ClientSession(connector=connector) as session:
        await asyncio.gather(*[fetch_and_scan(u) for u in urls], return_exceptions=True)
    elapsed = (datetime.now() - start).total_seconds()

    # Group into DomainResult-like objects for the reporter
    by_domain = {}
    for domain, findings in results_holder:
        if domain not in by_domain:
            by_domain[domain] = DomainResult(domain=domain, status="ok")
        by_domain[domain].findings += findings
        by_domain[domain].paths_scanned += 1

    results = list(by_domain.values())
    ui.print_summary(results, elapsed, show_raw=args.raw)

    paths = generate_reports(results, output_dir, timestamp, show_raw=args.raw)
    ui.print_report_paths(paths)


async def run_domain_scan(args, ui: ScannerUI, output_dir: Path, timestamp: str):
    from subdomains import enumerate_all_domains
    from rich.console import Console

    plain_domains, wildcard_roots = load_domains(args.file)
    no_brute = args.no_brute

    wildcard_expanded = []
    if wildcard_roots:
        Console().print(
            f"\n  [bold cyan]━━ WILDCARD EXPANSION ━━[/bold cyan]\n"
            f"  [dim]{len(wildcard_roots)} wildcard pattern(s) — auto-discovering subdomains[/dim]\n"
        )
        sub_map = await enumerate_all_domains(wildcard_roots, brute=not no_brute, ui=ui)
        for subs in sub_map.values():
            wildcard_expanded.extend(subs)

    subs_expanded = []
    if args.subs and plain_domains:
        Console().print("\n  [bold cyan]━━ SUBDOMAIN DISCOVERY (--subs) ━━[/bold cyan]")
        sub_map2 = await enumerate_all_domains(plain_domains, brute=not no_brute, ui=ui)
        for subs in sub_map2.values():
            subs_expanded.extend(subs)

    if subs_expanded:
        all_domains = list(dict.fromkeys(subs_expanded + wildcard_expanded))
    else:
        all_domains = list(dict.fromkeys(plain_domains + wildcard_expanded))

    if not all_domains:
        Console().print("  [red]No scannable domains after expansion.[/red]")
        return

    if wildcard_roots:
        Console().print(
            f"  [dim]Plain: {len(plain_domains)} | Wildcard-expanded: {len(wildcard_expanded)} | "
            f"Total: {len(all_domains)}[/dim]\n"
        )

    ui.print_banner(len(all_domains))

    scraper = SecretScraper(
        concurrency=args.concurrency,
        per_domain_concurrency=args.per_domain_concurrency,
        timeout=args.timeout,
        scan_sourcemaps=not args.no_sourcemaps,
        max_js_per_domain=args.max_js,
    )

    start = datetime.now()
    results = await scraper.scan_all(all_domains, ui)
    elapsed = (datetime.now() - start).total_seconds()

    ui.print_summary(results, elapsed, show_raw=args.raw)

    paths = generate_reports(results, output_dir, timestamp, show_raw=args.raw)
    ui.print_report_paths(paths)


async def main():
    args = parse_args()
    if not args.file and not args.js_list:
        print("[ERROR] Provide -f domains.txt or --js-list urls.txt")
        sys.exit(1)

    ui = ScannerUI()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    t = ts()

    if args.js_list:
        await run_js_list_scan(args, ui, output_dir, t)
    else:
        await run_domain_scan(args, ui, output_dir, t)


if __name__ == "__main__":
    asyncio.run(main())
